package natcf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/csbxd/natnet"
)

const defaultAPIBase = "https://api.cloudflare.com/client/v4"
const maxResponseBodySize = 64 * 1024

var (
	errResponseBodyTooLarge = errors.New("response body too large")
)

type Config struct {
	Zone      string
	Record    string
	RulesetID string
	RuleID    string
	APIKey    string
	Domain    string

	Retry       int
	Timeout     time.Duration
	Description string
	APIBase     string
	HTTPClient  *http.Client
}

type Client struct {
	cfg  Config
	hc   *http.Client
	last natnet.Addr
}

func New(cfg Config) *Client {
	if cfg.Retry == 0 {
		cfg.Retry = 3
	}
	if cfg.Description == "" {
		cfg.Description = "nat"
	}
	if cfg.APIBase == "" {
		cfg.APIBase = defaultAPIBase
	}
	cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{
		cfg: cfg,
		hc:  hc,
	}
}

func (c *Client) Sync(ctx context.Context, addr natnet.Addr) error {
	if c.last == addr {
		return nil
	}

	if err := c.Update(ctx, addr); err != nil {
		return err
	}

	c.last = addr
	return nil
}

func (c *Client) Update(ctx context.Context, addr natnet.Addr) error {
	if err := c.updateRule(ctx, addr.Port()); err != nil {
		return err
	}
	return c.updateDNS(ctx, addr)
}

func (c *Client) updateRule(ctx context.Context, port uint16) error {
	body := ruleUpdate{
		Expression:  `(http.host wildcard "` + c.cfg.Domain + `")`,
		Description: c.cfg.Description,
		Action:      "route",
		ActionParameters: ruleActionParameters{
			Origin: ruleOrigin{
				Port: int(port),
			},
		},
	}
	path := "/zones/" + pathEscape(c.cfg.Zone) + "/rulesets/" + pathEscape(c.cfg.RulesetID) + "/rules/" + pathEscape(c.cfg.RuleID)
	return c.doJSON(ctx, http.MethodPatch, path, body)
}

func (c *Client) updateDNS(ctx context.Context, addr natnet.Addr) error {
	ip := addr.Addr()
	typ := "AAAA"
	if ip.Is4() {
		typ = "A"
	}
	body := dnsUpdate{
		Type:    typ,
		Name:    c.cfg.Domain,
		Content: ip.String(),
		TTL:     1,
		Proxied: true,
	}
	path := "/zones/" + pathEscape(c.cfg.Zone) + "/dns_records/" + pathEscape(c.cfg.Record)
	return c.doJSON(ctx, http.MethodPut, path, body)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any) error {
	var err error
	for i := 0; i <= c.cfg.Retry; i++ {
		err = c.doJSONOnce(ctx, method, path, body)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

func (c *Client) doJSONOnce(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIBase+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := readResponseBody(resp.Body, resp.ContentLength, maxResponseBodySize)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare %s %s: %s: %s", method, path, resp.Status, trimBody(respBody))
	}

	var r response
	if len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if !r.Success {
		return r.err()
	}
	return nil
}

func pathEscape(s string) string {
	return url.PathEscape(s)
}

func trimBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

func readResponseBody(r io.Reader, contentLength int64, maxBodySize int) ([]byte, error) {
	var dst []byte
	if maxBodySize > 0 && contentLength > int64(maxBodySize) {
		return dst, errResponseBodyTooLarge
	}
	if contentLength == 0 {
		return dst, nil
	}
	if contentLength > 0 {
		dst = make([]byte, int(contentLength))
		_, err := io.ReadFull(r, dst)
		return dst, err
	}
	dst = make([]byte, 0, 1024)
	for {
		if maxBodySize > 0 && len(dst) == maxBodySize {
			var b [1]byte
			n, err := r.Read(b[:])
			if n > 0 {
				return dst, errResponseBodyTooLarge
			}
			if errors.Is(err, io.EOF) {
				return dst, nil
			}
			if err != nil {
				return dst, err
			}
			return dst, errors.New("response body read returned (0, nil)")
		}
		if len(dst) == cap(dst) {
			n := 2 * cap(dst)
			if n == 0 {
				n = 1024
			}
			if maxBodySize > 0 && n > maxBodySize {
				n = maxBodySize
			}
			b := make([]byte, len(dst), n)
			copy(b, dst)
			dst = b
		}
		n, err := r.Read(dst[len(dst):cap(dst)])
		dst = dst[:len(dst)+n]
		if errors.Is(err, io.EOF) {
			return dst, nil
		}
		if err != nil {
			return dst, err
		}
		if n == 0 {
			return dst, errors.New("response body read returned (0, nil)")
		}
	}
}

type dnsUpdate struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type ruleUpdate struct {
	Expression       string               `json:"expression"`
	Description      string               `json:"description"`
	Action           string               `json:"action"`
	ActionParameters ruleActionParameters `json:"action_parameters"`
}

type ruleActionParameters struct {
	Origin ruleOrigin `json:"origin"`
}

type ruleOrigin struct {
	Port int `json:"port"`
}

type response struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (r response) err() error {
	if len(r.Errors) == 0 {
		return errors.New("cloudflare request failed")
	}
	var b strings.Builder
	for i := range r.Errors {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(r.Errors[i].Message)
	}
	return errors.New(b.String())
}
