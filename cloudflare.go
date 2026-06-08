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
	"sync"
	"time"

	"github.com/csbxd/natnet"
)

const defaultAPIBase = "https://api.cloudflare.com/client/v4"

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
	cfg Config
	hc  *http.Client

	mu     sync.Mutex
	synced bool
	last   natnet.Addr
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
	c.mu.Lock()
	if c.synced && c.last == addr {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if err := c.Update(ctx, addr); err != nil {
		return err
	}

	c.mu.Lock()
	c.synced = true
	c.last = addr
	c.mu.Unlock()
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
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(body); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIBase+path, &b)
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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
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
