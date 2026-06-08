package natcf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestSyncUpdatesRuleAndDNSThenCaches(t *testing.T) {
	var rules atomic.Int32
	var dns atomic.Int32

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/rulesets/rs/rules/rule":
			if r.Method != http.MethodPatch {
				t.Fatalf("rule method = %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer token" {
				t.Fatalf("bad auth header")
			}
			var body ruleUpdate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Expression != `(http.host wildcard "*.example.com")` {
				t.Fatalf("expression = %s", body.Expression)
			}
			if body.ActionParameters.Origin.Port != 26656 {
				t.Fatalf("port = %d", body.ActionParameters.Origin.Port)
			}
			rules.Add(1)
		case "/zones/zone/dns_records/record":
			if r.Method != http.MethodPut {
				t.Fatalf("dns method = %s", r.Method)
			}
			var body dnsUpdate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Type != "A" || body.Content != "203.0.113.3" || !body.Proxied || body.TTL != 1 {
				t.Fatalf("bad dns body: %+v", body)
			}
			dns.Add(1)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer s.Close()

	c := New(Config{
		Zone:      "zone",
		Record:    "record",
		RulesetID: "rs",
		RuleID:    "rule",
		APIKey:    "token",
		Domain:    "*.example.com",
		APIBase:   s.URL,
	})
	addr := netip.MustParseAddrPort("203.0.113.3:26656")
	if err := c.Sync(context.Background(), addr); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(context.Background(), addr); err != nil {
		t.Fatal(err)
	}
	if rules.Load() != 1 || dns.Load() != 1 {
		t.Fatalf("rules=%d dns=%d", rules.Load(), dns.Load())
	}
}

func TestSyncUpdatesAAAA(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones/zone/dns_records/record" {
			var body dnsUpdate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Type != "AAAA" || body.Content != "2001:db8::1" {
				t.Fatalf("bad dns body: %+v", body)
			}
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer s.Close()

	c := New(Config{
		Zone:      "zone",
		Record:    "record",
		RulesetID: "rs",
		RuleID:    "rule",
		APIKey:    "token",
		Domain:    "example.com",
		APIBase:   s.URL,
	})
	if err := c.Sync(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:443")); err != nil {
		t.Fatal(err)
	}
}
