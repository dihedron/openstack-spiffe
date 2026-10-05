package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalAggregator = `
tls_cert_path: /tls.crt
tls_key_path: /tls.key
replicas:
  - https://signer-a.internal:8443/jwks/local.json
  - https://signer-b.internal:8443/jwks/local.json
`

// parseAggregator checks the document without file checks and fails on any
// error finding.
func parseAggregator(r io.Reader) (*Aggregator, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	result := CheckAggregator("", data, CheckOptions{SkipFiles: true})
	if err := result.Err(); err != nil {
		return nil, err
	}
	return result.Config, nil
}

func TestAggregatorDefaults(t *testing.T) {
	cfg, err := parseAggregator(strings.NewReader(minimalAggregator))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"listen_addr", cfg.ListenAddr, "0.0.0.0:8444"},
		{"poll_interval", cfg.PollInterval, 30 * time.Second},
		{"fetch_timeout", cfg.FetchTimeout, 5 * time.Second},
		{"stale_key_retention", cfg.StaleKeyRetention, 5 * time.Minute},
		{"cache_max_age", cfg.CacheMaxAge, 30 * time.Second},
		{"rate_limit_per_source", cfg.RateLimitPerSource, Rate{Events: 50, Per: time.Second}},
		{"client_address.trusted_proxies", len(cfg.ClientAddress.TrustedProxies), 0},
		{"replicas", len(cfg.Replicas), 2},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestAggregatorInvalid(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"unknown key", minimalAggregator + "bogus: 1\n", "bogus"},
		{"bad rate", minimalAggregator + "rate_limit_per_source: \"fast\"\n", "rate_limit_per_source"},
		{"trusted proxy host name", minimalAggregator + "client_address:\n  trusted_proxies: [proxy.internal]\n", "client_address.trusted_proxies[0]"},
		{"invalid client address header", minimalAggregator + "client_address:\n  trusted_proxies: [10.0.0.1]\n  header: \"X Forwarded\"\n", "client_address.header"},
		{"no replicas", "tls_cert_path: /c\ntls_key_path: /k\n", "replicas"},
		{"missing tls", "replicas: [https://a/jwks]\n", "tls_cert_path"},
		{"http replica", "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [http://a/jwks]\n", "replicas"},
		{"replica without host", "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [\"https:///jwks\"]\n", "replicas"},
		{"unparsable replica", "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [\"https://a b/\"]\n", "replicas"},
		{"duplicate replica", "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [https://a/jwks, https://a/jwks]\n", "replicas"},
		{"poll interval zero", minimalAggregator + "poll_interval: 0s\n", "poll_interval"},
		{"fetch timeout >= poll", minimalAggregator + "poll_interval: 10s\nfetch_timeout: 10s\n", "fetch_timeout"},
		{"retention shorter than token ttl", minimalAggregator + "stale_key_retention: 4m\n", "stale_key_retention"},
		{"negative cache age", minimalAggregator + "cache_max_age: -1s\n", "cache_max_age"},
		{"fractional cache age", minimalAggregator + "cache_max_age: 1500ms\n", "cache_max_age"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAggregator(strings.NewReader(tt.doc))
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want ErrInvalidConfig mentioning %q", err, tt.want)
			}
		})
	}
}

func TestLoadAggregator(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir, "aggregator", time.Now().Add(365*24*time.Hour), 0o600)
	doc := strings.NewReplacer("/tls.crt", cert, "/tls.key", key).Replace(minimalAggregator)
	path := filepath.Join(dir, "aggregator.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAggregator(path); err != nil {
		t.Fatalf("LoadAggregator: %v", err)
	}

	// pre-flight: the referenced files must be sane
	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte(minimalAggregator), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAggregator(broken); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "tls_cert_path") {
		t.Fatalf("missing TLS files: err = %v, want ErrInvalidConfig mentioning tls_cert_path", err)
	}
}

func TestAggregatorClientAddress(t *testing.T) {
	cfg, err := parseAggregator(strings.NewReader(minimalAggregator + "client_address:\n  trusted_proxies: [10.0.10.0/24]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ClientAddress.Header != "X-Forwarded-For" {
		t.Errorf("client_address.header = %q, want the default X-Forwarded-For with trusted proxies", cfg.ClientAddress.Header)
	}

	warned := func(doc, path string) bool {
		for _, f := range CheckAggregator("aggregator.yaml", []byte(doc), checkOptions()).Warnings() {
			if f.Path == path {
				return true
			}
		}
		return false
	}
	if !warned(minimalAggregator+"client_address:\n  header: X-Real-IP\n", "client_address.header") {
		t.Error("no warning for a header without trusted proxies")
	}
	if !warned(minimalAggregator+"client_address:\n  trusted_proxies: [\"::/0\"]\n", "client_address.trusted_proxies[0]") {
		t.Error("no warning for a trusted proxy range covering every address")
	}
}
