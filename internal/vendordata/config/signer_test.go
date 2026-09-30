package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const minimalSigner = `
tls_cert_path: /etc/vendordata-signer/tls.crt
tls_key_path: /etc/vendordata-signer/tls.key
replica_id: signer-a
keystone:
  allowed_users: ["nova@Default"]
`

// parseSigner checks doc without file checks and fails on any error finding.
func parseSigner(r io.Reader, hostname func() (string, error)) (*Signer, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	result := CheckSigner("", data, CheckOptions{Hostname: hostname, SkipFiles: true})
	if err := result.Err(); err != nil {
		return nil, err
	}
	return result.Config, nil
}

func parseSignerString(t *testing.T, doc string) (*Signer, error) {
	t.Helper()
	return parseSigner(strings.NewReader(doc), func() (string, error) { return "Signer-Host.example.org", nil })
}

func TestSignerDefaults(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"listen_addr", cfg.ListenAddr, "0.0.0.0:8443"},
		{"key_store.backend", cfg.KeyStore.Backend, BackendEphemeralMemory},
		{"key_store.algorithm", cfg.KeyStore.Algorithm, "RS256"},
		{"key_store.rotation_interval", cfg.KeyStore.RotationInterval, 24 * time.Hour},
		{"key_store.publish_ahead", cfg.KeyStore.PublishAhead, 2 * time.Minute},
		{"token_ttl_seconds", cfg.TokenTTLSeconds, 300},
		{"rate_limit_per_instance", cfg.RateLimitPerInstance, Rate{Events: 1, Per: 5 * time.Second}},
		{"rate_limit_per_source", cfg.RateLimitPerSource, Rate{Events: 200, Per: time.Second}},
		{"max_body_bytes", cfg.MaxBodyBytes, int64(256 * 1024)},
		{"keystone.required_role", cfg.Keystone.RequiredRole, "service"},
		{"keystone.validation_cache_ttl", cfg.Keystone.ValidationCacheTTL, time.Minute},
		{"keystone.project_cache_ttl", cfg.Keystone.ProjectCacheTTL, 10 * time.Minute},
		{"nova_lookup.enabled", cfg.NovaLookup.Enabled, true},
		{"nova_lookup.cache_ttl", cfg.NovaLookup.CacheTTL, time.Minute},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	wantStatuses := []string{"ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "PASSWORD"}
	if !slices.Equal(cfg.NovaLookup.AllowedStatuses, wantStatuses) {
		t.Errorf("nova_lookup.allowed_statuses = %v, want %v", cfg.NovaLookup.AllowedStatuses, wantStatuses)
	}
	if cfg.TokenTTL() != 5*time.Minute {
		t.Errorf("TokenTTL() = %v", cfg.TokenTTL())
	}
}

func TestSignerFullFile(t *testing.T) {
	doc := `
listen_addr: "127.0.0.1:9443"
tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: az1-signer-0
key_store:
  backend: ephemeral_memory
  algorithm: ES256
  rotation_interval: 12h
  publish_ahead: 90s
token_ttl_seconds: 120
rate_limit_per_instance: "2/10s"
rate_limit_per_source: "50/1s"
max_body_bytes: 131072
custom_claims:
  country: italy
tags:
  allowlist: [role, env]
keystone:
  allowed_users: [nova@Default, nova-metadata@Default]
  required_role: admin
  validation_cache_ttl: 30s
  project_cache_ttl: 5m
  ca_cert_path: /etc/ssl/keystone-ca.pem
nova_lookup:
  enabled: true
  cache_ttl: 30s
  allowed_statuses: [ACTIVE]
enrich: [availability_zone, flavor, user_id, project_name, domain_id]
`
	cfg, err := parseSignerString(t, doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9443" || cfg.ReplicaID != "az1-signer-0" || cfg.KeyStore.Algorithm != "ES256" ||
		cfg.KeyStore.RotationInterval != 12*time.Hour || cfg.KeyStore.PublishAhead != 90*time.Second ||
		cfg.TokenTTLSeconds != 120 || cfg.RateLimitPerInstance != (Rate{2, 10 * time.Second}) ||
		cfg.RateLimitPerSource != (Rate{50, time.Second}) || cfg.MaxBodyBytes != 131072 ||
		cfg.CustomClaims["country"] != "italy" || !slices.Equal(cfg.Tags.Allowlist, []string{"role", "env"}) ||
		!slices.Equal(cfg.Keystone.AllowedUsers, []string{"nova@Default", "nova-metadata@Default"}) || cfg.Keystone.RequiredRole != "admin" ||
		cfg.Keystone.ValidationCacheTTL != 30*time.Second || cfg.Keystone.ProjectCacheTTL != 5*time.Minute ||
		cfg.Keystone.CACertPath != "/etc/ssl/keystone-ca.pem" || cfg.NovaLookup.CacheTTL != 30*time.Second ||
		!slices.Equal(cfg.NovaLookup.AllowedStatuses, []string{"ACTIVE"}) || len(cfg.Enrich) != 5 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestSignerReplicaIDFromHostname(t *testing.T) {
	doc := strings.Replace(minimalSigner, "replica_id: signer-a\n", "", 1)
	cfg, err := parseSignerString(t, doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ReplicaID != "signer-host" {
		t.Fatalf("replica_id = %q, want %q (first label of the lowercased hostname)", cfg.ReplicaID, "signer-host")
	}

	_, err = parseSigner(strings.NewReader(doc), func() (string, error) { return "under_score", nil })
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "replica_id") {
		t.Fatalf("hostname not usable as replica_id: err = %v", err)
	}
	_, err = parseSigner(strings.NewReader(doc), func() (string, error) { return "", errors.New("boom") })
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "replica_id") {
		t.Fatalf("hostname lookup failure: err = %v", err)
	}
}

func TestSignerInvalid(t *testing.T) {
	tests := []struct {
		name    string
		replace [2]string // applied to minimalSigner
		append  string
		want    string
	}{
		{"unknown key", [2]string{}, "bogus: 1\n", "bogus"},
		{"missing tls cert", [2]string{"tls_cert_path: /etc/vendordata-signer/tls.crt\n", ""}, "", "tls_cert_path"},
		{"missing tls key", [2]string{"tls_key_path: /etc/vendordata-signer/tls.key\n", ""}, "", "tls_key_path"},
		{"bad replica id", [2]string{"replica_id: signer-a", "replica_id: Signer_A"}, "", "replica_id"},
		{"replica id too long", [2]string{"replica_id: signer-a", "replica_id: " + strings.Repeat("a", 64)}, "", "replica_id"},
		{"vault not supported yet", [2]string{}, "key_store:\n  backend: vault_transit\n", "vault_transit"},
		{"unknown backend", [2]string{}, "key_store:\n  backend: barbican\n", "backend"},
		{"unknown algorithm", [2]string{}, "key_store:\n  algorithm: HS256\n", "algorithm"},
		{"publish_ahead zero", [2]string{}, "key_store:\n  publish_ahead: 0s\n", "publish_ahead"},
		{"publish_ahead >= rotation", [2]string{}, "key_store:\n  rotation_interval: 10m\n  publish_ahead: 10m\n", "publish_ahead"},
		{"rotation too short", [2]string{}, "key_store:\n  rotation_interval: 4m\n  publish_ahead: 1m\n", "rotation_interval"},
		{"ttl zero", [2]string{}, "token_ttl_seconds: -1\n", "token_ttl_seconds"},
		{"ttl too long", [2]string{}, "token_ttl_seconds: 301\n", "token_ttl_seconds"},
		{"bad rate", [2]string{}, "rate_limit_per_instance: \"fast\"\n", "rate"},
		{"body too small", [2]string{}, "max_body_bytes: 100\n", "max_body_bytes"},
		{"reserved custom claim", [2]string{}, "custom_claims:\n  project_id: other\n", "custom_claims"},
		{"empty custom claim", [2]string{}, "custom_claims:\n  \"\": x\n", "custom_claims"},
		{"custom claim uses enrichment name", [2]string{}, "custom_claims:\n  availability_zone: nova\n", "custom_claims"},
		{"empty allowlist entry", [2]string{}, "tags:\n  allowlist: [\"\"]\n", "tags.allowlist"},
		{"duplicate allowlist entry", [2]string{}, "tags:\n  allowlist: [a, a]\n", "tags.allowlist"},
		{"no allowed users", [2]string{"  allowed_users: [\"nova@Default\"]\n", ""}, "", "keystone.allowed_users"},
		{"empty allowed user", [2]string{"allowed_users: [\"nova@Default\"]", "allowed_users: [\"\"]"}, "", "keystone.allowed_users"},
		{"bare allowed user name", [2]string{"allowed_users: [\"nova@Default\"]", "allowed_users: [\"nova\"]"}, "", "keystone.allowed_users[0]"},
		{"allowed user without domain", [2]string{"allowed_users: [\"nova@Default\"]", "allowed_users: [\"nova@\"]"}, "", "keystone.allowed_users[0]"},
		{"empty required role", [2]string{"  allowed_users: [\"nova@Default\"]\n", "  allowed_users: [\"nova@Default\"]\n  required_role: \"\"\n"}, "", "keystone.required_role"},
		{"validation cache too long", [2]string{"  allowed_users: [\"nova@Default\"]\n", "  allowed_users: [\"nova@Default\"]\n  validation_cache_ttl: 11m\n"}, "", "keystone.validation_cache_ttl"},
		{"nova cache longer than ttl", [2]string{}, "nova_lookup:\n  cache_ttl: 6m\n", "nova_lookup.cache_ttl"},
		{"nova cache longer than custom ttl", [2]string{}, "token_ttl_seconds: 60\nnova_lookup:\n  cache_ttl: 61s\n", "nova_lookup.cache_ttl"},
		{"empty statuses", [2]string{}, "nova_lookup:\n  allowed_statuses: []\n", "nova_lookup.allowed_statuses"},
		{"deleted status allowed", [2]string{}, "nova_lookup:\n  allowed_statuses: [ACTIVE, DELETED]\n", "nova_lookup.allowed_statuses"},
		{"unknown enrichment", [2]string{}, "enrich: [hypervisor_hostname]\n", "enrich"},
		{"duplicate enrichment", [2]string{}, "enrich: [flavor, flavor]\n", "enrich"},
		{"server enrichment without lookup", [2]string{}, "nova_lookup:\n  enabled: false\nenrich: [availability_zone]\n", "enrich"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := minimalSigner
			if tt.replace[0] != "" {
				if !strings.Contains(doc, tt.replace[0]) {
					t.Fatalf("test setup: %q not found", tt.replace[0])
				}
				doc = strings.Replace(doc, tt.replace[0], tt.replace[1], 1)
			}
			doc += tt.append
			cfg, err := parseSignerString(t, doc)
			if err == nil {
				t.Fatalf("parse succeeded, want error mentioning %q: %+v", tt.want, cfg)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestSignerAllowedUsersByIDOrQualifiedName(t *testing.T) {
	doc := strings.Replace(minimalSigner, "allowed_users: [\"nova@Default\"]",
		"allowed_users: [\"0123456789abcdef0123456789abcdef\", \"svc@example.com@ldap\"]", 1)
	if _, err := parseSignerString(t, doc); err != nil {
		t.Fatalf("user ID and qualified name rejected: %v", err)
	}
}

func TestSignerKeystoneOnlyEnrichmentWithoutLookup(t *testing.T) {
	doc := minimalSigner + "nova_lookup:\n  enabled: false\nenrich: [project_name, domain_id]\n"
	if _, err := parseSignerString(t, doc); err != nil {
		t.Fatalf("keystone-only enrichment without nova lookup rejected: %v", err)
	}
}

func TestSignerReportsAllProblems(t *testing.T) {
	doc := "replica_id: ok\ntoken_ttl_seconds: 999\n"
	_, err := parseSignerString(t, doc)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	for _, want := range []string{"tls_cert_path", "tls_key_path", "token_ttl_seconds", "keystone.allowed_users"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestLoadSigner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.yaml")
	if err := os.WriteFile(path, []byte(minimalSigner), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if cfg.ReplicaID != "signer-a" {
		t.Fatalf("replica_id = %q", cfg.ReplicaID)
	}
	if len(warnings) != 1 || warnings[0].Path != "tags.allowlist" || warnings[0].File != path {
		t.Fatalf("warnings = %+v, want the tags.allowlist warning", warnings)
	}
	if _, _, err := LoadSigner(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatalf("LoadSigner on a missing file succeeded")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte(minimalSigner+"token_ttl_seconds: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSigner(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadSigner on an invalid file: err = %v, want ErrInvalidConfig", err)
	}
}

func TestSignerEmptyDocument(t *testing.T) {
	if _, err := parseSignerString(t, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty document: err = %v, want ErrInvalidConfig", err)
	}
}
