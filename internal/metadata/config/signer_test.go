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

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const minimalSigner = `
tls_cert_path: /etc/openstack-metadata-signer/tls.crt
tls_key_path: /etc/openstack-metadata-signer/tls.key
replica_id: signer-a
keystone:
  allowed_users: ["3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60"]
`

// secureSettings enables the syslog audit sink and restricts /attest, so
// that fixtures meant to be free of warnings get none about them.
const secureSettings = "audit:\n  syslog:\n    enabled: true\nattest:\n  allowed_sources: [10.0.20.0/24]\n"

// vendordataUserID is the ID of Nova's vendordata user in the fixtures.
const vendordataUserID = "3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60"

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
		{"key_store.lock_memory", cfg.KeyStore.LockMemory, true},
		{"token_ttl_seconds", cfg.TokenTTLSeconds, 300},
		{"rate_limit_per_instance", cfg.RateLimitPerInstance, Rate{Events: 1, Per: 5 * time.Second}},
		{"rate_limit_per_source", cfg.RateLimitPerSource, Rate{Events: 200, Per: time.Second}},
		{"rate_limit_per_source_public", cfg.RateLimitPerSourcePublic, Rate{Events: 50, Per: time.Second}},
		{"keystone.max_concurrent_validations", cfg.Keystone.MaxConcurrentValidations, 32},
		{"max_body_bytes", cfg.MaxBodyBytes, int64(256 * 1024)},
		{"keystone.required_role", cfg.Keystone.RequiredRole, "service"},
		{"keystone.validation_cache_ttl", cfg.Keystone.ValidationCacheTTL, time.Minute},
		{"keystone.project_cache_ttl", cfg.Keystone.ProjectCacheTTL, 10 * time.Minute},
		{"nova_lookup.enabled", cfg.NovaLookup.Enabled, true},
		{"nova_lookup.cache_ttl", cfg.NovaLookup.CacheTTL, time.Minute},
		{"audit.syslog.enabled", cfg.Audit.Syslog.Enabled, false},
		{"audit.syslog.socket", cfg.Audit.Syslog.Socket, "/dev/log"},
		{"audit.syslog.facility", cfg.Audit.Syslog.Facility, "authpriv"},
		{"audit.syslog.app_name", cfg.Audit.Syslog.AppName, "openstack-spire-issuer"},
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
		{"missing tls cert", [2]string{"tls_cert_path: /etc/openstack-metadata-signer/tls.crt\n", ""}, "", "tls_cert_path"},
		{"missing tls key", [2]string{"tls_key_path: /etc/openstack-metadata-signer/tls.key\n", ""}, "", "tls_key_path"},
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
		{"custom claims too large", [2]string{}, "custom_claims:\n  c: " + strings.Repeat("x", iid.MaxCustomClaimsBytes) + "\n", "custom_claims"},
		{"empty allowlist entry", [2]string{}, "tags:\n  allowlist: [\"\"]\n", "tags.allowlist"},
		{"duplicate allowlist entry", [2]string{}, "tags:\n  allowlist: [a, a]\n", "tags.allowlist"},
		{"no allowed users", [2]string{"  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n", ""}, "", "keystone.allowed_users"},
		{"empty allowed user", [2]string{"allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]", "allowed_users: [\"\"]"}, "", "keystone.allowed_users"},
		{"bare allowed user name", [2]string{"allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]", "allowed_users: [\"nova\"]"}, "", "keystone.allowed_users[0]"},
		{"allowed user without domain", [2]string{"allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]", "allowed_users: [\"nova@\"]"}, "", "keystone.allowed_users[0]"},
		{"trusted proxy host name", [2]string{}, "client_address:\n  trusted_proxies: [proxy.internal]\n", "client_address.trusted_proxies[0]"},
		{"trusted proxy bad range", [2]string{}, "client_address:\n  trusted_proxies: [10.0.0.0/33]\n", "client_address.trusted_proxies[0]"},
		{"duplicate trusted proxy", [2]string{}, "client_address:\n  trusted_proxies: [10.0.0.1, 10.0.0.1]\n", "client_address.trusted_proxies"},
		{"invalid client address header", [2]string{}, "client_address:\n  trusted_proxies: [10.0.0.1]\n  header: \"X Forwarded\"\n", "client_address.header"},
		{"empty required role", [2]string{"  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n", "  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n  required_role: \"\"\n"}, "", "keystone.required_role"},
		{"validation cache too long", [2]string{"  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n", "  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n  validation_cache_ttl: 11m\n"}, "", "keystone.validation_cache_ttl"},
		{"nova cache longer than ttl", [2]string{}, "nova_lookup:\n  cache_ttl: 6m\n", "nova_lookup.cache_ttl"},
		{"nova cache longer than custom ttl", [2]string{}, "token_ttl_seconds: 60\nnova_lookup:\n  cache_ttl: 61s\n", "nova_lookup.cache_ttl"},
		{"empty statuses", [2]string{}, "nova_lookup:\n  allowed_statuses: []\n", "nova_lookup.allowed_statuses"},
		{"deleted status allowed", [2]string{}, "nova_lookup:\n  allowed_statuses: [ACTIVE, DELETED]\n", "nova_lookup.allowed_statuses"},
		{"unknown enrichment", [2]string{}, "enrich: [hypervisor_hostname]\n", "enrich"},
		{"duplicate enrichment", [2]string{}, "enrich: [flavor, flavor]\n", "enrich"},
		{"server enrichment without lookup", [2]string{}, "nova_lookup:\n  enabled: false\nenrich: [availability_zone]\n", "enrich"},
		{"unknown audit syslog key", [2]string{}, "audit:\n  syslog:\n    severity: info\n", "severity"},
		{"unknown syslog facility", [2]string{}, "audit:\n  syslog:\n    facility: kern\n", "audit.syslog.facility"},
		{"empty syslog facility", [2]string{}, "audit:\n  syslog:\n    facility: \"\"\n", "audit.syslog.facility"},
		{"syslog app name too long", [2]string{}, "audit:\n  syslog:\n    app_name: " + strings.Repeat("a", 49) + "\n", "audit.syslog.app_name"},
		{"syslog app name with a space", [2]string{}, "audit:\n  syslog:\n    app_name: \"my issuer\"\n", "audit.syslog.app_name"},
		{"syslog app name not ASCII", [2]string{}, "audit:\n  syslog:\n    app_name: \"issuér\"\n", "audit.syslog.app_name"},
		{"empty syslog app name", [2]string{}, "audit:\n  syslog:\n    app_name: \"\"\n", "audit.syslog.app_name"},
		{"empty syslog socket", [2]string{}, "audit:\n  syslog:\n    enabled: true\n    socket: \"\"\n", "audit.syslog.socket"},
		{"attest source host name", [2]string{}, "attest:\n  allowed_sources: [metadata.internal]\n", "attest.allowed_sources[0]"},
		{"attest source bad range", [2]string{}, "attest:\n  allowed_sources: [10.0.0.0/33]\n", "attest.allowed_sources[0]"},
		{"duplicate attest source", [2]string{}, "attest:\n  allowed_sources: [10.0.0.1, 10.0.0.1]\n", "attest.allowed_sources"},
		{"empty attest source", [2]string{}, "attest:\n  allowed_sources: [\"\"]\n", "attest.allowed_sources"},
		{"unknown attest key", [2]string{}, "attest:\n  allowed_source: [10.0.0.1]\n", "allowed_source"},
		{"bad public rate", [2]string{}, "rate_limit_per_source_public: \"fast\"\n", "rate_limit_per_source_public"},
		{"no concurrent validations", [2]string{"  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n", "  allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]\n  max_concurrent_validations: 0\n"}, "", "keystone.max_concurrent_validations"},
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
	doc := strings.Replace(minimalSigner, "allowed_users: [\"3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60\"]",
		"allowed_users: [\"0123456789abcdef0123456789abcdef\", \"svc@example.com@ldap\"]", 1)
	if _, err := parseSignerString(t, doc); err != nil {
		t.Fatalf("user ID and qualified name rejected: %v", err)
	}
}

func TestSignerClientAddress(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ClientAddress.TrustedProxies) != 0 || cfg.ClientAddress.Header != "" {
		t.Fatalf("not proxied by default, got %+v", cfg.ClientAddress)
	}

	cfg, err = parseSignerString(t, minimalSigner+"client_address:\n  trusted_proxies: [10.0.10.0/24, \"2001:db8::1\"]\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ClientAddress.Header != "X-Forwarded-For" {
		t.Fatalf("header %q, want the X-Forwarded-For default with trusted proxies", cfg.ClientAddress.Header)
	}

	cfg, err = parseSignerString(t, minimalSigner+"client_address:\n  trusted_proxies: [10.0.10.0/24]\n  header: X-Real-IP\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ClientAddress.Header != "X-Real-IP" {
		t.Fatalf("header %q, want X-Real-IP", cfg.ClientAddress.Header)
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

// writeSigner writes a signer configuration file referencing a fresh,
// valid TLS key pair, plus extra, and returns its path.
func writeSigner(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir, "signer", time.Now().Add(365*24*time.Hour), 0o600)
	doc := strings.NewReplacer(
		"/etc/openstack-metadata-signer/tls.crt", cert,
		"/etc/openstack-metadata-signer/tls.key", key,
	).Replace(minimalSigner) + extra
	path := filepath.Join(dir, "signer.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSigner(t *testing.T) {
	path := writeSigner(t, "")
	cfg, warnings, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if cfg.ReplicaID != "signer-a" {
		t.Fatalf("replica_id = %q", cfg.ReplicaID)
	}
	var paths []string
	for _, w := range warnings {
		if w.File != path {
			t.Fatalf("warning %+v names file %q, want %q", w, w.File, path)
		}
		paths = append(paths, w.Path)
	}
	if want := []string{"attest", "tags.allowlist", "audit.syslog.enabled"}; !slices.Equal(paths, want) {
		t.Fatalf("warnings = %+v, want %v", warnings, want)
	}
	if _, _, err := LoadSigner(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatalf("LoadSigner on a missing file succeeded")
	}
	if _, _, err := LoadSigner(writeSigner(t, "token_ttl_seconds: 0\n")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadSigner on an invalid file: err = %v, want ErrInvalidConfig", err)
	}
}

// TestLoadSignerPreflight checks that the service refuses a configuration
// whose referenced files are not sane, and reports risky ones as warnings.
func TestLoadSignerPreflight(t *testing.T) {
	dir := t.TempDir()
	valid := func() (string, string) {
		return writeKeyPair(t, t.TempDir(), "signer", time.Now().Add(365*24*time.Hour), 0o600)
	}
	write := func(cert, key, extra string) string {
		doc := strings.NewReplacer("/etc/openstack-metadata-signer/tls.crt", cert, "/etc/openstack-metadata-signer/tls.key", key).Replace(minimalSigner) + extra
		path := filepath.Join(t.TempDir(), "signer.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	expiredCert, expiredKey := writeKeyPair(t, dir, "expired", time.Now().Add(-time.Hour), 0o600)
	cert, _ := valid()
	_, otherKey := valid()
	notPEM := filepath.Join(dir, "ca.pem")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	goodCert, goodKey := valid()

	for _, tt := range []struct {
		name, cert, key, extra, want string
	}{
		{"missing certificate", filepath.Join(dir, "missing.crt"), goodKey, "", "tls_cert_path"},
		{"missing key", goodCert, filepath.Join(dir, "missing.key"), "", "tls_key_path"},
		{"expired certificate", expiredCert, expiredKey, "", "tls_cert_path"},
		{"mismatched key", cert, otherKey, "", "tls_key_path"},
		{"unparseable CA bundle", goodCert, goodKey, "  ca_cert_path: " + notPEM + "\n", "keystone.ca_cert_path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := LoadSigner(write(tt.cert, tt.key, tt.extra))
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want ErrInvalidConfig mentioning %q", err, tt.want)
			}
		})
	}

	// risky but usable: warnings, not errors
	soonCert, soonKey := writeKeyPair(t, dir, "soon", time.Now().Add(10*24*time.Hour), 0o644)
	_, warnings, err := LoadSigner(write(soonCert, soonKey, ""))
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	paths := map[string]bool{}
	for _, w := range warnings {
		paths[w.Path] = true
	}
	if !paths["tls_cert_path"] || !paths["tls_key_path"] {
		t.Fatalf("warnings %+v, want the expiring certificate and the readable key", warnings)
	}
}

func TestSignerEmptyDocument(t *testing.T) {
	if _, err := parseSignerString(t, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty document: err = %v, want ErrInvalidConfig", err)
	}
}

func TestSignerAuditSyslog(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner+`audit:
  syslog:
    enabled: true
    socket: /run/systemd/journal/dev-log
    facility: local3
    app_name: issuer-a
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := AuditSyslog{Enabled: true, Socket: "/run/systemd/journal/dev-log", Facility: "local3", AppName: "issuer-a"}
	if cfg.Audit.Syslog != want {
		t.Fatalf("audit.syslog = %+v, want %+v", cfg.Audit.Syslog, want)
	}
	for _, facility := range []string{"auth", "authpriv", "daemon", "local0", "local7"} {
		if _, err := parseSignerString(t, minimalSigner+"audit:\n  syslog:\n    facility: "+facility+"\n"); err != nil {
			t.Errorf("facility %s: %v", facility, err)
		}
	}
}

func TestSignerAttest(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner+`attest:
  allowed_sources: ["10.0.20.0/24", "192.0.2.10", "2001:db8::/64"]
  client_ca_path: /etc/openstack-spire-issuer/nova-client-ca.pem
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []string{"10.0.20.0/24", "192.0.2.10", "2001:db8::/64"}; !slices.Equal(cfg.Attest.AllowedSources, want) {
		t.Errorf("attest.allowed_sources = %v, want %v", cfg.Attest.AllowedSources, want)
	}
	if cfg.Attest.ClientCAPath != "/etc/openstack-spire-issuer/nova-client-ca.pem" {
		t.Errorf("attest.client_ca_path = %q", cfg.Attest.ClientCAPath)
	}
	defaults, err := parseSignerString(t, minimalSigner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(defaults.Attest.AllowedSources) != 0 || defaults.Attest.ClientCAPath != "" {
		t.Errorf("attest defaults = %+v, want no restriction", defaults.Attest)
	}
}
