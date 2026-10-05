package config

import (
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func checkOptions() CheckOptions {
	return CheckOptions{
		Hostname:  func() (string, error) { return "ci-runner", nil },
		SkipFiles: true,
	}
}

// findingKey is a compact, comparable view of a finding.
type findingKey struct {
	Line     int
	Path     string
	Severity Severity
	Kind     Kind
}

func keysOf(findings []Finding) []findingKey {
	keys := make([]findingKey, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, findingKey{f.Line, f.Path, f.Severity, f.Kind})
	}
	return keys
}

func findByPath(t *testing.T, findings []Finding, path string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no finding for %q in %+v", path, findings)
	return Finding{}
}

func TestCheckSignerReportsEverythingInOneRun(t *testing.T) {
	doc := `listen_addr: "127.0.0.1:9443"
tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: signer-a
rate_limt_per_instance: "1/5s"
rate_limit_per_source: "fast"
token_ttl_seconds: 999
max_body_bytes: lots
key_store:
  publish_ahed: 1m
  rotation_interval: 5q
keystone:
  alowed_users: [nova]
  validation_cache_ttl: 11m
tags:
  allowlist: [role, role]
enrich: [flavor, hypervisor_hostname]
`
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if result.Config == nil {
		t.Fatalf("config not decoded")
	}
	if result.Config.ListenAddr != "127.0.0.1:9443" {
		t.Fatalf("valid values must still be decoded; listen_addr = %q", result.Config.ListenAddr)
	}

	errs := keysOf(result.Errors())
	want := []findingKey{
		{5, "rate_limt_per_instance", SeverityError, KindUnknownKey},
		{6, "rate_limit_per_source", SeverityError, KindInvalidValue},
		{7, "token_ttl_seconds", SeverityError, KindRuleViolation},
		{8, "max_body_bytes", SeverityError, KindInvalidValue},
		{10, "key_store.publish_ahed", SeverityError, KindUnknownKey},
		{11, "key_store.rotation_interval", SeverityError, KindInvalidValue},
		{13, "keystone.alowed_users", SeverityError, KindUnknownKey},
		{14, "keystone.validation_cache_ttl", SeverityError, KindRuleViolation},
		{16, "tags.allowlist[1]", SeverityError, KindRuleViolation},
		{17, "enrich[1]", SeverityError, KindRuleViolation},
		{0, "keystone.allowed_users", SeverityError, KindRuleViolation},
	}
	for _, w := range want {
		if !slices.Contains(errs, w) {
			t.Errorf("missing finding %+v", w)
		}
	}
	if len(errs) != len(want) {
		t.Errorf("got %d errors, want %d:\n%s", len(errs), len(want), dump(result.Findings))
	}

	if f := findByPath(t, result.Findings, "rate_limt_per_instance"); f.Suggestion != "rate_limit_per_instance" {
		t.Errorf("suggestion = %q, want rate_limit_per_instance", f.Suggestion)
	}
	if f := findByPath(t, result.Findings, "keystone.alowed_users"); f.Suggestion != "allowed_users" {
		t.Errorf("suggestion = %q, want allowed_users", f.Suggestion)
	}
	if f := findByPath(t, result.Findings, "key_store.publish_ahed"); f.Suggestion != "publish_ahead" {
		t.Errorf("suggestion = %q, want publish_ahead", f.Suggestion)
	}
	for _, f := range result.Findings {
		if f.File != "signer.yaml" {
			t.Errorf("finding %+v has file %q", f, f.File)
		}
	}
}

func dump(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	return b.String()
}

func TestCheckSignerValid(t *testing.T) {
	doc := minimalSigner + "tags:\n  allowlist: [role]\n" + secureSettings
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s", dump(result.Findings))
	}
	if result.Config.ReplicaID != "signer-a" {
		t.Fatalf("replica_id = %q", result.Config.ReplicaID)
	}
}

func TestCheckSignerSyntaxError(t *testing.T) {
	result := CheckSigner("signer.yaml", []byte("listen_addr: a\nkeystone: [\n"), checkOptions())
	if result.Config != nil {
		t.Fatalf("config decoded from a malformed document")
	}
	errs := result.Errors()
	if len(errs) != 1 || errs[0].Kind != KindSyntax || errs[0].Line == 0 {
		t.Fatalf("findings = %+v, want one syntax error with a line", errs)
	}
}

func TestCheckSignerTopLevelNotAMapping(t *testing.T) {
	result := CheckSigner("signer.yaml", []byte("- a\n- b\n"), checkOptions())
	if len(result.Errors()) == 0 {
		t.Fatalf("expected errors for a non-mapping document")
	}
}

func TestCheckSignerDefaultValueViolationHasNoLine(t *testing.T) {
	// the default nova_lookup.cache_ttl (60s) exceeds a 30s token TTL
	doc := minimalSigner + "tags:\n  allowlist: [role]\ntoken_ttl_seconds: 30\n"
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	f := findByPath(t, result.Findings, "nova_lookup.cache_ttl")
	if f.Line != 0 || f.Severity != SeverityError {
		t.Fatalf("finding = %+v, want an error without line (default value)", f)
	}
}

func TestCheckSignerCustomClaimPath(t *testing.T) {
	doc := minimalSigner + "custom_claims:\n  country: italy\n  project_id: other\n"
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	f := findByPath(t, result.Findings, "custom_claims.project_id")
	if f.Line != 9 || f.Kind != KindRuleViolation {
		t.Fatalf("finding = %+v, want rule violation on line 9", f)
	}
}

func TestCheckSignerWarnings(t *testing.T) {
	doc := `tls_cert_path: /tls.crt
tls_key_path: /tls.key
key_store:
  vault_proxy_endpoint: https://vault.internal:8200
rate_limit_per_instance: "1/s"
keystone:
  allowed_users: [3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60]
nova_lookup:
  enabled: false
`
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	want := []findingKey{
		{0, "replica_id", SeverityWarning, KindRisky},
		{0, "tags.allowlist", SeverityWarning, KindRisky},
		{4, "key_store.vault_proxy_endpoint", SeverityWarning, KindRisky},
		{5, "rate_limit_per_instance", SeverityWarning, KindRisky},
		{9, "nova_lookup.enabled", SeverityWarning, KindRisky},
		{0, "audit.syslog.enabled", SeverityWarning, KindRisky},
		{0, "attest", SeverityWarning, KindRisky},
	}
	got := keysOf(result.Warnings())
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing warning %+v", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d warnings, want %d:\n%s", len(got), len(want), dump(result.Warnings()))
	}
	if result.Config.ReplicaID != "ci-runner" {
		t.Errorf("replica_id = %q, want derived from hostname", result.Config.ReplicaID)
	}
	if f := findByPath(t, result.Findings, "replica_id"); !strings.Contains(f.Message, "ci-runner") {
		t.Errorf("replica_id warning %q does not show the derived value", f.Message)
	}
}

func TestCheckSignerClientAddressWarnings(t *testing.T) {
	ignored := `tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: signer-a
tags:
  allowlist: [role]
keystone:
  allowed_users: [3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60]
client_address:
  header: X-Real-IP
` + secureSettings
	result := CheckSigner("signer.yaml", []byte(ignored), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	if got, want := keysOf(result.Warnings()), []findingKey{{9, "client_address.header", SeverityWarning, KindRisky}}; !slices.Equal(got, want) {
		t.Fatalf("warnings %+v, want %+v", got, want)
	}

	wildcard := strings.Replace(ignored, "  header: X-Real-IP\n", "  trusted_proxies:\n    - 10.0.10.0/24\n    - 0.0.0.0/0\n    - \"::/0\"\n", 1)
	result = CheckSigner("signer.yaml", []byte(wildcard), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	want := []findingKey{
		{11, "client_address.trusted_proxies[1]", SeverityWarning, KindRisky},
		{12, "client_address.trusted_proxies[2]", SeverityWarning, KindRisky},
	}
	if got := keysOf(result.Warnings()); !slices.Equal(got, want) {
		t.Fatalf("warnings %+v, want %+v", got, want)
	}
}

func TestCheckAggregatorReportsEverything(t *testing.T) {
	doc := `tls_cert_path: /c
tls_key_path: /k
replicas:
  - https://a/jwks
  - http://b/jwks
pol_interval: 10s
fetch_timeout: 1x
`
	result := CheckAggregator("aggregator.yaml", []byte(doc), checkOptions())
	want := []findingKey{
		{5, "replicas[1]", SeverityError, KindRuleViolation},
		{6, "pol_interval", SeverityError, KindUnknownKey},
		{7, "fetch_timeout", SeverityError, KindInvalidValue},
	}
	got := keysOf(result.Errors())
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing finding %+v", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d errors, want %d:\n%s", len(got), len(want), dump(result.Findings))
	}
	if f := findByPath(t, result.Findings, "pol_interval"); f.Suggestion != "poll_interval" {
		t.Errorf("suggestion = %q", f.Suggestion)
	}
}

func TestCrossCheck(t *testing.T) {
	signer := func(file, replica, publishAhead string) *Result[Signer] {
		doc := strings.Replace(minimalSigner, "replica_id: signer-a", "replica_id: "+replica, 1) +
			"tags:\n  allowlist: [role]\nkey_store:\n  publish_ahead: " + publishAhead + "\n" + secureSettings
		r := CheckSigner(file, []byte(doc), checkOptions())
		if len(r.Findings) != 0 {
			t.Fatalf("setup: unexpected findings:\n%s", dump(r.Findings))
		}
		return r
	}
	aggregator := CheckAggregator("aggregator.yaml", []byte(minimalAggregator+"poll_interval: 60s\nfetch_timeout: 10s\nreplica_ca_cert_path: /ca.pem\n"), checkOptions())
	if len(aggregator.Findings) != 0 {
		t.Fatalf("setup: unexpected findings:\n%s", dump(aggregator.Findings))
	}

	a := signer("a.yaml", "signer-a", "2m")
	b := signer("b.yaml", "signer-b", "100s") // == poll + fetch + cache_max_age: too short
	c := signer("c.yaml", "signer-a", "5m")   // duplicate replica_id
	CrossCheck([]*Result[Signer]{a, b, c}, aggregator)

	if len(a.Findings) != 0 {
		t.Errorf("a.yaml: unexpected findings:\n%s", dump(a.Findings))
	}
	if got := keysOf(b.Errors()); !slices.Equal(got, []findingKey{{10, "key_store.publish_ahead", SeverityError, KindInconsistency}}) {
		t.Errorf("b.yaml findings = %+v", got)
	}
	if got := keysOf(c.Errors()); !slices.Equal(got, []findingKey{{4, "replica_id", SeverityError, KindInconsistency}}) {
		t.Errorf("c.yaml findings = %+v", got)
	}
	if f := findByPath(t, c.Findings, "replica_id"); !strings.Contains(f.Message, "a.yaml") {
		t.Errorf("duplicate replica_id message %q does not name the other file", f.Message)
	}

	// without an aggregator only the replica_id uniqueness is checked
	b2, c2 := signer("b.yaml", "signer-b", "100s"), signer("c.yaml", "signer-a", "5m")
	CrossCheck([]*Result[Signer]{signer("a.yaml", "signer-a", "2m"), b2, c2}, nil)
	if len(b2.Findings) != 0 || len(c2.Errors()) != 1 {
		t.Errorf("without aggregator: b=%+v c=%+v", b2.Findings, c2.Findings)
	}
}

func TestCrossCheckSkipsUndecodableFiles(t *testing.T) {
	broken := CheckSigner("broken.yaml", []byte("key_store: [\n"), checkOptions())
	aggregator := CheckAggregator("aggregator.yaml", []byte("{"), checkOptions())
	CrossCheck([]*Result[Signer]{broken}, aggregator) // must not panic
}

func TestSuggest(t *testing.T) {
	candidates := []string{"poll_interval", "fetch_timeout", "replicas", "tls_key_path", "tls_cert_path"}
	tests := map[string]string{
		"pol_interval":  "poll_interval",
		"poll_intervl":  "poll_interval",
		"replica":       "replicas",
		"tls_kee_path":  "tls_key_path",
		"something":     "",
		"x":             "",
		"fetch_timeout": "fetch_timeout",
	}
	for in, want := range tests {
		if got := suggest(in, candidates); got != want {
			t.Errorf("suggest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResultErr(t *testing.T) {
	result := CheckSigner("signer.yaml", []byte(minimalSigner), checkOptions()) // only warnings
	if len(result.Warnings()) == 0 {
		t.Fatalf("setup: expected warnings")
	}
	if err := result.Err(); err != nil {
		t.Fatalf("Err() = %v with warnings only", err)
	}

	result = CheckSigner("signer.yaml", []byte(minimalSigner+"token_ttl_seconds: 0\n"), checkOptions())
	err := result.Err()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Err() = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "signer.yaml:7: token_ttl_seconds:") {
		t.Fatalf("Err() = %q, want file:line: path", err)
	}
}

func TestSeverityAndKindText(t *testing.T) {
	for v, want := range map[Severity]string{SeverityError: "error", SeverityWarning: "warning", Severity(0): "unknown"} {
		if v.String() != want {
			t.Errorf("Severity(%d).String() = %q, want %q", v, v.String(), want)
		}
	}
	kinds := map[Kind]string{
		KindSyntax: "syntax", KindUnknownKey: "unknown-key", KindInvalidValue: "invalid-value",
		KindRuleViolation: "rule-violation", KindInconsistency: "inconsistency", KindFile: "file",
		KindRisky: "risky", Kind(0): "unknown",
	}
	for v, want := range kinds {
		if v.String() != want {
			t.Errorf("Kind(%d).String() = %q, want %q", v, v.String(), want)
		}
	}

	f := Finding{Line: 3, Path: "a.b", Severity: SeverityWarning, Kind: KindRisky, Message: "m"}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(string(data), `"severity":"warning"`) || !strings.Contains(string(data), `"kind":"risky"`) {
		t.Errorf("json = %s", data)
	}
	out, err := yaml.Marshal(f)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if !strings.Contains(string(out), "severity: warning") || !strings.Contains(string(out), "kind: risky") {
		t.Errorf("yaml = %s", out)
	}
}

func TestRateMarshal(t *testing.T) {
	out, err := yaml.Marshal(struct {
		R Rate `yaml:"r"`
	}{Rate{1, 5 * time.Second}})
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if strings.TrimSpace(string(out)) != "r: 1/5s" {
		t.Fatalf("yaml = %q", out)
	}
}

func TestTLSMinVersion(t *testing.T) {
	signer := func(extra string) string {
		return "tls_cert_path: /c\ntls_key_path: /k\nreplica_id: a\ntags:\n  allowlist: [role]\nkeystone:\n  allowed_users: [3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60]\n" + secureSettings + extra
	}
	aggregator := func(extra string) string {
		return "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [https://a/jwks]\nreplica_ca_cert_path: /ca.pem\n" + extra
	}
	opts := checkOptions()
	opts.SkipFiles = true

	// default: TLS 1.3, no findings
	s := CheckSigner("s.yaml", []byte(signer("")), opts)
	a := CheckAggregator("a.yaml", []byte(aggregator("")), opts)
	if len(s.Findings)+len(a.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s%s", dump(s.Findings), dump(a.Findings))
	}
	if s.Config.TLSMinVersion != "1.3" || s.Config.MinTLSVersion() != tls.VersionTLS13 ||
		a.Config.TLSMinVersion != "1.3" || a.Config.MinTLSVersion() != tls.VersionTLS13 {
		t.Fatalf("defaults: signer %q, aggregator %q", s.Config.TLSMinVersion, a.Config.TLSMinVersion)
	}

	// 1.2: allowed, with a warning
	s = CheckSigner("s.yaml", []byte(signer(`tls_min_version: "1.2"`+"\n")), opts)
	a = CheckAggregator("a.yaml", []byte(aggregator(`tls_min_version: "1.2"`+"\n")), opts)
	for _, r := range [][]Finding{s.Findings, a.Findings} {
		if got := keysOf(r); len(got) != 1 || got[0].Path != "tls_min_version" || got[0].Severity != SeverityWarning {
			t.Fatalf("findings %+v, want one tls_min_version warning", got)
		}
	}
	if s.Config.MinTLSVersion() != tls.VersionTLS12 || a.Config.MinTLSVersion() != tls.VersionTLS12 {
		t.Fatal("1.2 not mapped to tls.VersionTLS12")
	}

	// anything else: an error
	// unquoted numbers decode as their string form
	if s := CheckSigner("s.yaml", []byte(signer("tls_min_version: 1.2\n")), opts); s.Config.MinTLSVersion() != tls.VersionTLS12 || len(s.Errors()) != 0 {
		t.Fatalf("unquoted 1.2: %q, errors %+v", s.Config.TLSMinVersion, s.Errors())
	}
	for _, bad := range []string{`"1.1"`, `"1.0"`, `"TLS1.3"`, `1.30`, `""`} {
		s = CheckSigner("s.yaml", []byte(signer("tls_min_version: "+bad+"\n")), opts)
		a = CheckAggregator("a.yaml", []byte(aggregator("tls_min_version: "+bad+"\n")), opts)
		for _, errs := range [][]Finding{s.Errors(), a.Errors()} {
			if len(errs) != 1 || errs[0].Path != "tls_min_version" {
				t.Fatalf("tls_min_version %s: errors %+v, want one on tls_min_version", bad, errs)
			}
		}
	}
}

func TestCheckSignerSecureSettingsHaveNoWarning(t *testing.T) {
	doc := `tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: signer-a
tags:
  allowlist: [role]
keystone:
  allowed_users: [3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60]
audit:
  syslog:
    enabled: true
attest:
  client_ca_path: /etc/openstack-spire-issuer/nova-client-ca.pem
`
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s", dump(result.Findings))
	}
}

func TestCheckSignerSecurityWarnings(t *testing.T) {
	doc := `tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: signer-a
tags:
  allowlist: [role]
keystone:
  allowed_users: [nova@Default, nova-vendordata@Default, ` + vendordataUserID + `]
peers:
  urls: [https://signer-b.internal:8443/jwks/local.json]
audit:
  syslog:
    enabled: true
`
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	got := keysOf(result.Warnings())
	want := []findingKey{
		{0, "attest", SeverityWarning, KindRisky},                    // neither restriction (S-3)
		{7, "keystone.allowed_users[0]", SeverityWarning, KindRisky}, // name@domain (E-6)
		{7, "keystone.allowed_users[0]", SeverityWarning, KindRisky}, // nova (S-3)
		{7, "keystone.allowed_users[1]", SeverityWarning, KindRisky}, // name@domain (E-6)
		{9, "peers.urls", SeverityWarning, KindRisky},                // public CAs (S-5)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("warnings:\n%s\nwant %+v", dump(result.Warnings()), want)
	}
	for _, f := range result.Warnings() {
		if strings.Contains(f.Path, "allowed_users[1]") && !strings.Contains(f.Message, "user ID") {
			t.Errorf("the name@domain warning does not recommend the user ID: %s", f.Message)
		}
	}

	// every source allowed: as good as no restriction
	open := strings.Replace(doc, "audit:", "attest:\n  allowed_sources: [\"10.0.20.0/24\", \"0.0.0.0/0\"]\naudit:", 1)
	result = CheckSigner("signer.yaml", []byte(open), checkOptions())
	if f := findByPath(t, result.Findings, "attest.allowed_sources[1]"); f.Severity != SeverityWarning {
		t.Errorf("0.0.0.0/0 in attest.allowed_sources: %+v, want a warning", f)
	}
	for _, f := range result.Findings {
		if f.Path == "attest" {
			t.Errorf("unexpected warning with allowed_sources set: %+v", f)
		}
	}

	// a client CA alone is a restriction too
	certOnly := strings.Replace(doc, "audit:", "attest:\n  client_ca_path: /nova-ca.pem\naudit:", 1)
	for _, f := range CheckSigner("signer.yaml", []byte(certOnly), checkOptions()).Findings {
		if f.Path == "attest" {
			t.Errorf("unexpected warning with client_ca_path set: %+v", f)
		}
	}
}

func TestCheckAggregatorWithoutReplicaCA(t *testing.T) {
	doc := "tls_cert_path: /c\ntls_key_path: /k\nreplicas: [https://a/jwks/local.json]\n"
	result := CheckAggregator("aggregator.yaml", []byte(doc), checkOptions())
	if f := findByPath(t, result.Findings, "replica_ca_cert_path"); f.Severity != SeverityWarning {
		t.Errorf("no replica_ca_cert_path: %+v, want a warning (S-5)", f)
	}
}
