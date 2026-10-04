package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// peeredSigner is a valid signer with two peers and no warnings but the
// one about the disabled syslog audit sink, left out so that tests can
// append to its peers block.
const peeredSigner = minimalSigner + `tags:
  allowlist: [role]
peers:
  urls:
    - https://signer-b.internal:8443/jwks/local.json
    - https://signer-c.internal:8443/jwks/local.json
`

func TestSignerPeersDefaults(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Peers.Enabled() {
		t.Fatalf("peers enabled by default: %+v", cfg.Peers)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"peers.poll_interval", cfg.Peers.PollInterval, 30 * time.Second},
		{"peers.fetch_timeout", cfg.Peers.FetchTimeout, 5 * time.Second},
		{"peers.stale_key_retention", cfg.Peers.StaleKeyRetention, 5 * time.Minute},
		{"peers.cache_max_age", cfg.Peers.CacheMaxAge, 30 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestSignerPeersValid(t *testing.T) {
	result := CheckSigner("signer.yaml", []byte(peeredSigner+auditSyslogEnabled), checkOptions())
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s", dump(result.Findings))
	}
	if !result.Config.Peers.Enabled() || len(result.Config.Peers.URLs) != 2 {
		t.Fatalf("peers = %+v", result.Config.Peers)
	}
}

func TestSignerPeersInvalid(t *testing.T) {
	tests := []struct {
		name   string
		append string
		want   string // YAML path of the expected error
	}{
		{"http peer", "    - http://signer-d.internal/jwks/local.json\n", "peers.urls[2]"},
		{"peer without host", "    - \"https:///jwks/local.json\"\n", "peers.urls[2]"},
		{"unparsable peer", "    - \"https://a b/\"\n", "peers.urls[2]"},
		{"duplicate peer", "    - https://signer-b.internal:8443/jwks/local.json\n", "peers.urls[2]"},
		{"peer serving its merged set", "    - https://signer-d.internal:8443/.well-known/jwks.json\n", "peers.urls[2]"},
		{"merged set behind a path prefix", "    - https://lb.internal/signer-d/.well-known/jwks.json\n", "peers.urls[2]"},
		{"poll interval zero", "  poll_interval: 0s\n", "peers.poll_interval"},
		{"fetch timeout >= poll", "  poll_interval: 10s\n  fetch_timeout: 10s\n", "peers.fetch_timeout"},
		{"retention shorter than token ttl", "  stale_key_retention: 4m\n", "peers.stale_key_retention"},
		{"negative cache age", "  cache_max_age: -1s\n", "peers.cache_max_age"},
		{"fractional cache age", "  cache_max_age: 1500ms\n", "peers.cache_max_age"},
		// defaults: 30s + 5s + 30s = 65s
		{"publish_ahead too short", "key_store:\n  publish_ahead: 65s\n", "key_store.publish_ahead"},
		{"publish_ahead ignores cache", "  poll_interval: 60s\n  fetch_timeout: 10s\n  cache_max_age: 60s\nkey_store:\n  publish_ahead: 2m\n", "key_store.publish_ahead"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSigner("signer.yaml", []byte(peeredSigner+tt.append), checkOptions())
			errs := result.Errors()
			i := slices.IndexFunc(errs, func(f Finding) bool { return f.Path == tt.want })
			if i < 0 {
				t.Fatalf("errors %+v, want one at %q", keysOf(errs), tt.want)
			}
			if errs[i].Line == 0 {
				t.Errorf("finding %+v has no line", errs[i])
			}
		})
	}
}

func TestSignerPeersSettingsWithoutURLsWarn(t *testing.T) {
	doc := minimalSigner + "tags:\n  allowlist: [role]\npeers:\n  poll_interval: 10s\n  fetch_timeout: 1s\n" + auditSyslogEnabled
	result := CheckSigner("signer.yaml", []byte(doc), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	want := []findingKey{
		{10, "peers.poll_interval", SeverityWarning, KindRisky},
		{11, "peers.fetch_timeout", SeverityWarning, KindRisky},
	}
	if got := keysOf(result.Warnings()); !slices.Equal(got, want) {
		t.Fatalf("warnings %+v, want %+v", got, want)
	}

	// without peers, publish_ahead is not checked against the peer timing
	doc = minimalSigner + "tags:\n  allowlist: [role]\nkey_store:\n  publish_ahead: 10s\n" + auditSyslogEnabled
	if result := CheckSigner("signer.yaml", []byte(doc), checkOptions()); len(result.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s", dump(result.Findings))
	}
}

func TestFileChecksPeersCABundle(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir, "server", fileCheckNow.Add(365*24*time.Hour), 0o600)
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := signerDoc(cert, key, "") + "peers:\n  urls: [https://b/jwks/local.json]\n  ca_cert_path: " + garbage + "\n"
	result := CheckSigner("signer.yaml", []byte(doc), fileCheckOptions())
	want := []findingKey{{10, "peers.ca_cert_path", SeverityError, KindFile}}
	if got := fileFindings(result.Findings); !slices.Equal(got, want) {
		t.Fatalf("file findings = %+v, want %+v\n%s", got, want, dump(result.Findings))
	}
}

func TestAggregatorWarnsAboutMergedReplicaURLs(t *testing.T) {
	doc := strings.Replace(minimalAggregator, "https://signer-b.internal:8443/jwks/local.json", "https://signer-b.internal:8443/.well-known/jwks.json", 1)
	result := CheckAggregator("aggregator.yaml", []byte(doc), checkOptions())
	if len(result.Errors()) != 0 {
		t.Fatalf("unexpected errors:\n%s", dump(result.Errors()))
	}
	want := []findingKey{{6, "replicas[1]", SeverityWarning, KindRisky}}
	if got := keysOf(result.Warnings()); !slices.Equal(got, want) {
		t.Fatalf("warnings %+v, want %+v", got, want)
	}
}
