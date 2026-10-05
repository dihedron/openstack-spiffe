package config

import (
	"strings"
	"testing"
	"time"
)

func TestMetricsDefaults(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Metrics
	checks := []struct {
		name      string
		got, want any
	}{
		{"enabled", m.Enabled, false},
		{"exporter", m.Exporter, ExporterPrometheus},
		{"runtime", m.Runtime, true},
		{"project_attribute", m.ProjectAttribute, false},
		{"max_projects", m.MaxProjects, 500},
		{"prometheus.listen_addr", m.Prometheus.ListenAddr, "127.0.0.1:9464"},
		{"prometheus.rate_limit_per_source", m.Prometheus.RateLimitPerSource, Rate{Events: 10, Per: time.Second}},
		{"otlp.protocol", m.OTLP.Protocol, ProtocolHTTP},
		{"otlp.interval", m.OTLP.Interval, 30 * time.Second},
		{"otlp.timeout", m.OTLP.Timeout, 10 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	agg, err := parseAggregator(strings.NewReader(minimalAggregator))
	if err != nil {
		t.Fatal(err)
	}
	if agg.Metrics != m {
		t.Errorf("aggregator metrics defaults %+v differ from the signer's %+v", agg.Metrics, m)
	}
}

// metricsDoc is a metrics block, enabled, with the given settings.
func metricsDoc(settings string) string {
	doc := "metrics:\n  enabled: true\n"
	for _, line := range strings.Split(strings.TrimSpace(settings), "\n") {
		if line != "" {
			doc += "  " + line + "\n"
		}
	}
	return doc
}

const otlpSettings = `exporter: otlp
otlp:
  endpoint: https://collector.internal:4318
  ca_cert_path: /ca.pem`

const tlsSettings = `  tls_cert_path: /m.crt
  tls_key_path: /m.key
  client_ca_path: /clients.pem`

func TestMetricsValid(t *testing.T) {
	for name, settings := range map[string]string{
		"disabled defaults":               "",
		"prometheus on loopback":          "exporter: prometheus",
		"localhost":                       "prometheus:\n  listen_addr: localhost:9464",
		"ipv6 loopback":                   "prometheus:\n  listen_addr: \"[::1]:9464\"",
		"beyond loopback with tls":        "prometheus:\n  listen_addr: 10.0.0.5:9464\n" + tlsSettings,
		"loopback with tls, no client ca": "prometheus:\n  tls_cert_path: /m.crt\n  tls_key_path: /m.key",
		"otlp http":                       otlpSettings,
		"otlp grpc":                       otlpSettings + "\n  protocol: grpc",
		"otlp client certificate":         otlpSettings + "\n  client_cert_path: /c.crt\n  client_key_path: /c.key",
		"otlp headers env":                otlpSettings + "\n  headers_env: OTLP_HEADERS",
		"project attribute capped":        "project_attribute: true\nmax_projects: 10",
	} {
		t.Run(name, func(t *testing.T) {
			doc := minimalSigner
			if settings != "" {
				doc += metricsDoc(settings)
			}
			if _, err := parseSignerString(t, doc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMetricsErrors(t *testing.T) {
	tests := []struct {
		name, settings, path string
	}{
		{"unknown exporter", "exporter: statsd", "metrics.exporter"},
		{"unknown protocol", otlpSettings + "\n  protocol: http/json", "metrics.otlp.protocol"},
		{"otlp without endpoint", "exporter: otlp", "metrics.otlp.endpoint"},
		{"otlp over http", "exporter: otlp\notlp:\n  endpoint: http://collector:4318", "metrics.otlp.endpoint"},
		{"otlp endpoint without host", "exporter: otlp\notlp:\n  endpoint: \"https:///v1\"", "metrics.otlp.endpoint"},
		{"interval too short", otlpSettings + "\n  interval: 4s\n  timeout: 1s", "metrics.otlp.interval"},
		{"timeout not under interval", otlpSettings + "\n  interval: 10s\n  timeout: 10s", "metrics.otlp.timeout"},
		{"otlp client certificate without key", otlpSettings + "\n  client_cert_path: /c.crt", "metrics.otlp.client_key_path"},
		{"otlp client key without certificate", otlpSettings + "\n  client_key_path: /c.key", "metrics.otlp.client_cert_path"},
		{"invalid headers env", otlpSettings + "\n  headers_env: \"1-BAD\"", "metrics.otlp.headers_env"},
		{"max projects zero", "max_projects: 0", "metrics.max_projects"},
		{"every interface without tls", "prometheus:\n  listen_addr: \":9464\"", "metrics.prometheus.listen_addr"},
		{"remote address without tls", "prometheus:\n  listen_addr: 10.0.0.5:9464", "metrics.prometheus.listen_addr"},
		{"remote address without client ca", "prometheus:\n  listen_addr: 10.0.0.5:9464\n  tls_cert_path: /m.crt\n  tls_key_path: /m.key", "metrics.prometheus.client_ca_path"},
		{"client ca without tls", "prometheus:\n  client_ca_path: /clients.pem", "metrics.prometheus.client_ca_path"},
		{"certificate without key", "prometheus:\n  tls_cert_path: /m.crt", "metrics.prometheus.tls_key_path"},
		{"malformed listen address", "prometheus:\n  listen_addr: nowhere", "metrics.prometheus.listen_addr"},
		{"same address as the service", "prometheus:\n  listen_addr: 127.0.0.1:8443", "metrics.prometheus.listen_addr"},
		{"bad rate", "prometheus:\n  rate_limit_per_source: fast", "metrics.prometheus.rate_limit_per_source"},
		{"unknown key", "exporters: otlp", "metrics.exporters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSigner("", []byte(minimalSigner+metricsDoc(tt.settings)), CheckOptions{SkipFiles: true})
			found := false
			for _, f := range result.Errors() {
				found = found || strings.HasPrefix(f.Path, tt.path)
			}
			if !found {
				t.Errorf("no error at %s; findings: %v", tt.path, result.Findings)
			}
		})
	}
}

func TestMetricsValidatedWhenDisabled(t *testing.T) {
	result := CheckSigner("", []byte(minimalSigner+"metrics:\n  exporter: statsd\n"), CheckOptions{SkipFiles: true})
	if result.Err() == nil {
		t.Error("an invalid exporter accepted while metrics are disabled")
	}
}

func TestMetricsServiceAddressClash(t *testing.T) {
	for _, tt := range []struct {
		service, metrics string
		clash            bool
	}{
		{"0.0.0.0:8443", "127.0.0.1:8443", true}, // the service listens everywhere
		{"10.0.0.5:8443", "127.0.0.1:8443", false},
		{"127.0.0.1:9464", "127.0.0.1:9464", true},
		{"0.0.0.0:8443", "127.0.0.1:9464", false},
		{"[::]:8443", "[::1]:8443", true},
		{"127.0.0.1:0", "127.0.0.1:0", false}, // any free port
	} {
		doc := strings.Replace(minimalSigner, "replica_id:", "listen_addr: \""+tt.service+"\"\nreplica_id:", 1) +
			metricsDoc("prometheus:\n  listen_addr: \""+tt.metrics+"\"")
		result := CheckSigner("", []byte(doc), CheckOptions{SkipFiles: true})
		clash := false
		for _, f := range result.Errors() {
			clash = clash || f.Path == "metrics.prometheus.listen_addr"
		}
		if clash != tt.clash {
			t.Errorf("service %s, metrics %s: clash %v, want %v (%v)", tt.service, tt.metrics, clash, tt.clash, result.Findings)
		}
	}
}

func TestMetricsWarnings(t *testing.T) {
	warned := func(findings []Finding, path, text string) bool {
		for _, f := range findings {
			if f.Path == path && strings.Contains(f.Message, text) {
				return true
			}
		}
		return false
	}
	signer := CheckSigner("", []byte(minimalSigner+metricsDoc("project_attribute: true")), CheckOptions{SkipFiles: true})
	if !warned(signer.Warnings(), "metrics.project_attribute", "tenant") {
		t.Errorf("no warning about project_attribute: %v", signer.Findings)
	}
	otlp := CheckSigner("", []byte(minimalSigner+metricsDoc("exporter: otlp\notlp:\n  endpoint: https://collector:4318")), CheckOptions{SkipFiles: true})
	if !warned(otlp.Warnings(), "metrics.otlp.ca_cert_path", "public CA") {
		t.Errorf("no warning about otlp.ca_cert_path: %v", otlp.Findings)
	}
	agg := CheckAggregator("", []byte(minimalAggregator+metricsDoc("project_attribute: true")), CheckOptions{SkipFiles: true})
	if !warned(agg.Warnings(), "metrics.project_attribute", "ignored") {
		t.Errorf("no warning about project_attribute on the aggregator: %v", agg.Findings)
	}
	quiet := CheckSigner("", []byte(minimalSigner+metricsDoc(otlpSettings)), CheckOptions{SkipFiles: true})
	for _, f := range quiet.Warnings() {
		if strings.HasPrefix(f.Path, "metrics") {
			t.Errorf("unexpected warning: %v", f)
		}
	}
}

func TestMetricsAggregatorErrors(t *testing.T) {
	result := CheckAggregator("", []byte(minimalAggregator+metricsDoc("prometheus:\n  listen_addr: 10.0.0.5:9464")), CheckOptions{SkipFiles: true})
	if result.Err() == nil {
		t.Error("a non-loopback metrics listener without TLS accepted on the aggregator")
	}
}

func TestMetricsFileChecks(t *testing.T) {
	doc := minimalSigner + metricsDoc(otlpSettings+"\n  client_cert_path: /nonexistent/c.crt\n  client_key_path: /nonexistent/c.key")
	result := CheckSigner("", []byte(doc), CheckOptions{Hostname: func() (string, error) { return "h", nil }})
	for _, path := range []string{"metrics.otlp.ca_cert_path", "metrics.otlp.client_cert_path"} {
		found := false
		for _, f := range result.Errors() {
			found = found || (f.Path == path && f.Kind == KindFile)
		}
		if !found {
			t.Errorf("no file error at %s: %v", path, result.Findings)
		}
	}
}

func TestMetricsSettings(t *testing.T) {
	cfg, err := parseSignerString(t, minimalSigner+metricsDoc(otlpSettings+"\n  protocol: grpc\n  interval: 20s\n  timeout: 4s\n  client_cert_path: /c.crt\n  client_key_path: /c.key\n  headers_env: H\nproject_attribute: true\nmax_projects: 7\nruntime: false"))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Metrics.Settings()
	if !s.Enabled || s.Exporter != ExporterOTLP || s.Runtime || !s.ProjectAttribute || s.MaxProjects != 7 {
		t.Errorf("settings %+v", s)
	}
	o := s.OTLP
	if o.Endpoint != "https://collector.internal:4318" || o.Protocol != ProtocolGRPC || o.Interval != 20*time.Second || o.Timeout != 4*time.Second ||
		o.CACertPath != "/ca.pem" || o.ClientCertPath != "/c.crt" || o.ClientKeyPath != "/c.key" || o.HeadersEnv != "H" {
		t.Errorf("OTLP settings %+v", o)
	}
}
