package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
)

const metricsOn = "metrics:\n  enabled: true\n  prometheus:\n    listen_addr: 127.0.0.1:0\n"

// get fetches a URL and returns the status and body.
func get(t *testing.T, client *http.Client, method, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestSignerMetrics(t *testing.T) {
	h := start(t, metricsOn)
	if h.metricsURL == "" {
		t.Fatal("no metrics listener")
	}
	if code, _ := get(t, h.client, http.MethodGet, h.url+"/liveness"); code != http.StatusOK {
		t.Fatalf("/liveness: %d", code)
	}
	plain := &http.Client{Timeout: 10 * time.Second}
	code, body := get(t, plain, http.MethodGet, h.metricsURL+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics: %d", code)
	}
	for _, want := range []string{
		`http_server_request_duration_seconds_count{`,
		`http_route="/liveness"`,
		`openstack_spire_component="signer"`,
		`service_instance_id="signer-a"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics has no %s", want)
		}
	}

	// never on the Nova-facing listener (I-8)
	if code, body := get(t, h.client, http.MethodGet, h.url+"/metrics"); code != http.StatusNotFound || strings.Contains(body, "http_server") {
		t.Errorf("/metrics on the service listener: %d", code)
	}
	if code, _ := get(t, plain, http.MethodPost, h.metricsURL+"/metrics"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics: %d, want 405", code)
	}
	if code, _ := get(t, plain, http.MethodGet, h.metricsURL+"/readiness"); code != http.StatusNotFound {
		t.Errorf("another path on the metrics listener: %d, want 404", code)
	}
}

func TestMetricsListenerRateLimit(t *testing.T) {
	h := start(t, metricsOn+"    rate_limit_per_source: 2/1m\n")
	plain := &http.Client{Timeout: 10 * time.Second}
	codes := []int{}
	for range 3 {
		code, _ := get(t, plain, http.MethodGet, h.metricsURL+"/metrics")
		codes = append(codes, code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Errorf("statuses %v, want 200, 200, 429", codes)
	}
}

func TestMetricsListenerClientCertificates(t *testing.T) {
	caPath, valid, foreign := clientPKI(t)
	certPath, keyPath, pool := writeTLS(t)
	h := start(t, "metrics:\n  enabled: true\n  prometheus:\n    listen_addr: 0.0.0.0:0\n"+
		"    tls_cert_path: "+certPath+"\n    tls_key_path: "+keyPath+"\n    client_ca_path: "+caPath+"\n")
	if !strings.HasPrefix(h.metricsURL, "https://") {
		t.Fatalf("metrics URL %q: not TLS", h.metricsURL)
	}
	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs},
		}}
	}
	if code, _ := get(t, client(valid), http.MethodGet, h.metricsURL+"/metrics"); code != http.StatusOK {
		t.Errorf("with a valid client certificate: %d", code)
	}
	for name, c := range map[string]*http.Client{"no certificate": client(), "another CA": client(foreign)} {
		req, _ := http.NewRequest(http.MethodGet, h.metricsURL+"/metrics", nil)
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: answered %d, want a refused handshake", name, resp.StatusCode)
		}
	}
	// plain HTTP is not served
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(strings.Replace(h.metricsURL, "https://", "http://", 1) + "/metrics"); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("metrics served over plain HTTP")
		}
	}
}

func TestAggregatorMetrics(t *testing.T) {
	replica := newFakeReplica(t)
	h := startAggregator(t, metricsOn, replica)
	if h.metricsURL == "" {
		t.Fatal("no metrics listener")
	}
	if code, _ := get(t, h.client, http.MethodGet, h.url+"/liveness"); code != http.StatusOK {
		t.Fatalf("/liveness: %d", code)
	}
	code, body := get(t, &http.Client{Timeout: 10 * time.Second}, http.MethodGet, h.metricsURL+"/metrics")
	if code != http.StatusOK || !strings.Contains(body, `openstack_spire_component="aggregator"`) || !strings.Contains(body, `http_route="/liveness"`) {
		t.Errorf("/metrics: %d\n%s", code, body)
	}
}

func TestRunWithMetricsListeners(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	served := func(context.Context, net.Listener, net.Listener) error { return nil }
	ctx := context.Background()

	disabled, err := metrics.New(ctx, config.Metrics{}, metrics.Resource{}, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	// disabled: the metrics address is never listened on
	if err := runWithMetrics(ctx, "127.0.0.1:0", disabled, busy.Addr().String(), served); err != nil {
		t.Errorf("disabled metrics: %v", err)
	}
	enabled, err := metrics.New(ctx, config.Metrics{Enabled: true, Exporter: config.ExporterPrometheus}, metrics.Resource{}, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	// enabled: a busy metrics address fails the start
	if err := runWithMetrics(ctx, "127.0.0.1:0", enabled, busy.Addr().String(), served); err == nil || !strings.Contains(err.Error(), "for metrics") {
		t.Errorf("a busy metrics address: %v", err)
	}
}
