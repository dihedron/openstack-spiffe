package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/openstacktest"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
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

	disabled, err := metrics.New(ctx, metrics.Config{}, metrics.Resource{}, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	// disabled: the metrics address is never listened on
	if err := runWithMetrics(ctx, "127.0.0.1:0", disabled, busy.Addr().String(), served); err != nil {
		t.Errorf("disabled metrics: %v", err)
	}
	enabled, err := metrics.New(ctx, metrics.Config{Enabled: true, Exporter: metrics.ExporterPrometheus}, metrics.Resource{}, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	// enabled: a busy metrics address fails the start
	if err := runWithMetrics(ctx, "127.0.0.1:0", enabled, busy.Addr().String(), served); err == nil || !strings.Contains(err.Error(), "for metrics") {
		t.Errorf("a busy metrics address: %v", err)
	}
}

// attestReasons scrapes the signer's metrics and returns the count of each
// (reason, status) pair of openstack_spire_attest_requests_total.
func attestReasons(t *testing.T, h *harness) map[string]int {
	t.Helper()
	_, body := get(t, &http.Client{Timeout: 10 * time.Second}, http.MethodGet, h.metricsURL+"/metrics")
	reasons := map[string]int{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "openstack_spire_attest_requests_total{") {
			continue
		}
		label := func(name string) string {
			_, rest, _ := strings.Cut(line, name+`="`)
			value, _, _ := strings.Cut(rest, `"`)
			return value
		}
		var n int
		fields := strings.Fields(line)
		if _, err := fmt.Sscan(fields[len(fields)-1], &n); err != nil {
			t.Fatalf("unparsable line %q", line)
		}
		reasons[label("reason")+" "+label("http_response_status_code")] += n
	}
	return reasons
}

// TestAttestReasonsEndToEnd drives the signer, against the fake cloud, into
// every refusal the cloud can produce, and checks that each is counted
// under its reason and status, and none as unspecified.
func TestAttestReasonsEndToEnd(t *testing.T) {
	h := start(t, metricsOn+"enrich: [availability_zone]\n")
	waitReady(t, h) // the first key is published ahead of use
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	alice := h.cloud.IssueToken(openstacktest.User{ID: "fedcba9876543210fedcba9876543210", Name: "alice", DomainID: "default", DomainName: "Default", Roles: []string{"member"}}, time.Now().Add(time.Hour))
	const badZone, down = "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	h.cloud.AddInstance(openstacktest.Instance{ID: badZone, ProjectID: projectID, Status: "ACTIVE", AvailabilityZone: "az\u202e-1"})

	steps := []struct {
		token, body, want string
	}{
		{token, novaBody(projectID, instanceID), "none 200"},
		{token, novaBody(projectID, instanceID), "rate_limited_instance 429"},
		{"", novaBody(projectID, otherInstance), "unauthenticated 401"},
		{alice, novaBody(projectID, otherInstance), "caller_not_allowed 403"},
		{token, "{", "invalid_request 400"},
		{token, novaBody(projectID, otherInstance), "instance_not_allowed 403"}, // another project's
		{token, novaBody(projectID, "44444444-4444-4444-8444-444444444444"), "instance_not_allowed 403"},
		{token, novaBody(projectID, badZone), "enrichment_invalid 503"},
	}
	for _, s := range steps {
		h.request(t, http.MethodPost, "/attest", s.token, s.body)
	}
	h.cloud.SetDown(true)
	h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, down)) // the token is cached: Nova fails
	fresh := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	h.request(t, http.MethodPost, "/attest", fresh, novaBody(projectID, down)) // Keystone fails
	h.cloud.SetDown(false)

	want := map[string]int{"lookup_unavailable 503": 1, "keystone_unavailable 503": 1}
	for _, s := range steps {
		want[s.want]++
	}
	got := attestReasons(t, h)
	for key, n := range want {
		if got[key] != n {
			t.Errorf("%s: %d, want %d", key, got[key], n)
		}
	}
	for key := range got {
		if strings.HasPrefix(key, metrics.ReasonUnspecified) {
			t.Errorf("a rejection with no reason: %s", key)
		}
	}
}

// TestGuardReasonsEndToEnd covers the refusals that need their own
// configuration: the source allowlist, the client certificate and the
// per-source limit.
func TestGuardReasonsEndToEnd(t *testing.T) {
	caPath, _, _ := clientPKI(t)
	for _, tt := range []struct {
		extra, want string
		requests    int
	}{
		{"attest:\n  allowed_sources: [10.99.0.0/16]\n", "source_not_allowed 403", 1},
		{"attest:\n  client_ca_path: " + caPath + "\n", "client_certificate 403", 1},
		{"rate_limit_per_source: 1/1m\n", "rate_limited_source 429", 2},
	} {
		t.Run(tt.want, func(t *testing.T) {
			h := start(t, metricsOn+tt.extra)
			token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
			for range tt.requests {
				h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID))
			}
			if got := attestReasons(t, h); got[tt.want] != 1 {
				t.Errorf("%s: %v", tt.want, got)
			}
		})
	}
}

// series returns the sum of the values of a Prometheus metric's series whose
// labels include every given one (name, value pairs), and whether any did.
func series(body, metric string, labels ...string) (float64, bool) {
	var total float64
	found := false
	for _, line := range strings.Split(body, "\n") {
		name, rest, ok := strings.Cut(line, "{")
		if !ok || name != metric {
			continue
		}
		match := true
		for i := 0; i+1 < len(labels); i += 2 {
			match = match && strings.Contains(rest, labels[i]+`="`+labels[i+1]+`"`)
		}
		if !match {
			continue
		}
		fields := strings.Fields(line)
		var v float64
		if _, err := fmt.Sscan(fields[len(fields)-1], &v); err == nil {
			total, found = total+v, true
		}
	}
	return total, found
}

func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	code, body := get(t, &http.Client{Timeout: 10 * time.Second}, http.MethodGet, url+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics: %d", code)
	}
	return body
}

func TestSignerStateMetrics(t *testing.T) {
	h := start(t, metricsOn+"rate_limit_per_source_public: 1/1m\n")
	// the first takes the only public token, the second is refused
	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		if code, _ := get(t, h.client, http.MethodGet, h.url+"/liveness"); code != want {
			t.Fatalf("/liveness #%d: %d, want %d", i+1, code, want)
		}
	}
	// the metrics listener has its own limit: wait there for the first key
	var body string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		body = scrapeMetrics(t, h.metricsURL)
		if v, _ := series(body, "openstack_spire_readiness_check", "check", "key_store"); v == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the key store never became ready:\n%s", body)
		}
	}
	for _, tt := range []struct {
		metric string
		labels []string
		min    float64
	}{
		{"openstack_spire_keys", []string{"state", "active"}, 1},
		{"openstack_spire_key_rotations_total", nil, 0},
		{"openstack_spire_key_active_age_seconds", nil, 0},
		{"openstack_spire_jwks_keys", []string{"set", "local"}, 1},
		{"openstack_spire_jwks_keys", []string{"set", "merged"}, 1},
		{"openstack_spire_readiness_check", []string{"check", "key_store"}, 1},
		{"openstack_spire_readiness_check", []string{"check", "keystone"}, 1},
		{"openstack_spire_rate_limit_rejections_total", []string{"limiter", "source_public"}, 1},
		{"openstack_spire_rate_limit_tracked", []string{"limiter", "instance"}, 0},
		{"openstack_spire_rate_limit_tracked", []string{"limiter", "metrics"}, 1},
	} {
		v, ok := series(body, tt.metric, tt.labels...)
		if !ok || v < tt.min {
			t.Errorf("%s %v: %v (found %v), want at least %v", tt.metric, tt.labels, v, ok, tt.min)
		}
	}
	if _, ok := series(body, "openstack_spire_audit_syslog_dropped_total"); ok {
		t.Error("syslog metrics without an audit sink")
	}
}

func TestAggregatorStateMetrics(t *testing.T) {
	good, bad := newFakeReplica(t, "k1", "k2"), newFakeReplica(t)
	bad.mu.Lock()
	bad.body = []byte("not a JWK Set")
	bad.mu.Unlock()
	h := startAggregator(t, metricsOn, good, bad)
	goodPeer, badPeer := peerName(good.URL), peerName(bad.URL)
	deadline := time.Now().Add(10 * time.Second)
	for {
		body := scrapeMetrics(t, h.metricsURL)
		ok, _ := series(body, "openstack_spire_jwks_fetches_total", "peer", goodPeer, "result", "ok")
		invalid, _ := series(body, "openstack_spire_jwks_fetches_total", "peer", badPeer, "result", "invalid")
		keys, _ := series(body, "openstack_spire_jwks_keys", "set", "merged")
		_, aged := series(body, "openstack_spire_jwks_fetch_age_seconds", "peer", goodPeer)
		_, badAged := series(body, "openstack_spire_jwks_fetch_age_seconds", "peer", badPeer)
		if ok >= 1 && invalid >= 1 && keys == 2 && aged && !badAged {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ok %v, invalid %v, merged keys %v, good aged %v, bad aged %v\n%s", ok, invalid, keys, aged, badAged, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestObserveAuditSink(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	if err := observeAuditSink(m, func() (syslog.AuditStats, bool) { return syslog.AuditStats{}, false }); err != nil {
		t.Fatal(err)
	}
	if len(r.Points(t, "openstack_spire.audit.syslog.dropped")) != 0 {
		t.Error("syslog metrics while the sink is disabled")
	}
	if err := observeAuditSink(m, func() (syslog.AuditStats, bool) { return syslog.AuditStats{Dropped: 4, Queued: 1}, true }); err != nil {
		t.Fatal(err)
	}
	if got := r.Value(t, "openstack_spire.audit.syslog.dropped"); got != 4 {
		t.Errorf("%d dropped, want 4", got)
	}
}
