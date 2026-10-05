package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

var testResource = Resource{Component: "signer", InstanceID: "signer-a", Version: "1.2.3"}

func enabled(exporter string) Config {
	return Config{
		Enabled:     true,
		Exporter:    exporter,
		MaxProjects: 500,
		OTLP:        OTLPConfig{Protocol: ProtocolHTTP, Interval: time.Hour, Timeout: 5 * time.Second},
	}
}

// serve sends one request through the middleware, to a handler answering
// with status.
func serve(m *Metrics, method, path string, status int) {
	h := m.Middleware([]string{"/attest", "/liveness"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
}

// scrape returns the Prometheus endpoint's body.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	if m.Handler() == nil {
		t.Fatal("no Prometheus handler")
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("scrape: status %d", w.Code)
	}
	return w.Body.String()
}

func TestDisabled(t *testing.T) {
	for name, m := range map[string]*Metrics{"nil": nil, "disabled": mustNew(t, Config{Enabled: false})} {
		t.Run(name, func(t *testing.T) {
			if m.Handler() != nil {
				t.Error("a Prometheus handler while disabled")
			}
			serve(m, http.MethodGet, "/attest", http.StatusOK) // must not panic
			if err := m.Shutdown(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
}

func mustNew(t *testing.T, cfg Config, opts ...Option) *Metrics {
	t.Helper()
	m, err := New(context.Background(), cfg, testResource, tls.VersionTLS13, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m
}

func TestPrometheus(t *testing.T) {
	// the resource attributes set here win over the environment's
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.instance.id=from-env")
	t.Setenv("OTEL_SERVICE_NAME", "from-env")
	cfg := enabled(ExporterPrometheus)
	cfg.Runtime = true
	m := mustNew(t, cfg)
	serve(m, http.MethodPost, "/attest", http.StatusOK)
	serve(m, http.MethodGet, "/random/probe", http.StatusNotFound)
	serve(m, "BREW", "/liveness", http.StatusMethodNotAllowed)

	body := scrape(t, m)
	for _, want := range []string{
		`http_server_request_duration_seconds_bucket{`,
		`http_route="/attest"`,
		`http_route="other"`,
		`http_request_method="_OTHER"`,
		`http_response_status_code="404"`,
		`service_instance_id="signer-a"`,
		`service_name="openstack-spire-issuer"`,
		`service_version="1.2.3"`,
		`openstack_spire_component="signer"`,
		`go_goroutine_count`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape has no %s", want)
		}
	}
	if strings.Contains(body, "/random/probe") {
		t.Error("an unknown path became a series")
	}
	if strings.Contains(body, "from-env") {
		t.Error("the environment overrode the resource")
	}
}

func TestPrometheusWithoutRuntime(t *testing.T) {
	m := mustNew(t, enabled(ExporterPrometheus))
	if strings.Contains(scrape(t, m), "go_goroutine_count") {
		t.Error("runtime metrics while runtime is false")
	}
}

// collector is an in-process OTLP collector over TLS.
type collector struct {
	caPath string
	addr   string

	mu       sync.Mutex
	requests []*collectorpb.ExportMetricsServiceRequest
	headers  []http.Header
	paths    []string
}

func (c *collector) record(req *collectorpb.ExportMetricsServiceRequest, h http.Header, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, req)
	c.headers = append(c.headers, h)
	c.paths = append(c.paths, path)
}

func (c *collector) received() ([]*collectorpb.ExportMetricsServiceRequest, []http.Header, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.headers, c.paths
}

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newHTTPCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body = zr
		}
		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &collectorpb.ExportMetricsServiceRequest{}
		if err := proto.Unmarshal(data, req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.record(req, r.Header.Clone(), r.URL.Path)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(nil)
	}))
	t.Cleanup(srv.Close)
	c.caPath, c.addr = writeCA(t, srv), srv.Listener.Addr().String()
	return c
}

type grpcCollector struct {
	collectorpb.UnimplementedMetricsServiceServer
	c *collector
}

func (g grpcCollector) Export(ctx context.Context, req *collectorpb.ExportMetricsServiceRequest) (*collectorpb.ExportMetricsServiceResponse, error) {
	md, _ := grpcmetadata.FromIncomingContext(ctx)
	h := http.Header{}
	for k, v := range md {
		h[http.CanonicalHeaderKey(k)] = v
	}
	g.c.record(req, h, "grpc")
	return &collectorpb.ExportMetricsServiceResponse{}, nil
}

func newGRPCCollector(t *testing.T) *collector {
	t.Helper()
	// borrow httptest's certificate, valid for 127.0.0.1
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	certSource.Close()
	c := &collector{caPath: writeCA(t, certSource)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: certSource.TLS.Certificates})))
	collectorpb.RegisterMetricsServiceServer(srv, grpcCollector{c: c})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	c.addr = ln.Addr().String()
	return c
}

// hasMetric reports whether an export carries the named metric and the
// signer's resource.
func hasMetric(req *collectorpb.ExportMetricsServiceRequest, name string) (metric, resource bool) {
	for _, rm := range req.GetResourceMetrics() {
		for _, kv := range rm.GetResource().GetAttributes() {
			if kv.GetKey() == "service.instance.id" && kv.GetValue().GetStringValue() == "signer-a" {
				resource = true
			}
		}
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				metric = metric || m.GetName() == name
			}
		}
	}
	return metric, resource
}

func TestOTLP(t *testing.T) {
	for _, protocol := range []string{ProtocolHTTP, ProtocolGRPC} {
		t.Run(protocol, func(t *testing.T) {
			var c *collector
			if protocol == ProtocolHTTP {
				c = newHTTPCollector(t)
			} else {
				c = newGRPCCollector(t)
			}
			// the environment never redirects the metrics nor adds headers
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://elsewhere.invalid:4318")
			t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "X-From-Env=leak")
			t.Setenv("TEST_OTLP_HEADERS", "Authorization=Bearer%20secret,X-Tenant=lab")
			cfg := enabled(ExporterOTLP)
			cfg.OTLP.Protocol = protocol
			cfg.OTLP.Endpoint = "https://" + c.addr
			cfg.OTLP.CACertPath = c.caPath
			cfg.OTLP.HeadersEnv = "TEST_OTLP_HEADERS"
			m, err := New(context.Background(), cfg, testResource, tls.VersionTLS12)
			if err != nil {
				t.Fatal(err)
			}
			serve(m, http.MethodPost, "/attest", http.StatusOK)
			if err := m.Shutdown(context.Background()); err != nil { // the last export
				t.Fatal(err)
			}
			requests, headers, paths := c.received()
			if len(requests) == 0 {
				t.Fatal("the collector received nothing")
			}
			metric, resource := hasMetric(requests[0], "http.server.request.duration")
			if !metric || !resource {
				t.Errorf("export: metric %v, resource %v", metric, resource)
			}
			if protocol == ProtocolHTTP && paths[0] != otlpHTTPPath {
				t.Errorf("path %q, want %q", paths[0], otlpHTTPPath)
			}
			h := headers[0]
			if got := h.Get("Authorization"); got != "Bearer secret" {
				t.Errorf("Authorization %q from headers_env", got)
			}
			if h.Get("X-From-Env") != "" {
				t.Error("OTEL_EXPORTER_OTLP_HEADERS was sent")
			}
		})
	}
}

func TestOTLPRefusesAnUnknownCA(t *testing.T) {
	c := newHTTPCollector(t)
	cfg := enabled(ExporterOTLP)
	cfg.OTLP.Endpoint = "https://" + c.addr // no ca_cert_path: system roots
	m, err := New(context.Background(), cfg, testResource, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	serve(m, http.MethodPost, "/attest", http.StatusOK)
	_ = m.Shutdown(context.Background())
	if requests, _, _ := c.received(); len(requests) != 0 {
		t.Error("metrics sent to a collector with an unverified certificate")
	}
}

// logs captures the default logger's records.
func logs(t *testing.T) *syncBuffer {
	t.Helper()
	var b syncBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &b
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestOTLPUnreachableCollector(t *testing.T) {
	out := logs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there any more
	cfg := enabled(ExporterOTLP)
	cfg.OTLP.Endpoint = "https://" + addr
	cfg.OTLP.Interval, cfg.OTLP.Timeout = 50*time.Millisecond, 20*time.Millisecond
	m, err := New(context.Background(), cfg, testResource, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 20 {
		serve(m, http.MethodPost, "/attest", http.StatusOK)
		time.Sleep(10 * time.Millisecond)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("requests took %v with an unreachable collector", elapsed)
	}
	_ = m.Shutdown(context.Background())
	if n := strings.Count(out.String(), "metrics export failing"); n != 1 {
		t.Errorf("%d \"metrics export failing\" records, want exactly 1:\n%s", n, out)
	}
}

func TestOTLPHeaders(t *testing.T) {
	if h, err := otlpHeaders(""); err != nil || len(h) != 0 {
		t.Errorf("no variable: %v, %v", h, err)
	}
	if _, err := otlpHeaders("TEST_OTLP_UNSET_VARIABLE"); err == nil {
		t.Error("an unset variable accepted")
	}
	for _, bad := range []string{"novalue", "=value", "a=%zz"} {
		t.Setenv("TEST_OTLP_BAD", bad)
		if _, err := otlpHeaders("TEST_OTLP_BAD"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	t.Setenv("TEST_OTLP_GOOD", " a = 1 , b=x%2Cy")
	h, err := otlpHeaders("TEST_OTLP_GOOD")
	if err != nil || h["a"] != "1" || h["b"] != "x,y" {
		t.Errorf("headers %v, %v", h, err)
	}
}

func TestNewRefusesMissingFiles(t *testing.T) {
	cfg := enabled(ExporterOTLP)
	cfg.OTLP.Endpoint = "https://collector.invalid:4318"
	cfg.OTLP.CACertPath = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(context.Background(), cfg, testResource, tls.VersionTLS12); err == nil {
		t.Error("a missing CA bundle accepted")
	}
}
