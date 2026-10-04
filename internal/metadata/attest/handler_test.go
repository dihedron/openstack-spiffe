package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/metadata/auth"
	"github.com/dihedron/openstack-spiffe/internal/metadata/claims"
	"github.com/dihedron/openstack-spiffe/internal/metadata/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/metadata/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/metadata/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/metadata/token"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

const (
	projectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	instanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
	userData   = "I2Nsb3VkLWNvbmZpZwpwYXNzd29yZDogaHVudGVyMg==" // a secret
)

var validBody = `{"project-id":"` + projectID + `","instance-id":"` + instanceID + `","image-id":"img","hostname":"vm-01",` +
	`"metadata":{"role":"web"},"user-data":"` + userData + `","boot-roles":"member"}`

// fakes record their calls, so that tests can check what was (not) reached.
type fakeLimiter struct {
	mu    sync.Mutex
	allow bool
	retry time.Duration
	keys  []string
}

func (f *fakeLimiter) Allow(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	return f.allow, f.retry
}

type fakeVerifier struct {
	enrichment claims.Enrichment
	err        error
	calls      int
}

func (f *fakeVerifier) Verify(ctx context.Context, projectID, instanceID string) (claims.Enrichment, error) {
	f.calls++
	return f.enrichment, f.err
}

type fakeMinter struct {
	token      string
	err        error
	calls      int
	req        claims.NovaRequest
	enrichment claims.Enrichment
}

const (
	testKID = "2026-09-29-signer-a-key-52331"
	testJTI = "5b1f0f3e-2f7a-4c1e-8d0a-6c2f9b7e4a11"
	testIAT = int64(1790692331)
)

func (f *fakeMinter) Mint(ctx context.Context, req claims.NovaRequest, e claims.Enrichment) (token.Issued, error) {
	f.calls++
	f.req, f.enrichment = req, e
	if f.err != nil {
		return token.Issued{}, f.err
	}
	return token.Issued{Token: f.token, KeyID: testKID, ID: testJTI, IssuedAt: testIAT, Expiry: testIAT + 300}, nil
}

type fixture struct {
	limiter  *fakeLimiter
	verifier *fakeVerifier
	minter   *fakeMinter
	handler  *Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		limiter:  &fakeLimiter{allow: true},
		verifier: &fakeVerifier{enrichment: claims.Enrichment{AvailabilityZone: "az-1"}},
		minter:   &fakeMinter{token: "h.p.s"},
	}
	h, err := NewHandler(f.limiter, f.verifier, f.minter, 4096)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	f.handler = h
	return f
}

func (f *fixture) do(method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/attest", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// captureLogs redirects the default logger for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestHappyPath(t *testing.T) {
	f := newFixture(t)
	w := f.do(http.MethodPost, validBody)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", cc)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"openstack_iid":{"jwt":"h.p.s"}}`; got != want {
		t.Fatalf("body %s, want %s", got, want)
	}
	if f.limiter.keys[0] != instanceID {
		t.Fatalf("rate limited on %q, want the instance ID", f.limiter.keys[0])
	}
	if f.minter.req.InstanceID != instanceID || f.minter.req.Metadata["role"] != "web" {
		t.Fatalf("minter got %+v", f.minter.req)
	}
	if f.minter.enrichment.AvailabilityZone != "az-1" {
		t.Fatalf("enrichment not passed to the minter: %+v", f.minter.enrichment)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		w := f.do(method, validBody)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s: status %d, Allow %q; want 405, POST", method, w.Code, w.Header().Get("Allow"))
		}
	}
	if f.minter.calls != 0 {
		t.Fatal("minter called")
	}
}

func TestBadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"not JSON", `project-id=x`},
		{"truncated JSON", `{"project-id":"` + projectID + `",`},
		{"array", `[]`},
		{"trailing data", validBody + `{}`},
		{"duplicate instance-id", `{"project-id":"` + projectID + `","instance-id":"` + instanceID + `","instance-id":"00000000-0000-4000-8000-000000000000","hostname":"vm"}`},
		{"missing instance-id", `{"project-id":"` + projectID + `","hostname":"vm"}`},
		{"non-canonical instance-id", `{"project-id":"` + projectID + `","instance-id":"` + strings.ToUpper(instanceID) + `","hostname":"vm"}`},
		{"wrong type", `{"project-id":42,"instance-id":"` + instanceID + `","hostname":"vm"}`},
		{"too large", `{"project-id":"` + projectID + `","instance-id":"` + instanceID + `","hostname":"vm","user-data":"` + strings.Repeat("A", 5000) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if w := f.do(http.MethodPost, tt.body); w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", w.Code)
			}
			if len(f.limiter.keys) != 0 || f.verifier.calls != 0 || f.minter.calls != 0 {
				t.Fatal("invalid request went past validation")
			}
		})
	}
}

func TestRejectedPayloadIsLoggedRedacted(t *testing.T) {
	logs := captureLogs(t)
	f := newFixture(t)
	body := `{"project-id":"` + projectID + `","instance-id":"NOT-A-UUID","hostname":"vm","user-data":"` + userData + `"}`
	if w := f.do(http.MethodPost, body); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	out := logs.String()
	if strings.Contains(out, userData) {
		t.Fatalf("user-data leaked into the logs:\n%s", out)
	}
	if !strings.Contains(out, "NOT-A-UUID") || !strings.Contains(out, "redacted") {
		t.Fatalf("payload not logged (redacted):\n%s", out)
	}
}

func TestUnparseablePayloadIsLoggedBySizeAndHashOnly(t *testing.T) {
	logs := captureLogs(t)
	f := newFixture(t)
	body := `{"project-id":"` + projectID + `","user-data":"` + userData + `", broken`
	if w := f.do(http.MethodPost, body); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	out := logs.String()
	// the sensitive values cannot be located reliably in an unparseable
	// payload, so none of its content is logged
	if strings.Contains(out, userData[:12]) || strings.Contains(out, projectID) {
		t.Fatalf("payload content leaked into the logs:\n%s", out)
	}
	sum := sha256.Sum256([]byte(body))
	for _, want := range []string{fmt.Sprintf("payload_bytes=%d", len(body)), "payload_sha256=" + hex.EncodeToString(sum[:])} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %s:\n%s", want, out)
		}
	}
}

func TestRejectedPayloadMetadataValuesAreRedacted(t *testing.T) {
	logs := captureLogs(t)
	f := newFixture(t)
	body := `{"project-id":"` + projectID + `","instance-id":"NOT-A-UUID","hostname":"vm","metadata":{"db_password":"hunter2","role":"web"}}`
	if w := f.do(http.MethodPost, body); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	out := logs.String()
	if strings.Contains(out, "hunter2") || strings.Contains(out, `\"web\"`) {
		t.Fatalf("metadata value leaked into the logs:\n%s", out)
	}
	if !strings.Contains(out, "db_password") || !strings.Contains(out, "role") {
		t.Fatalf("metadata keys not logged:\n%s", out)
	}
}

func TestLoggedPayloadIsTruncated(t *testing.T) {
	logs := captureLogs(t)
	f := newFixture(t)
	body := `{"project-id":"` + projectID + `","instance-id":"bad","hostname":"vm","metadata":{"k":"` + strings.Repeat("m", 3000) + `"}}`
	f.do(http.MethodPost, body)
	if strings.Contains(logs.String(), strings.Repeat("m", maxLoggedPayload)) {
		t.Fatal("logged payload not truncated")
	}
}

func TestPerInstanceRateLimit(t *testing.T) {
	f := newFixture(t)
	f.limiter.allow, f.limiter.retry = false, 4200*time.Millisecond
	w := f.do(http.MethodPost, validBody)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "5" {
		t.Fatalf("status %d, Retry-After %q; want 429, 5", w.Code, w.Header().Get("Retry-After"))
	}
	if f.verifier.calls != 0 || f.minter.calls != 0 {
		t.Fatal("lookup or signing performed despite the rate limit")
	}
}

func TestVerificationFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"mismatch", fmt.Errorf("%w: instance belongs to another project", novalookup.ErrInstanceMismatch), http.StatusForbidden},
		{"lookup unavailable", fmt.Errorf("%w: connection refused", novalookup.ErrLookupUnavailable), http.StatusServiceUnavailable},
		{"cancelled", context.Canceled, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.verifier.err = tt.err
			w := f.do(http.MethodPost, validBody)
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if f.minter.calls != 0 {
				t.Fatal("token minted despite the verification failure")
			}
			if strings.Contains(w.Body.String(), "another project") || strings.Contains(w.Body.String(), "refused") {
				t.Fatalf("error details leaked to the client: %s", w.Body)
			}
		})
	}
}

func TestMintFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"key store unavailable", fmt.Errorf("minting: %w: vault down", token.ErrKeyStoreUnavailable), http.StatusServiceUnavailable},
		{"invalid request", fmt.Errorf("minting: %w", claims.ErrInvalidRequest), http.StatusBadRequest},
		{"reserved claim", fmt.Errorf("minting: %w", iid.ErrInvalidCustomClaim), http.StatusInternalServerError},
		{"token too large", fmt.Errorf("minting: %w", token.ErrTokenTooLarge), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.minter.token, f.minter.err = "", tt.err
			w := f.do(http.MethodPost, validBody)
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if strings.Contains(w.Body.String(), "jwt") {
				t.Fatalf("token-shaped body on failure: %s", w.Body)
			}
		})
	}
}

func TestNewHandlerValidation(t *testing.T) {
	l, v, m := &fakeLimiter{}, &fakeVerifier{}, &fakeMinter{}
	for _, tt := range []struct {
		name string
		fn   func() (*Handler, error)
	}{
		{"nil limiter", func() (*Handler, error) { return NewHandler(nil, v, m, 1024) }},
		{"nil verifier", func() (*Handler, error) { return NewHandler(l, nil, m, 1024) }},
		{"nil minter", func() (*Handler, error) { return NewHandler(l, v, nil, 1024) }},
		{"zero body cap", func() (*Handler, error) { return NewHandler(l, v, m, 0) }},
	} {
		if _, err := tt.fn(); err == nil {
			t.Fatalf("%s: accepted", tt.name)
		}
	}
}

// TestWithRealComponents wires the real per-instance limiter, key store,
// claims builder and minter: the response carries a token for the instance,
// and a second request within 5s gets 429.
func TestWithRealComponents(t *testing.T) {
	now := time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)
	clock := func() time.Time { return now }
	ks, err := keystore.NewEphemeral(context.Background(), "signer-a", "ES256", keystore.WithClock(clock))
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	now = now.Add(2 * time.Minute)
	builder, err := claims.NewBuilder(claims.WithClock(clock))
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	minter, err := token.NewMinter(ks, builder)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	limiter, err := ratelimit.NewLimiter(1, 5*time.Second, ratelimit.WithClock(clock))
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	h, err := NewHandler(limiter, &fakeVerifier{enrichment: claims.Enrichment{ProjectName: "web"}}, minter, 256*1024)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	post := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(validBody)))
		return w
	}
	w := post()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp iid.VendorDataResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	parts := strings.Split(resp.Target.JWT, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %q is not a compact JWS", resp.Target.JWT)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var c iid.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	if c.Subject != instanceID || c.ProjectID != projectID || c.ProjectName != "web" || c.Tags["role"] != "web" {
		t.Fatalf("unexpected claims: %+v", c)
	}
	if strings.Contains(string(payload), userData) {
		t.Fatal("user-data copied into the token")
	}

	if w := post(); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request within 5s: status %d, want 429", w.Code)
	}
}

// errReader fails the body read, as a client disconnecting mid-body would.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestBodyReadFailure(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/attest", io.NopCloser(errReader{})))
	if w.Code != http.StatusBadRequest || f.minter.calls != 0 {
		t.Fatalf("status %d, minter calls %d; want 400, 0", w.Code, f.minter.calls)
	}
}

// auditRecords returns the token_issued audit records in JSON logs.
func auditRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(logs.String()) {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		if r[syslog.AuditKey] == "token_issued" {
			out = append(out, r)
		}
	}
	return out
}

func captureJSONLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

const auditedToken = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2VjcmV0LXNpZ25hdHVyZQ"

// authenticated returns a request as it reaches the handler behind the
// authentication middleware.
func authenticated(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(body))
	return r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{UserID: "3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60"}))
}

func TestTokenIssuedAuditRecord(t *testing.T) {
	logs := captureJSONLogs(t)
	f := newFixture(t)
	f.minter.token = auditedToken
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, authenticated(validBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}

	records := auditRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("%d token_issued records, want exactly 1:\n%s", len(records), logs)
	}
	r := records[0]
	want := map[string]any{
		"msg":            "token issued",
		"level":          "INFO",
		"user_id":        "3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60",
		"client_address": "192.0.2.1",
		"project_id":     projectID,
		"instance_id":    instanceID,
		"jti":            testJTI,
		"kid":            testKID,
		"iat":            float64(testIAT),
		"exp":            float64(testIAT + 300),
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
	for _, absent := range []string{"peer_address", "client_cert_subject", "client_cert_serial"} {
		if _, ok := r[absent]; ok {
			t.Errorf("%s = %v, want it absent", absent, r[absent])
		}
	}
	for _, secret := range []string{auditedToken, "c2VjcmV0LXNpZ25hdHVyZQ", userData} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log contains %q:\n%s", secret, logs)
		}
	}
}

func TestTokenIssuedAuditRecordBehindTrustedProxy(t *testing.T) {
	logs := captureJSONLogs(t)
	f := newFixture(t)
	resolver, err := clientaddr.NewResolver([]string{"10.0.10.0/24"}, "")
	if err != nil {
		t.Fatal(err)
	}
	r := authenticated(validBody)
	r.RemoteAddr = "10.0.10.3:40000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	resolver.Middleware(f.handler).ServeHTTP(httptest.NewRecorder(), r)

	records := auditRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("%d token_issued records, want 1", len(records))
	}
	if got := records[0]["client_address"]; got != "198.51.100.7" {
		t.Errorf("client_address = %v, want the forwarded address", got)
	}
	if got := records[0]["peer_address"]; got != "10.0.10.3" {
		t.Errorf("peer_address = %v, want the proxy", got)
	}
}

func TestTokenIssuedAuditRecordWithClientCertificate(t *testing.T) {
	logs := captureJSONLogs(t)
	f := newFixture(t)
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "nova-api-metadata", Organization: []string{"cloud"}},
		SerialNumber: big.NewInt(0x1f2e3d),
	}
	r := authenticated(validBody)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	f.handler.ServeHTTP(httptest.NewRecorder(), r)

	records := auditRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("%d token_issued records, want 1", len(records))
	}
	if got, want := records[0]["client_cert_subject"], "CN=nova-api-metadata,O=cloud"; got != want {
		t.Errorf("client_cert_subject = %v, want %v", got, want)
	}
	if got, want := records[0]["client_cert_serial"], "1f2e3d"; got != want {
		t.Errorf("client_cert_serial = %v, want %v", got, want)
	}
}

func TestNoAuditRecordWithoutToken(t *testing.T) {
	for name, setup := range map[string]func(f *fixture){
		"rate limited":        func(f *fixture) { f.limiter.allow = false },
		"instance mismatch":   func(f *fixture) { f.verifier.err = novalookup.ErrInstanceMismatch },
		"lookup unavailable":  func(f *fixture) { f.verifier.err = novalookup.ErrLookupUnavailable },
		"key store down":      func(f *fixture) { f.minter.err = token.ErrKeyStoreUnavailable },
		"oversized token":     func(f *fixture) { f.minter.err = token.ErrTokenTooLarge },
		"invalid for builder": func(f *fixture) { f.minter.err = claims.ErrInvalidRequest },
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureJSONLogs(t)
			f := newFixture(t)
			setup(f)
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, authenticated(validBody))
			if w.Code == http.StatusOK {
				t.Fatal("status 200")
			}
			if records := auditRecords(t, logs); len(records) != 0 {
				t.Fatalf("token_issued records for a refused request: %v", records)
			}
		})
	}
	logs := captureJSONLogs(t)
	f := newFixture(t)
	f.handler.ServeHTTP(httptest.NewRecorder(), authenticated("not json"))
	if records := auditRecords(t, logs); len(records) != 0 {
		t.Fatalf("token_issued records for a bad request: %v", records)
	}
}
