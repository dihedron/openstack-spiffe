package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/claims"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/token"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
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

func (f *fakeMinter) Mint(ctx context.Context, req claims.NovaRequest, e claims.Enrichment) (string, error) {
	f.calls++
	f.req, f.enrichment = req, e
	return f.token, f.err
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

func TestMalformedPayloadIsLoggedWithoutUserData(t *testing.T) {
	logs := captureLogs(t)
	f := newFixture(t)
	body := `{"project-id":"` + projectID + `","user-data":"` + userData + `", broken`
	if w := f.do(http.MethodPost, body); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	out := logs.String()
	if strings.Contains(out, userData) || strings.Contains(out, userData[:12]) {
		t.Fatalf("user-data leaked into the logs:\n%s", out)
	}
	if !strings.Contains(out, projectID) {
		t.Fatalf("payload prefix not logged:\n%s", out)
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
