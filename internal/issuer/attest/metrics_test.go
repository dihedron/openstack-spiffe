package attest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/issuer/token"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// TestReasons drives every exit of the handler through the /attest metrics
// wrapper: each refusal names its reason, none is left unspecified.
func TestReasons(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   string
		setup  func(*fixture)
		status int
		reason string
	}{
		{"issued", http.MethodPost, validBody, nil, http.StatusOK, metrics.ReasonNone},
		{"method", http.MethodGet, "", nil, http.StatusMethodNotAllowed, metrics.ReasonInvalidRequest},
		{"malformed", http.MethodPost, "{", nil, http.StatusBadRequest, metrics.ReasonInvalidRequest},
		{"invalid", http.MethodPost, `{"project-id":"x","instance-id":"y"}`, nil, http.StatusBadRequest, metrics.ReasonInvalidRequest},
		{"oversized", http.MethodPost, `{"pad":"` + strings.Repeat("x", 5000) + `"}`, nil, http.StatusBadRequest, metrics.ReasonInvalidRequest},
		{"instance rate", http.MethodPost, validBody, func(f *fixture) { f.limiter.allow = false }, http.StatusTooManyRequests, metrics.ReasonRateLimitedInstance},
		{"instance not allowed", http.MethodPost, validBody, func(f *fixture) {
			f.verifier.err = fmt.Errorf("%w: x", novalookup.ErrInstanceMismatch)
		}, http.StatusForbidden, metrics.ReasonInstanceNotAllowed},
		{"lookup unavailable", http.MethodPost, validBody, func(f *fixture) {
			f.verifier.err = fmt.Errorf("%w: x", novalookup.ErrLookupUnavailable)
		}, http.StatusServiceUnavailable, metrics.ReasonLookupUnavailable},
		{"enrichment invalid", http.MethodPost, validBody, func(f *fixture) {
			f.verifier.err = fmt.Errorf("%w: %w: x", novalookup.ErrLookupUnavailable, novalookup.ErrEnrichmentInvalid)
		}, http.StatusServiceUnavailable, metrics.ReasonEnrichmentInvalid},
		{"key store", http.MethodPost, validBody, func(f *fixture) {
			f.minter.err = fmt.Errorf("%w: x", token.ErrKeyStoreUnavailable)
		}, http.StatusServiceUnavailable, metrics.ReasonKeyStoreUnavailable},
		{"claims invalid", http.MethodPost, validBody, func(f *fixture) {
			f.minter.err = fmt.Errorf("%w: x", claims.ErrInvalidRequest)
		}, http.StatusBadRequest, metrics.ReasonInvalidRequest},
		{"signing failed", http.MethodPost, validBody, func(f *fixture) {
			f.minter.err = fmt.Errorf("%w: x", iid.ErrInvalidCustomClaim)
		}, http.StatusInternalServerError, metrics.ReasonSigningFailed},
		{"token too large", http.MethodPost, validBody, func(f *fixture) {
			f.minter.err = fmt.Errorf("%w: x", token.ErrTokenTooLarge)
		}, http.StatusInternalServerError, metrics.ReasonSigningFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, r := metricstest.New(t, metrics.Config{})
			f := newFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			h := m.AttestMiddleware(f.handler)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, "/attest", strings.NewReader(tt.body)))
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if got := r.Value(t, "openstack_spire.attest.requests", "reason", tt.reason, "http.response.status_code", strconv.Itoa(tt.status)); got != 1 {
				t.Errorf("no %s with status %d: %v", tt.reason, tt.status, r.Points(t, "openstack_spire.attest.requests"))
			}
		})
	}
}

func TestIssuedTokenMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{ProjectAttribute: true, MaxProjects: 10})
	f := newFixture(t)
	h, err := NewHandler(f.limiter, f.verifier, f.minter, 4096, WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	f.handler = h
	if w := f.do(http.MethodPost, validBody); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got := r.Value(t, "openstack_spire.tokens.issued", "project_id", projectID); got != 1 {
		t.Errorf("%d tokens counted for the project, want 1", got)
	}
	if got := r.Value(t, "openstack_spire.token.size"); got != 1 {
		t.Errorf("%d token sizes recorded, want 1", got)
	}
}
