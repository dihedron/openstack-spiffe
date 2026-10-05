package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
)

// attest sends one request through AttestMiddleware, to a handler that
// names reason (if any) and answers with status.
func attest(m *metrics.Metrics, reason string, status int) {
	h := m.AttestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason != "" {
			metrics.Reject(r.Context(), reason)
		}
		w.WriteHeader(status)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/attest", nil))
}

func TestAttestOutcomes(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	attest(m, "", http.StatusOK)
	attest(m, metrics.ReasonSourceNotAllowed, http.StatusForbidden)
	attest(m, metrics.ReasonSourceNotAllowed, http.StatusForbidden)
	attest(m, metrics.ReasonRateLimitedInstance, http.StatusTooManyRequests)
	attest(m, "", http.StatusInternalServerError) // a path that named no reason

	const name = "openstack_spire.attest.requests"
	for _, tt := range []struct {
		attrs []string
		want  int64
	}{
		{[]string{"outcome", "issued", "reason", metrics.ReasonNone, "http.response.status_code", "200"}, 1},
		{[]string{"outcome", "rejected", "reason", metrics.ReasonSourceNotAllowed, "http.response.status_code", "403"}, 2},
		{[]string{"reason", metrics.ReasonRateLimitedInstance, "http.response.status_code", "429"}, 1},
		{[]string{"reason", metrics.ReasonUnspecified, "http.response.status_code", "500"}, 1},
	} {
		if got := r.Value(t, name, tt.attrs...); got != tt.want {
			t.Errorf("%v: %d, want %d", tt.attrs, got, tt.want)
		}
	}
	if got := r.Value(t, "openstack_spire.attest.duration", "outcome", "rejected"); got != 4 {
		t.Errorf("%d rejected durations, want 4", got)
	}
}

func TestRejectFirstReasonWins(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	h := m.AttestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		metrics.Reject(req.Context(), metrics.ReasonUnauthenticated)
		metrics.Reject(req.Context(), metrics.ReasonSigningFailed)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/attest", nil))
	if r.Value(t, "openstack_spire.attest.requests", "reason", metrics.ReasonUnauthenticated) != 1 {
		t.Error("the first reason named was not recorded")
	}
}

func TestRejectWithoutWrapper(t *testing.T) {
	metrics.Reject(context.Background(), metrics.ReasonRateLimitedSource) // must not panic
}

func TestTokenIssued(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	m.TokenIssued(context.Background(), "ES256", "p1", 900)
	if r.Value(t, "openstack_spire.tokens.issued", "algorithm", "ES256") != 1 {
		t.Error("issued token not counted")
	}
	for _, p := range r.Points(t, "openstack_spire.tokens.issued") {
		if _, ok := p.Attributes["project_id"]; ok {
			t.Errorf("project_id recorded while project_attribute is off: %v", p.Attributes)
		}
	}
	if r.Value(t, "openstack_spire.token.size") != 1 {
		t.Error("token size not recorded")
	}
}

func TestProjectCap(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{ProjectAttribute: true, MaxProjects: 2})
	for _, project := range []string{"p1", "p2", "p1", "p3", "p4", "p2"} {
		m.TokenIssued(context.Background(), "RS256", project, 1000)
	}
	for project, want := range map[string]int64{"p1": 2, "p2": 2, metrics.OtherProject: 2, "p3": 0} {
		if got := r.Value(t, "openstack_spire.tokens.issued", "project_id", project); got != want {
			t.Errorf("project %s: %d tokens, want %d", project, got, want)
		}
	}
}

func TestDependencies(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	ctx := context.Background()
	m.KeystoneValidation(ctx, metrics.ResultValid, "cache")
	m.KeystoneValidation(ctx, metrics.ResultBusy, "backend")
	m.KeystoneCall(ctx, metrics.ResultValid, 20*time.Millisecond)
	m.KeystoneInFlight(ctx, 1)
	m.KeystoneInFlight(ctx, -1)
	m.Lookup(ctx, metrics.LookupServer, metrics.ResultFound, "merged")
	m.LookupCall(ctx, metrics.LookupProject, metrics.ResultError, time.Second)
	m.Signing(ctx, "ES256", metrics.ResultOK, time.Millisecond)
	m.TagDropped(ctx, "not_allowed")
	for _, tt := range []struct {
		name  string
		attrs []string
		want  int64
	}{
		{"openstack_spire.keystone.validations", []string{"result", "valid", "source", "cache"}, 1},
		{"openstack_spire.keystone.validations", []string{"result", "busy"}, 1},
		{"openstack_spire.keystone.validation.duration", []string{"result", "valid"}, 1},
		{"openstack_spire.keystone.validations.in_flight", nil, 0},
		{"openstack_spire.verification.lookups", []string{"kind", "server", "result", "found", "source", "merged"}, 1},
		{"openstack_spire.verification.lookup.duration", []string{"kind", "project", "result", "error"}, 1},
		{"openstack_spire.signing.duration", []string{"algorithm", "ES256", "result", "ok"}, 1},
		{"openstack_spire.tags.dropped", []string{"reason", "not_allowed"}, 1},
	} {
		if got := r.Value(t, tt.name, tt.attrs...); got != tt.want {
			t.Errorf("%s %v: %d, want %d", tt.name, tt.attrs, got, tt.want)
		}
	}
}

func TestIssuanceDisabled(t *testing.T) {
	for name, m := range map[string]*metrics.Metrics{"nil": nil} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			attest(m, metrics.ReasonSigningFailed, http.StatusInternalServerError)
			m.TokenIssued(ctx, "ES256", "p", 1)
			m.TagDropped(ctx, "x")
			m.KeystoneValidation(ctx, "x", "y")
			m.KeystoneCall(ctx, "x", time.Second)
			m.KeystoneInFlight(ctx, 1)
			m.Lookup(ctx, "x", "y", "z")
			m.LookupCall(ctx, "x", "y", time.Second)
			m.Signing(ctx, "x", "y", time.Second)
		})
	}
	disabled, err := metrics.New(context.Background(), metrics.Config{}, metrics.Resource{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	attest(disabled, metrics.ReasonSigningFailed, http.StatusInternalServerError)
	disabled.TokenIssued(context.Background(), "ES256", "p", 1)
}
