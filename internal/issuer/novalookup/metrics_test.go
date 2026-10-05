package novalookup

import (
	"context"
	"errors"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const lookups = "openstack_spire.verification.lookups"

func TestLookupMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithMetrics(m), WithEnrichment([]string{iid.ClaimProjectName}))
	ctx := context.Background()

	if _, err := v.Verify(ctx, projectID, instanceID); err != nil { // both looked up
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, projectID, instanceID); err != nil { // both cached
		t.Fatal(err)
	}
	_, _ = v.Verify(ctx, projectID, "9d8e7f6a-1b2c-4d3e-8f9a-0b1c2d3e4f5a") // unknown instance
	b.serverErr = errors.New("connection refused")
	_, _ = v.Verify(ctx, projectID, "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d") // Nova failing

	for _, tt := range []struct {
		attrs []string
		want  int64
	}{
		{[]string{"kind", metrics.LookupServer, "result", metrics.ResultFound, "source", "backend"}, 1},
		{[]string{"kind", metrics.LookupServer, "result", metrics.ResultFound, "source", "cache"}, 1},
		{[]string{"kind", metrics.LookupServer, "result", metrics.ResultNotFound}, 1},
		{[]string{"kind", metrics.LookupServer, "result", metrics.ResultError}, 1},
		{[]string{"kind", metrics.LookupProject, "result", metrics.ResultFound, "source", "backend"}, 1},
		{[]string{"kind", metrics.LookupProject, "source", "cache"}, 3},
	} {
		if got := r.Value(t, lookups, tt.attrs...); got != tt.want {
			t.Errorf("%v: %d, want %d", tt.attrs, got, tt.want)
		}
	}
	// calls actually made: 3 server lookups (one per uncached instance), 1 project lookup
	if got := r.Value(t, "openstack_spire.verification.lookup.duration", "kind", metrics.LookupServer); got != 3 {
		t.Errorf("%d Nova calls recorded, want 3", got)
	}
	if got := r.Value(t, "openstack_spire.verification.lookup.duration", "kind", metrics.LookupProject); got != 1 {
		t.Errorf("%d Keystone calls recorded, want 1", got)
	}
}
