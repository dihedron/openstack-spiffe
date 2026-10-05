package token

import (
	"context"
	"errors"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
)

func TestSigningMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	ks := newFakeStore()
	ks.add(t, "k1", "ES256")
	ks.active = "k1"
	mi, err := NewMinter(ks, newBuilder(t), WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := mi.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if err != nil || issued.Algorithm != "ES256" {
		t.Fatalf("Mint: %+v, %v", issued, err)
	}
	ks.signErr = errors.New("hsm down")
	_, _ = mi.Mint(context.Background(), validRequest(), claims.Enrichment{})

	const name = "openstack_spire.signing.duration"
	if got := r.Value(t, name, "algorithm", "ES256", "result", metrics.ResultOK); got != 1 {
		t.Errorf("%d successful signatures recorded, want 1", got)
	}
	if got := r.Value(t, name, "algorithm", "ES256", "result", metrics.ResultError); got != 1 {
		t.Errorf("%d failed signatures recorded, want 1", got)
	}
}

func TestTagsDroppedMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	b := newBuilder(t, claims.WithAllowlist([]string{"role", "count"}), claims.WithMetrics(m))
	req := validRequest()
	req.Metadata = map[string]any{"role": "web", "env": "prod", "count": 3.0, "bad:key": "x"}
	if _, err := b.Build(context.Background(), req, claims.Enrichment{}); err != nil {
		t.Fatal(err)
	}
	for reason, want := range map[string]int64{"not_allowed": 1, "not_string": 1, "invalid_key": 1} {
		if got := r.Value(t, "openstack_spire.tags.dropped", "reason", reason); got != want {
			t.Errorf("%s: %d, want %d", reason, got, want)
		}
	}
}
