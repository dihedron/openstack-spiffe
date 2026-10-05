package metrics_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
)

func TestObservations(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	activeSince := time.Now().Add(-90 * time.Second)
	lastFetch := time.Now().Add(-20 * time.Second)
	for _, err := range []error{
		m.ObserveKeys(func() metrics.KeyState {
			return metrics.KeyState{Published: 1, Active: 1, Retired: 2, ActiveSince: activeSince, Rotations: 3}
		}),
		m.ObserveFetches(func() []metrics.PeerFetches {
			return []metrics.PeerFetches{
				{Peer: "signer-b.internal:8443", OK: 5, Error: 2, LastSuccess: lastFetch, Conflicts: 1},
				{Peer: "signer-c.internal:8443", Invalid: 4}, // never fetched
			}
		}),
		m.ObserveKeySet(metrics.KeySetLocal, func(context.Context) (int, error) { return 3, nil }),
		m.ObserveKeySet(metrics.KeySetMerged, func(context.Context) (int, error) { return 0, errors.New("unavailable") }),
		m.ObserveLimiter(metrics.LimiterSource, func() metrics.LimiterState { return metrics.LimiterState{Rejections: 7, Tracked: 4} }),
		m.ObserveLimiter(metrics.LimiterInstance, func() metrics.LimiterState { return metrics.LimiterState{Tracked: 9} }),
		m.ObserveSyslog(func() metrics.SyslogState { return metrics.SyslogState{Dropped: 6, Queued: 2} }),
		m.ObserveReadiness(func() map[string]bool { return map[string]bool{"keystone": true, "nova": false} }),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		name  string
		attrs []string
		want  int64
	}{
		{"openstack_spire.keys", []string{"state", "published"}, 1},
		{"openstack_spire.keys", []string{"state", "retired"}, 2},
		{"openstack_spire.key.rotations", nil, 3},
		{"openstack_spire.jwks.fetches", []string{"peer", "signer-b.internal:8443", "result", "ok"}, 5},
		{"openstack_spire.jwks.fetches", []string{"peer", "signer-b.internal:8443", "result", "error"}, 2},
		{"openstack_spire.jwks.fetches", []string{"peer", "signer-c.internal:8443", "result", "invalid"}, 4},
		{"openstack_spire.jwks.conflicts", []string{"peer", "signer-b.internal:8443"}, 1},
		{"openstack_spire.jwks.keys", []string{"set", "local"}, 3},
		{"openstack_spire.rate_limit.rejections", []string{"limiter", "source"}, 7},
		{"openstack_spire.rate_limit.tracked", []string{"limiter", "instance"}, 9},
		{"openstack_spire.audit.syslog.dropped", nil, 6},
		{"openstack_spire.audit.syslog.queue", nil, 2},
		{"openstack_spire.readiness.check", []string{"check", "keystone"}, 1},
		{"openstack_spire.readiness.check", []string{"check", "nova"}, 0},
	} {
		if got := r.Value(t, tt.name, tt.attrs...); got != tt.want {
			t.Errorf("%s %v: %d, want %d", tt.name, tt.attrs, got, tt.want)
		}
	}
	if age := r.Value(t, "openstack_spire.key.active.age"); age < 90 || age > 100 {
		t.Errorf("active key age %ds, want about 90", age)
	}
	ages := r.Points(t, "openstack_spire.jwks.fetch.age")
	if len(ages) != 1 || ages[0].Attributes["peer"] != "signer-b.internal:8443" || ages[0].Value < 20 {
		t.Errorf("fetch ages %v, want only signer-b's, about 20s", ages)
	}
	for _, p := range r.Points(t, "openstack_spire.jwks.keys") {
		if p.Attributes["set"] == metrics.KeySetMerged {
			t.Error("a key set reported while it cannot be read")
		}
	}
}

func TestObservationsDisabled(t *testing.T) {
	var m *metrics.Metrics
	if err := m.ObserveKeys(func() metrics.KeyState { t.Error("read while disabled"); return metrics.KeyState{} }); err != nil {
		t.Error(err)
	}
	if err := m.ObserveReadiness(nil); err != nil {
		t.Error(err)
	}
}
