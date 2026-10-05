package server

import (
	"context"
	"errors"
	"net/url"

	"github.com/dihedron/openstack-spiffe/internal/issuer/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/issuer/health"
	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ratelimit"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// The components describe their state with their own statistics (the
// shared ones never import OpenTelemetry); the functions below hand them to
// the metrics, which read them when they are collected.

// Option configures a signer.
type Option func(*signerOptions)

type signerOptions struct {
	auditStats func() (syslog.AuditStats, bool)
}

// WithAuditSink reports the syslog audit sink's delivery in the metrics:
// stats returns its statistics, and false while it is disabled.
func WithAuditSink(stats func() (syslog.AuditStats, bool)) Option {
	return func(o *signerOptions) { o.auditStats = stats }
}

// observeKeys reports a signer's keys and its local key set.
func observeKeys(m *metrics.Metrics, keys *keystore.Ephemeral) error {
	return errors.Join(
		m.ObserveKeys(func() metrics.KeyState {
			s := keys.Stats()
			return metrics.KeyState{Published: s.Published, Active: s.Active, Retired: s.Retired, ActiveSince: s.ActiveSince, Rotations: s.Rotations}
		}),
		m.ObserveKeySet(metrics.KeySetLocal, keyCount(keys)),
	)
}

// observeFetches reports the fetches of an aggregator (a signer's peers, or
// an aggregator's replicas) and the merged key set it serves.
func observeFetches(m *metrics.Metrics, a *aggregator.Aggregator) error {
	return errors.Join(
		m.ObserveFetches(func() []metrics.PeerFetches {
			var fetches []metrics.PeerFetches
			for _, s := range a.Stats() {
				fetches = append(fetches, metrics.PeerFetches{
					Peer: peerName(s.URL), OK: s.OK, Error: s.Error, Invalid: s.Invalid,
					LastSuccess: s.LastSuccess, Conflicts: s.Conflicts,
				})
			}
			return fetches
		}),
		m.ObserveKeySet(metrics.KeySetMerged, keyCount(a)),
	)
}

// peerName is the peer attribute of a replica URL: its host, from the
// configuration, so the attribute's values are bounded.
func peerName(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func keyCount(source jwks.KeySource) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		keys, err := source.PublicKeys(ctx)
		return len(keys), err
	}
}

// observeLimiter reports a rate limiter under its configuration key.
func observeLimiter(m *metrics.Metrics, name string, l *ratelimit.Limiter) error {
	return m.ObserveLimiter(name, func() metrics.LimiterState {
		s := l.Stats()
		return metrics.LimiterState{Rejections: s.Rejections, Tracked: s.Tracked}
	})
}

// observeReadiness reports the readiness checks.
func observeReadiness(m *metrics.Metrics, r *health.Readiness) error {
	return m.ObserveReadiness(r.Results)
}

// observeAuditSink reports the syslog audit sink, if any.
func observeAuditSink(m *metrics.Metrics, stats func() (syslog.AuditStats, bool)) error {
	if stats == nil {
		return nil
	}
	if _, enabled := stats(); !enabled {
		return nil
	}
	return m.ObserveSyslog(func() metrics.SyslogState {
		s, _ := stats()
		return metrics.SyslogState{Dropped: s.Dropped, Queued: s.Queued}
	})
}
