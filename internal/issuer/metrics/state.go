package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// The state metrics are read from the components when the metrics are
// collected (observable instruments): nothing is recorded on the request
// path. The components describe their state with the plain structs below,
// so that those shared with the SPIRE server plugin (key store, aggregator,
// syslog sink) never import OpenTelemetry; the server converts.

// KeyState describes a signer's keys.
type KeyState struct {
	Published, Active, Retired int
	// ActiveSince is when the active key became active (zero if none).
	ActiveSince time.Time
	// Rotations counts the keys generated after the first.
	Rotations uint64
}

// PeerFetches describes the fetches of one peer (a signer's peer replica,
// or an aggregator's replica).
type PeerFetches struct {
	// Peer identifies it: the host of its URL.
	Peer string
	// OK, Error and Invalid count the fetches by outcome.
	OK, Error, Invalid uint64
	// LastSuccess is the time of the last successful fetch (zero if none).
	LastSuccess time.Time
	// Conflicts counts the kids currently excluded because of it.
	Conflicts int
}

// LimiterState describes a rate limiter.
type LimiterState struct {
	Rejections uint64
	Tracked    int
}

// SyslogState describes the syslog audit sink.
type SyslogState struct {
	Dropped uint64
	Queued  int
}

// Limiter names, after their configuration keys.
const (
	LimiterSource       = "source"
	LimiterSourcePublic = "source_public"
	LimiterInstance     = "instance"
	LimiterMetrics      = "metrics"
)

// Key sets.
const (
	KeySetLocal  = "local"
	KeySetMerged = "merged"
)

// state holds the observable instruments.
type state struct {
	meter            metric.Meter
	keys             metric.Int64ObservableGauge
	activeAge        metric.Float64ObservableGauge
	rotations        metric.Int64ObservableCounter
	fetches          metric.Int64ObservableCounter
	fetchAge         metric.Float64ObservableGauge
	conflicts        metric.Int64ObservableGauge
	keySet           metric.Int64ObservableGauge
	limiterRejected  metric.Int64ObservableCounter
	limiterTracked   metric.Int64ObservableGauge
	syslogDropped    metric.Int64ObservableCounter
	syslogQueued     metric.Int64ObservableGauge
	readinessChecked metric.Int64ObservableGauge
}

func (s *state) instrument(meter metric.Meter) error {
	s.meter = meter
	var errs []error
	gauge := func(name, unit, description string) metric.Int64ObservableGauge {
		g, err := meter.Int64ObservableGauge(name, metric.WithUnit(unit), metric.WithDescription(description))
		errs = append(errs, err)
		return g
	}
	counter := func(name, unit, description string) metric.Int64ObservableCounter {
		c, err := meter.Int64ObservableCounter(name, metric.WithUnit(unit), metric.WithDescription(description))
		errs = append(errs, err)
		return c
	}
	seconds := func(name, description string) metric.Float64ObservableGauge {
		g, err := meter.Float64ObservableGauge(name, metric.WithUnit("s"), metric.WithDescription(description))
		errs = append(errs, err)
		return g
	}
	s.keys = gauge("openstack_spire.keys", "{key}", "Keys of this replica, by lifecycle state.")
	s.activeAge = seconds("openstack_spire.key.active.age", "Age of the active key.")
	s.rotations = counter("openstack_spire.key.rotations", "{rotation}", "Completed key rotations.")
	s.fetches = counter("openstack_spire.jwks.fetches", "{fetch}", "JWK Set fetches of each peer or replica, by result.")
	s.fetchAge = seconds("openstack_spire.jwks.fetch.age", "Time since the last successful fetch of each peer or replica.")
	s.conflicts = gauge("openstack_spire.jwks.conflicts", "{key}", "Kids currently excluded because of each peer or replica.")
	s.keySet = gauge("openstack_spire.jwks.keys", "{key}", "Keys served, by set.")
	s.limiterRejected = counter("openstack_spire.rate_limit.rejections", "{request}", "Requests refused by each rate limiter.")
	s.limiterTracked = gauge("openstack_spire.rate_limit.tracked", "{bucket}", "Buckets held by each rate limiter.")
	s.syslogDropped = counter("openstack_spire.audit.syslog.dropped", "{record}", "Audit records the syslog sink dropped.")
	s.syslogQueued = gauge("openstack_spire.audit.syslog.queue", "{record}", "Audit records waiting to be sent to syslog.")
	// no unit: with "1", the Prometheus exporter would name it a ratio
	s.readinessChecked = gauge("openstack_spire.readiness.check", "", "1 when the readiness check passes, 0 when it fails.")
	for _, err := range errs {
		if err != nil {
			return fmt.Errorf("creating the state instruments: %w", err)
		}
	}
	return nil
}

// observe registers a callback reading state at collection time.
func (m *Metrics) observe(callback metric.Callback, instruments ...metric.Observable) error {
	if m == nil || m.state == nil {
		return nil
	}
	if _, err := m.state.meter.RegisterCallback(callback, instruments...); err != nil {
		return fmt.Errorf("registering a metrics callback: %w", err)
	}
	return nil
}

// ObserveKeys reports a signer's keys from read.
func (m *Metrics) ObserveKeys(read func() KeyState) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(_ context.Context, o metric.Observer) error {
		k := read()
		for state, n := range map[string]int{"published": k.Published, "active": k.Active, "retired": k.Retired} {
			o.ObserveInt64(s.keys, int64(n), metric.WithAttributes(attribute.String("state", state)))
		}
		if !k.ActiveSince.IsZero() {
			o.ObserveFloat64(s.activeAge, time.Since(k.ActiveSince).Seconds())
		}
		o.ObserveInt64(s.rotations, int64(k.Rotations))
		return nil
	}, s.keys, s.activeAge, s.rotations)
}

// ObserveFetches reports the fetches of the peers or replicas from read.
func (m *Metrics) ObserveFetches(read func() []PeerFetches) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(_ context.Context, o metric.Observer) error {
		for _, p := range read() {
			peer := attribute.String("peer", p.Peer)
			for result, n := range map[string]uint64{ResultOK: p.OK, ResultError: p.Error, "invalid": p.Invalid} {
				o.ObserveInt64(s.fetches, int64(n), metric.WithAttributes(peer, attribute.String("result", result)))
			}
			if !p.LastSuccess.IsZero() {
				o.ObserveFloat64(s.fetchAge, time.Since(p.LastSuccess).Seconds(), metric.WithAttributes(peer))
			}
			o.ObserveInt64(s.conflicts, int64(p.Conflicts), metric.WithAttributes(peer))
		}
		return nil
	}, s.fetches, s.fetchAge, s.conflicts)
}

// ObserveKeySet reports the number of keys of a set (KeySetLocal,
// KeySetMerged) from count.
func (m *Metrics) ObserveKeySet(set string, count func(context.Context) (int, error)) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(ctx context.Context, o metric.Observer) error {
		n, err := count(ctx)
		if err != nil {
			return nil // reported by the readiness checks, not here
		}
		o.ObserveInt64(s.keySet, int64(n), metric.WithAttributes(attribute.String("set", set)))
		return nil
	}, s.keySet)
}

// ObserveLimiter reports a rate limiter, named after its configuration key
// (LimiterSource, ...), from read.
func (m *Metrics) ObserveLimiter(name string, read func() LimiterState) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(_ context.Context, o metric.Observer) error {
		l := read()
		attrs := metric.WithAttributes(attribute.String("limiter", name))
		o.ObserveInt64(s.limiterRejected, int64(l.Rejections), attrs)
		o.ObserveInt64(s.limiterTracked, int64(l.Tracked), attrs)
		return nil
	}, s.limiterRejected, s.limiterTracked)
}

// ObserveSyslog reports the syslog audit sink from read.
func (m *Metrics) ObserveSyslog(read func() SyslogState) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(_ context.Context, o metric.Observer) error {
		st := read()
		o.ObserveInt64(s.syslogDropped, int64(st.Dropped))
		o.ObserveInt64(s.syslogQueued, int64(st.Queued))
		return nil
	}, s.syslogDropped, s.syslogQueued)
}

// ObserveReadiness reports the readiness checks from read: whether each
// passed in its latest run (checks not run yet are absent).
func (m *Metrics) ObserveReadiness(read func() map[string]bool) error {
	if m == nil || m.state == nil {
		return nil
	}
	s := m.state
	return m.observe(func(_ context.Context, o metric.Observer) error {
		for check, ok := range read() {
			v := int64(0)
			if ok {
				v = 1
			}
			o.ObserveInt64(s.readinessChecked, v, metric.WithAttributes(attribute.String("check", check)))
		}
		return nil
	}, s.readinessChecked)
}
