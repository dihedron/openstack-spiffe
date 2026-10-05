package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Reasons of the /attest outcomes: one per row of the issuer spec's failure
// table, ReasonNone for issued tokens.
const (
	ReasonNone                = "none"
	ReasonSourceNotAllowed    = "source_not_allowed"
	ReasonClientCertificate   = "client_certificate"
	ReasonRateLimitedSource   = "rate_limited_source"
	ReasonRateLimitedInstance = "rate_limited_instance"
	ReasonInvalidRequest      = "invalid_request"
	ReasonUnauthenticated     = "unauthenticated"
	ReasonCallerNotAllowed    = "caller_not_allowed"
	ReasonKeystoneBusy        = "keystone_busy"
	ReasonKeystoneUnavailable = "keystone_unavailable"
	ReasonInstanceNotAllowed  = "instance_not_allowed"
	ReasonLookupUnavailable   = "lookup_unavailable"
	ReasonEnrichmentInvalid   = "enrichment_invalid"
	ReasonKeyStoreUnavailable = "key_store_unavailable"
	ReasonSigningFailed       = "signing_failed"
	// ReasonUnspecified marks a rejection whose path named no reason: a bug,
	// which the tests catch.
	ReasonUnspecified = "unspecified"
)

// Results of the Keystone validations, the verification lookups and the
// signing operations.
const (
	ResultValid      = "valid"
	ResultInvalid    = "invalid"
	ResultNotAllowed = "not_allowed"
	ResultBusy       = "busy"
	ResultFound      = "found"
	ResultNotFound   = "not_found"
	ResultOK         = "ok"
	ResultError      = "error"
)

// Kinds of verification lookups.
const (
	LookupServer  = "server"  // the Nova server record
	LookupProject = "project" // the Keystone project record
)

// OtherProject is the project_id of the tokens of the projects beyond
// max_projects.
const OtherProject = "other"

// signingBuckets are the bucket boundaries, in seconds, of the signing
// durations: 100µs to 1s.
var signingBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1}

// tokenSizeBuckets are the bucket boundaries, in bytes, of the token sizes,
// up to iid.MaxTokenBytes.
var tokenSizeBuckets = []float64{512, 1024, 2048, 4096, 8192, 16384}

// issuance holds the instruments of token issuance and of its dependencies.
type issuance struct {
	attestRequests       metric.Int64Counter
	attestDuration       metric.Float64Histogram
	tokensIssued         metric.Int64Counter
	tokenSize            metric.Int64Histogram
	tagsDropped          metric.Int64Counter
	keystoneValidations  metric.Int64Counter
	keystoneDuration     metric.Float64Histogram
	keystoneInFlight     metric.Int64UpDownCounter
	lookups              metric.Int64Counter
	lookupDuration       metric.Float64Histogram
	signingDuration      metric.Float64Histogram
	projectAttribute     bool
	maxProjects          int
	projectsMu           sync.Mutex
	projects             map[string]struct{}
	projectsCapAnnounced bool
}

func (i *issuance) instrument(meter metric.Meter) error {
	var errs []error
	counter := func(name, unit, description string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithUnit(unit), metric.WithDescription(description))
		errs = append(errs, err)
		return c
	}
	histogram := func(name, unit, description string, buckets []float64) metric.Float64Histogram {
		h, err := meter.Float64Histogram(name, metric.WithUnit(unit), metric.WithDescription(description), metric.WithExplicitBucketBoundaries(buckets...))
		errs = append(errs, err)
		return h
	}
	i.attestRequests = counter("openstack_spire.attest.requests", "{request}", "Calls to /attest, by outcome, reason and status.")
	i.attestDuration = histogram("openstack_spire.attest.duration", "s", "Duration of the calls to /attest, rejections included.", durationBuckets)
	i.tokensIssued = counter("openstack_spire.tokens.issued", "{token}", "Tokens issued.")
	i.tagsDropped = counter("openstack_spire.tags.dropped", "{tag}", "Instance metadata entries left out of the tags claim, by reason.")
	i.keystoneValidations = counter("openstack_spire.keystone.validations", "{validation}", "Validations of caller tokens, by result and by how they were answered.")
	i.keystoneDuration = histogram("openstack_spire.keystone.validation.duration", "s", "Duration of the validations actually sent to Keystone.", durationBuckets)
	i.lookups = counter("openstack_spire.verification.lookups", "{lookup}", "Instance verification lookups, by kind, result and how they were answered.")
	i.lookupDuration = histogram("openstack_spire.verification.lookup.duration", "s", "Duration of the lookups actually sent to Nova or Keystone.", durationBuckets)
	i.signingDuration = histogram("openstack_spire.signing.duration", "s", "Duration of the signing operations.", signingBuckets)
	var err error
	i.tokenSize, err = meter.Int64Histogram("openstack_spire.token.size", metric.WithUnit("By"),
		metric.WithDescription("Size of the serialized tokens issued."), metric.WithExplicitBucketBoundaries(tokenSizeBuckets...))
	errs = append(errs, err)
	i.keystoneInFlight, err = meter.Int64UpDownCounter("openstack_spire.keystone.validations.in_flight", metric.WithUnit("{validation}"),
		metric.WithDescription("Validations in flight against Keystone, against keystone.max_concurrent_validations."))
	errs = append(errs, err)
	for _, err := range errs {
		if err != nil {
			return fmt.Errorf("creating the issuance instruments: %w", err)
		}
	}
	return nil
}

// outcome is the reason a request to /attest was answered with, named by
// the layer that answered it.
type outcome struct {
	mu     sync.Mutex
	reason string
}

type outcomeKey struct{}

// Reject names the reason a request to /attest is being refused with. Each
// layer (guard, rate limits, authentication, handler) calls it just before
// it answers; without the /attest wrapper (AttestMiddleware) it does nothing.
// The first reason named wins.
func Reject(ctx context.Context, reason string) {
	o, ok := ctx.Value(outcomeKey{}).(*outcome)
	if !ok {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.reason == "" {
		o.reason = reason
	}
}

// AttestMiddleware records every request to /attest: its outcome, the reason
// named by Reject (ReasonUnspecified if none) and its duration.
func (m *Metrics) AttestMiddleware(next http.Handler) http.Handler {
	if m == nil || m.issuance == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		o := &outcome{}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), outcomeKey{}, o)))

		result, reason := "issued", ReasonNone
		if sw.status != http.StatusOK {
			result = "rejected"
			o.mu.Lock()
			reason = o.reason
			o.mu.Unlock()
			if reason == "" {
				reason = ReasonUnspecified
				slog.ErrorContext(r.Context(), "an /attest rejection named no reason: please report it", "status", sw.status)
			}
		}
		ctx := r.Context()
		m.issuance.attestRequests.Add(ctx, 1, metric.WithAttributes(
			attribute.String("outcome", result),
			attribute.String("reason", reason),
			attribute.Int("http.response.status_code", sw.status)))
		m.issuance.attestDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.String("outcome", result)))
	})
}

// TokenIssued records an issued token: its algorithm, its size and, when
// project_attribute is on, its project (up to max_projects distinct
// projects, then OtherProject).
func (m *Metrics) TokenIssued(ctx context.Context, algorithm, projectID string, size int) {
	if m == nil || m.issuance == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("algorithm", algorithm)}
	if m.issuance.projectAttribute {
		attrs = append(attrs, attribute.String("project_id", m.issuance.project(ctx, projectID)))
	}
	m.issuance.tokensIssued.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.issuance.tokenSize.Record(ctx, int64(size))
}

// project returns the project_id attribute of a token: the project itself
// while fewer than max_projects distinct projects have been seen, else
// OtherProject (announced once).
func (i *issuance) project(ctx context.Context, projectID string) string {
	i.projectsMu.Lock()
	defer i.projectsMu.Unlock()
	if _, ok := i.projects[projectID]; ok {
		return projectID
	}
	if len(i.projects) < i.maxProjects {
		i.projects[projectID] = struct{}{}
		return projectID
	}
	if !i.projectsCapAnnounced {
		i.projectsCapAnnounced = true
		slog.WarnContext(ctx, "metrics: max_projects reached, further projects are counted as \"other\"", "max_projects", i.maxProjects)
	}
	return OtherProject
}

// TagDropped records an instance metadata entry left out of the tags claim.
func (m *Metrics) TagDropped(ctx context.Context, reason string) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.tagsDropped.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// KeystoneValidation records a caller token validation: its result and its
// source (cache, merged or backend).
func (m *Metrics) KeystoneValidation(ctx context.Context, result, source string) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.keystoneValidations.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result), attribute.String("source", source)))
}

// KeystoneCall records a validation actually sent to Keystone.
func (m *Metrics) KeystoneCall(ctx context.Context, result string, elapsed time.Duration) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.keystoneDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attribute.String("result", result)))
}

// KeystoneInFlight adds delta to the validations in flight.
func (m *Metrics) KeystoneInFlight(ctx context.Context, delta int64) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.keystoneInFlight.Add(ctx, delta)
}

// Lookup records a verification lookup of a kind (LookupServer,
// LookupProject): its result and its source (cache, merged or backend).
func (m *Metrics) Lookup(ctx context.Context, kind, result, source string) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.lookups.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", kind), attribute.String("result", result), attribute.String("source", source)))
}

// LookupCall records a lookup actually sent to Nova or Keystone.
func (m *Metrics) LookupCall(ctx context.Context, kind, result string, elapsed time.Duration) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.lookupDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attribute.String("kind", kind), attribute.String("result", result)))
}

// Signing records a signing operation.
func (m *Metrics) Signing(ctx context.Context, algorithm, result string, elapsed time.Duration) {
	if m == nil || m.issuance == nil {
		return
	}
	m.issuance.signingDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attribute.String("algorithm", algorithm), attribute.String("result", result)))
}
