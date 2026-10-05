// Package novalookup independently verifies the instance a Nova vendordata
// request is about, against the Nova API, and looks up the optional
// enrichment claims from Nova and Keystone. Records are cached to protect
// nova-api and Keystone during boot storms.
package novalookup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ttlcache"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

var (
	// ErrInstanceMismatch is returned (wrapped) when the instance does not
	// exist, belongs to another project or is in a disallowed status, or the
	// project does not exist (403).
	ErrInstanceMismatch = errors.New("instance does not match the request")
	// ErrLookupUnavailable is returned (wrapped) when Nova or Keystone cannot
	// be reached, or a record lacks an enabled enrichment attribute (503).
	ErrLookupUnavailable = errors.New("instance lookup unavailable")
	// ErrNotFound is returned (wrapped) by a Backend for a record that does
	// not exist.
	ErrNotFound = errors.New("not found")
)

// Server is what the verification and enrichment need from a Nova server
// record.
type Server struct {
	ProjectID        string
	UserID           string
	Status           string
	AvailabilityZone string
	// Flavor is the flavor's original name (compute microversion >= 2.47).
	Flavor string
}

// Project is what the enrichment needs from a Keystone project record.
type Project struct {
	Name     string
	DomainID string
}

// Backend reads records from Nova and Keystone; it returns ErrNotFound
// (wrapped) for records that do not exist.
type Backend interface {
	Server(ctx context.Context, instanceID string) (Server, error)
	Project(ctx context.Context, projectID string) (Project, error)
}

var defaultAllowedStatuses = []string{
	"ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "PASSWORD",
}

// serverEnrichments are the enrichment claims read from the server record.
var serverEnrichments = []string{iid.ClaimAvailabilityZone, iid.ClaimFlavor, iid.ClaimUserID}

// DefaultAllowedStatuses returns the server statuses for which tokens are
// issued by default.
func DefaultAllowedStatuses() []string {
	return slices.Clone(defaultAllowedStatuses)
}

// Verifier verifies instances and looks up enrichment claims. It is safe for
// concurrent use.
type Verifier struct {
	backend    Backend
	verify     bool
	statuses   []string
	enrich     []string
	serverTTL  time.Duration
	projectTTL time.Duration
	maxEntries int
	timeout    time.Duration
	now        func() time.Time

	servers  *ttlcache.Cache[string, Server]
	projects *ttlcache.Cache[string, Project]
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithInstanceVerification turns the verification against Nova on or off
// (default: on).
func WithInstanceVerification(enabled bool) Option {
	return func(v *Verifier) { v.verify = enabled }
}

// WithAllowedStatuses sets the server statuses for which tokens are issued
// (default: DefaultAllowedStatuses).
func WithAllowedStatuses(statuses []string) Option {
	return func(v *Verifier) { v.statuses = slices.Clone(statuses) }
}

// WithEnrichment enables enrichment claims (see iid.EnrichmentClaims;
// default: none). Claims read from the server record require instance
// verification.
func WithEnrichment(names []string) Option {
	return func(v *Verifier) { v.enrich = slices.Clone(names) }
}

// WithServerCacheTTL bounds how long server records are cached; at most the
// maximum token TTL (default: 60s).
func WithServerCacheTTL(d time.Duration) Option {
	return func(v *Verifier) { v.serverTTL = d }
}

// WithProjectCacheTTL bounds how long project records are cached (default:
// 10m).
func WithProjectCacheTTL(d time.Duration) Option {
	return func(v *Verifier) { v.projectTTL = d }
}

// WithMaxCacheEntries bounds each cache (default: 4096 entries).
func WithMaxCacheEntries(n int) Option {
	return func(v *Verifier) { v.maxEntries = n }
}

// WithLookupTimeout bounds each Nova or Keystone lookup (default: 5s).
func WithLookupTimeout(d time.Duration) Option {
	return func(v *Verifier) { v.timeout = d }
}

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) { v.now = now }
}

// NewVerifier creates a Verifier reading records from the backend.
func NewVerifier(backend Backend, options ...Option) (*Verifier, error) {
	if backend == nil {
		return nil, errors.New("creating instance verifier: no backend")
	}
	v := &Verifier{
		backend:    backend,
		verify:     true,
		statuses:   DefaultAllowedStatuses(),
		serverTTL:  time.Minute,
		projectTTL: 10 * time.Minute,
		maxEntries: 4096,
		timeout:    5 * time.Second,
		now:        time.Now,
	}
	for _, option := range options {
		option(v)
	}
	for _, name := range v.enrich {
		switch {
		case !slices.Contains(iid.EnrichmentClaims(), name):
			return nil, fmt.Errorf("creating instance verifier: unknown enrichment claim %q", name)
		case slices.Contains(serverEnrichments, name) && !v.verify:
			return nil, fmt.Errorf("creating instance verifier: enrichment claim %q requires instance verification", name)
		}
	}
	switch {
	case v.verify && len(v.statuses) == 0:
		return nil, errors.New("creating instance verifier: no allowed statuses")
	case v.serverTTL <= 0 || v.serverTTL > iid.TTL:
		return nil, fmt.Errorf("creating instance verifier: server cache TTL %v must be positive and at most %v", v.serverTTL, iid.TTL)
	case v.projectTTL <= 0:
		return nil, fmt.Errorf("creating instance verifier: project cache TTL %v must be positive", v.projectTTL)
	}
	cfg := ttlcache.Config{MaxEntries: v.maxEntries, LoadTimeout: v.timeout, Now: v.now}
	var err error
	if v.servers, err = ttlcache.New[string, Server](cfg); err != nil {
		return nil, fmt.Errorf("creating instance verifier: %w", err)
	}
	if v.projects, err = ttlcache.New[string, Project](cfg); err != nil {
		return nil, fmt.Errorf("creating instance verifier: %w", err)
	}
	return v, nil
}

// Verify checks, if instance verification is enabled, that the instance
// exists, belongs to the project and is in an allowed status, and returns
// the enabled enrichment claims. It fails with ErrInstanceMismatch (403) or
// ErrLookupUnavailable (503), never with partial enrichment.
//
// The Keystone project lookup does not depend on the Nova server record, so
// both run at the same time: the latency is that of the slower lookup, not
// their sum. A failed server check returns at once, without waiting for the
// project lookup, which still completes (and is cached) in the background.
func (v *Verifier) Verify(ctx context.Context, projectID, instanceID string) (claims.Enrichment, error) {
	log := slog.With("project_id", projectID, "instance_id", instanceID)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	projectDone := make(chan struct{})
	var project claims.Enrichment
	var projectErr error
	if slices.Contains(v.enrich, iid.ClaimProjectName) || slices.Contains(v.enrich, iid.ClaimDomainID) {
		go func() {
			defer close(projectDone)
			project, projectErr = v.lookupProject(ctx, log, projectID)
		}()
	} else {
		close(projectDone)
	}

	e, err := v.verifyServer(ctx, log, projectID, instanceID)
	if err != nil {
		return claims.Enrichment{}, err
	}
	<-projectDone
	if projectErr != nil {
		return claims.Enrichment{}, projectErr
	}
	e.ProjectName, e.DomainID = project.ProjectName, project.DomainID
	if err := v.checkEnrichment(ctx, log, e); err != nil {
		return claims.Enrichment{}, err
	}
	return e, nil
}

// checkEnrichment applies iid.ValidateEnrichmentValue to every enabled
// enrichment claim: the SPIRE Server-side plugin rejects a token carrying an
// invalid one, so none is ever issued. The value is not logged, since it may
// hold the very characters the check rejects.
func (v *Verifier) checkEnrichment(ctx context.Context, log *slog.Logger, e claims.Enrichment) error {
	values := map[string]string{
		iid.ClaimAvailabilityZone: e.AvailabilityZone,
		iid.ClaimFlavor:           e.Flavor,
		iid.ClaimUserID:           e.UserID,
		iid.ClaimProjectName:      e.ProjectName,
		iid.ClaimDomainID:         e.DomainID,
	}
	for _, name := range v.enrich {
		if err := iid.ValidateEnrichmentValue(values[name]); err != nil {
			log.ErrorContext(ctx, "invalid enrichment attribute", "claim", name, "error", err)
			return fmt.Errorf("%w: %s: %w", ErrLookupUnavailable, name, err)
		}
	}
	return nil
}

// verifyServer checks the server record, if instance verification is
// enabled, and returns the enrichment claims read from it.
func (v *Verifier) verifyServer(ctx context.Context, log *slog.Logger, projectID, instanceID string) (claims.Enrichment, error) {
	var e claims.Enrichment
	if !v.verify {
		return e, nil
	}
	server, err := v.servers.Get(ctx, instanceID, func(ctx context.Context) (Server, time.Time, error) {
		s, err := v.backend.Server(ctx, instanceID)
		return s, v.now().Add(v.serverTTL), err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		log.WarnContext(ctx, "instance verification failed", "reason", "instance not found in Nova")
		return e, fmt.Errorf("%w: instance not found", ErrInstanceMismatch)
	case err != nil:
		log.ErrorContext(ctx, "cannot look up instance in Nova", "error", err)
		return e, fmt.Errorf("%w: looking up instance: %w", ErrLookupUnavailable, err)
	case server.ProjectID != projectID:
		log.WarnContext(ctx, "instance verification failed", "reason", "instance belongs to another project", "server_project_id", server.ProjectID)
		return e, fmt.Errorf("%w: instance belongs to another project", ErrInstanceMismatch)
	case !slices.Contains(v.statuses, server.Status):
		log.WarnContext(ctx, "instance verification failed", "reason", "disallowed instance status", "status", server.Status)
		return e, fmt.Errorf("%w: instance status %q is not allowed", ErrInstanceMismatch, server.Status)
	}
	for _, name := range v.enrich {
		var value string
		switch name {
		case iid.ClaimAvailabilityZone:
			value = server.AvailabilityZone
			e.AvailabilityZone = value
		case iid.ClaimFlavor:
			value = server.Flavor
			e.Flavor = value
		case iid.ClaimUserID:
			value = server.UserID
			e.UserID = value
		default:
			continue
		}
		if value == "" {
			log.ErrorContext(ctx, "server record lacks an enrichment attribute", "claim", name, "status", server.Status)
			return claims.Enrichment{}, fmt.Errorf("%w: server record lacks %s", ErrLookupUnavailable, name)
		}
	}
	return e, nil
}

// lookupProject returns the enrichment claims read from the project record.
func (v *Verifier) lookupProject(ctx context.Context, log *slog.Logger, projectID string) (claims.Enrichment, error) {
	var e claims.Enrichment
	project, err := v.projects.Get(ctx, projectID, func(ctx context.Context) (Project, time.Time, error) {
		p, err := v.backend.Project(ctx, projectID)
		return p, v.now().Add(v.projectTTL), err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		log.WarnContext(ctx, "instance verification failed", "reason", "project not found in Keystone")
		return e, fmt.Errorf("%w: project not found", ErrInstanceMismatch)
	case err != nil && ctx.Err() != nil:
		// abandoned: the server check failed, or the caller went away
		return e, fmt.Errorf("%w: looking up project: %w", ErrLookupUnavailable, err)
	case err != nil:
		log.ErrorContext(ctx, "cannot look up project in Keystone", "error", err)
		return e, fmt.Errorf("%w: looking up project: %w", ErrLookupUnavailable, err)
	}
	if slices.Contains(v.enrich, iid.ClaimProjectName) {
		e.ProjectName = project.Name
	}
	if slices.Contains(v.enrich, iid.ClaimDomainID) {
		e.DomainID = project.DomainID
	}
	if (slices.Contains(v.enrich, iid.ClaimProjectName) && e.ProjectName == "") || (slices.Contains(v.enrich, iid.ClaimDomainID) && e.DomainID == "") {
		log.ErrorContext(ctx, "project record lacks an enrichment attribute")
		return claims.Enrichment{}, fmt.Errorf("%w: project record lacks name or domain", ErrLookupUnavailable)
	}
	return e, nil
}
