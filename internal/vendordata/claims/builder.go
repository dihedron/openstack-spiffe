package claims

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"
	"uuid"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// Builder builds the claim set of an openstack_iid token from a Nova request.
// It is safe for concurrent use as long as the configured clock and ID
// generator are.
type Builder struct {
	now          func() time.Time
	newID        func() string
	ttl          time.Duration
	allowlist    []string
	maxTagsBytes int
	custom       map[string]string
}

// Option configures a Builder.
type Option func(*Builder)

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(b *Builder) { b.now = now }
}

// WithIDGenerator sets the "jti" generator (default: random UUIDv4).
func WithIDGenerator(newID func() string) Option {
	return func(b *Builder) { b.newID = newID }
}

// WithTTL sets the token validity window; it must be at least one second and
// at most iid.TTL (default: iid.TTL).
func WithTTL(ttl time.Duration) Option {
	return func(b *Builder) { b.ttl = ttl }
}

// WithAllowlist restricts the metadata keys copied into the "tags" claim; an
// empty allowlist lets every string-valued entry through.
func WithAllowlist(keys []string) Option {
	return func(b *Builder) { b.allowlist = slices.Clone(keys) }
}

// WithMaxTagsBytes sets the cap on the serialized "tags" claim; it must be at
// least 2 (the empty object) and at most iid.MaxTagsBytes (default:
// iid.MaxTagsBytes).
func WithMaxTagsBytes(size int) Option {
	return func(b *Builder) { b.maxTagsBytes = size }
}

// WithCustomClaims adds operator-configured static claims to every token, as
// top-level claims; their names must not be empty or reserved (see
// iid.ReservedClaims).
func WithCustomClaims(custom map[string]string) Option {
	return func(b *Builder) { b.custom = maps.Clone(custom) }
}

// NewBuilder creates a Builder, enforcing the TTL and tags size bounds and
// rejecting custom claims that would shadow reserved ones.
func NewBuilder(options ...Option) (*Builder, error) {
	b := &Builder{
		now:          time.Now,
		newID:        func() string { return uuid.NewV4().String() },
		ttl:          iid.TTL,
		maxTagsBytes: iid.MaxTagsBytes,
	}
	for _, option := range options {
		option(b)
	}
	if b.ttl < time.Second || b.ttl > iid.TTL {
		return nil, fmt.Errorf("token TTL %v out of range [1s, %v]", b.ttl, iid.TTL)
	}
	if b.maxTagsBytes < len("{}") || b.maxTagsBytes > iid.MaxTagsBytes {
		return nil, fmt.Errorf("tags size cap %d out of range [2, %d]", b.maxTagsBytes, iid.MaxTagsBytes)
	}
	if err := iid.ValidateCustomClaims(b.custom); err != nil {
		return nil, fmt.Errorf("configuring custom claims: %w", err)
	}
	return b, nil
}

// Build validates the request and returns the corresponding claims. Every
// claim value comes from the request, the clock, the ID generator or the
// operator-configured custom claims; nothing else can influence the result.
func (b *Builder) Build(ctx context.Context, req NovaRequest) (iid.Claims, error) {
	if err := req.Validate(); err != nil {
		slog.WarnContext(ctx, "rejecting invalid nova request", "project_id", req.ProjectID, "instance_id", req.InstanceID, "error", err)
		return iid.Claims{}, fmt.Errorf("building claims: %w", err)
	}

	tags, dropped := FilterTags(req.Metadata, b.allowlist, b.maxTagsBytes)
	for _, d := range dropped {
		slog.InfoContext(ctx, "metadata entry left out of tags", "project_id", req.ProjectID, "instance_id", req.InstanceID, "key", d.Key, "reason", d.Reason)
	}

	issuedAt := b.now().Unix()
	return iid.Claims{
		Issuer:     iid.Issuer,
		Audience:   iid.Audience,
		Subject:    req.InstanceID,
		IssuedAt:   issuedAt,
		NotBefore:  issuedAt,
		Expiry:     issuedAt + int64(b.ttl/time.Second),
		ID:         b.newID(),
		ProjectID:  req.ProjectID,
		InstanceID: req.InstanceID,
		Hostname:   req.Hostname,
		Tags:       tags,
		Custom:     maps.Clone(b.custom),
	}, nil
}
