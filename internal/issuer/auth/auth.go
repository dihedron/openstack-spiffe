// Package auth authenticates the caller of the vendordata endpoint: Nova's
// metadata API, which sends a Keystone token obtained with the credentials
// of its [vendordata_dynamic_auth] section in the X-Auth-Token header. The
// token is validated against Keystone, and its user must be allowlisted and
// carry the required role.
package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ttlcache"
)

// TokenHeader is the header carrying the caller's Keystone token.
const TokenHeader = "X-Auth-Token"

var (
	// ErrMissingToken is returned when the request carries no token (401).
	ErrMissingToken = errors.New("missing " + TokenHeader)
	// ErrInvalidToken is returned (wrapped) for a token Keystone does not
	// recognize, or that has expired (401).
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrForbidden is returned (wrapped) when the token's user is not
	// allowlisted or lacks the required role (403).
	ErrForbidden = errors.New("caller not authorized")
	// ErrBusy is returned (wrapped, with ErrUnavailable) when the
	// validations in flight already reach the cap (503, D-2).
	ErrBusy = errors.New("too many Keystone validations in flight")
	// ErrUnavailable is returned (wrapped) when the token cannot be validated
	// because Keystone cannot be reached or fails (503).
	ErrUnavailable = errors.New("token validation unavailable")
)

// Identity is what Keystone reports about a valid token.
type Identity struct {
	UserID     string
	UserName   string
	DomainID   string
	DomainName string
	// Roles are the names of the roles the token carries.
	Roles []string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// TokenValidator validates a Keystone token. It returns ErrInvalidToken
// (wrapped) for tokens Keystone does not accept; any other error means the
// token could not be validated.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (Identity, error)
}

// Authenticator authenticates and authorizes callers. Successful validations
// are cached by the SHA-256 of the token, for at most the cache TTL and never
// beyond the token's expiry; concurrent validations of the same token are
// merged into one Keystone request. It is safe for concurrent use.
type Authenticator struct {
	validator  TokenValidator
	users      []AllowedUser
	role       string
	cacheTTL   time.Duration
	maxEntries int
	timeout    time.Duration
	now        func() time.Time
	// inFlight holds a slot per Keystone validation in flight; nil means no
	// cap.
	inFlight chan struct{}

	// cache holds successful validations by the SHA-256 of the token (never
	// the token itself) and merges concurrent validations of the same token.
	cache *ttlcache.Cache[[sha256.Size]byte, Identity]

	metrics *metrics.Metrics // nil: none recorded
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(a *Authenticator) { a.now = now }
}

// WithCacheTTL bounds how long a successful validation is cached (default:
// 60s).
func WithCacheTTL(d time.Duration) Option {
	return func(a *Authenticator) { a.cacheTTL = d }
}

// WithMaxCacheEntries bounds the number of cached validations (default:
// 1024).
func WithMaxCacheEntries(n int) Option {
	return func(a *Authenticator) { a.maxEntries = n }
}

// WithMetrics records the validations in m.
func WithMetrics(m *metrics.Metrics) Option {
	return func(a *Authenticator) { a.metrics = m }
}

// WithValidationTimeout bounds each Keystone validation (default: 5s).
func WithValidationTimeout(d time.Duration) Option {
	return func(a *Authenticator) { a.timeout = d }
}

// WithMaxConcurrentValidations caps the Keystone validations in flight
// (default: no cap). Beyond it, a token that is neither cached nor being
// validated already is refused at once with ErrBusy, rather than queued: a
// flood of distinct bogus tokens is never relayed to Keystone faster than
// the cap allows (D-2).
func WithMaxConcurrentValidations(n int) Option {
	return func(a *Authenticator) {
		if n > 0 {
			a.inFlight = make(chan struct{}, n)
		}
	}
}

// NewAuthenticator creates an Authenticator accepting the tokens of the
// allowlisted users (see ParseAllowedUser) that carry the required role.
func NewAuthenticator(validator TokenValidator, allowedUsers []string, requiredRole string, options ...Option) (*Authenticator, error) {
	if validator == nil {
		return nil, errors.New("creating authenticator: no token validator")
	}
	if len(allowedUsers) == 0 {
		return nil, errors.New("creating authenticator: no allowed users")
	}
	if requiredRole == "" {
		return nil, errors.New("creating authenticator: no required role")
	}
	a := &Authenticator{
		validator:  validator,
		role:       requiredRole,
		cacheTTL:   time.Minute,
		maxEntries: 1024,
		timeout:    5 * time.Second,
		now:        time.Now,
	}
	for _, entry := range allowedUsers {
		user, err := ParseAllowedUser(entry)
		if err != nil {
			return nil, fmt.Errorf("creating authenticator: allowed user %w", err)
		}
		a.users = append(a.users, user)
	}
	for _, option := range options {
		option(a)
	}
	if a.cacheTTL <= 0 || a.maxEntries <= 0 || a.timeout <= 0 {
		return nil, fmt.Errorf("creating authenticator: cache TTL (%v), cache size (%d) and validation timeout (%v) must be positive", a.cacheTTL, a.maxEntries, a.timeout)
	}
	cache, err := ttlcache.New[[sha256.Size]byte, Identity](ttlcache.Config{MaxEntries: a.maxEntries, LoadTimeout: a.timeout, Now: a.now})
	if err != nil {
		return nil, fmt.Errorf("creating authenticator: %w", err)
	}
	a.cache = cache
	return a, nil
}

// Middleware rejects requests whose X-Auth-Token is missing or invalid (401),
// whose user is not authorized (403) or that cannot be validated (503), and
// passes the others to next, with the caller's identity in the request
// context (see IdentityFrom). Rejected requests never reach next, and their
// bodies are never read.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		identity, err := a.Authenticate(ctx, r.Header.Get(TokenHeader))
		var status int
		switch {
		case err == nil:
			next.ServeHTTP(w, r.WithContext(WithIdentity(ctx, identity)))
			return
		case errors.Is(err, ErrMissingToken), errors.Is(err, ErrInvalidToken):
			metrics.Reject(ctx, metrics.ReasonUnauthenticated)
			slog.WarnContext(ctx, "rejecting unauthenticated request", "client_address", clientaddr.String(r), "reason", err)
			status = http.StatusUnauthorized
		case errors.Is(err, ErrForbidden):
			metrics.Reject(ctx, metrics.ReasonCallerNotAllowed)
			slog.WarnContext(ctx, "rejecting unauthorized caller", "client_address", clientaddr.String(r), "user_id", identity.UserID, "reason", err)
			status = http.StatusForbidden
		case errors.Is(err, ErrBusy):
			metrics.Reject(ctx, metrics.ReasonKeystoneBusy)
			// debug level: a flood must not turn into a logging flood
			slog.DebugContext(ctx, "refusing caller: Keystone validation cap reached", "client_address", clientaddr.String(r))
			status = http.StatusServiceUnavailable
		default:
			metrics.Reject(ctx, metrics.ReasonKeystoneUnavailable)
			slog.ErrorContext(ctx, "cannot validate caller token", "error", err)
			status = http.StatusServiceUnavailable
		}
		http.Error(w, http.StatusText(status), status)
	})
}

type identityKey struct{}

// WithIdentity returns a copy of ctx carrying the caller's identity, as
// Middleware stores it.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFrom returns the caller's identity, stored in the request context
// by Middleware once the caller is authenticated and authorized.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

// Authenticate validates the token and checks that its user is allowlisted
// and carries the required role. On ErrForbidden the returned identity is
// the (unauthorized) caller's, for logging.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, ErrMissingToken // no validation at all
	}
	identity, source, err := a.validate(ctx, token)
	if err == nil {
		identity, err = a.authorize(identity)
	}
	a.metrics.KeystoneValidation(ctx, validationResult(err), source.String())
	return identity, err
}

// authorize checks a validated identity: not expired, allowlisted and
// carrying the required role. On ErrForbidden it returns the identity.
func (a *Authenticator) authorize(identity Identity) (Identity, error) {
	if !a.now().Before(identity.ExpiresAt) {
		return Identity{}, fmt.Errorf("%w: expired at %s", ErrInvalidToken, identity.ExpiresAt.Format(time.RFC3339))
	}
	if !slices.ContainsFunc(a.users, func(u AllowedUser) bool { return u.Matches(identity) }) {
		return identity, fmt.Errorf("%w: user is not in keystone.allowed_users", ErrForbidden)
	}
	if !slices.Contains(identity.Roles, a.role) {
		return identity, fmt.Errorf("%w: token lacks role %q", ErrForbidden, a.role)
	}
	return identity, nil
}

// validationResult is the metrics result of a validation.
func validationResult(err error) string {
	switch {
	case err == nil:
		return metrics.ResultValid
	case errors.Is(err, ErrInvalidToken):
		return metrics.ResultInvalid
	case errors.Is(err, ErrForbidden):
		return metrics.ResultNotAllowed
	case errors.Is(err, ErrBusy):
		return metrics.ResultBusy
	}
	return metrics.ResultError
}

// validate returns the identity behind the token, from the cache or from a
// (possibly shared) Keystone validation, and where it came from. Successful
// validations are cached for at most the cache TTL and never beyond the
// token's expiry; failures are not cached.
func (a *Authenticator) validate(ctx context.Context, token string) (Identity, ttlcache.Source, error) {
	identity, source, err := a.cache.GetSource(ctx, sha256.Sum256([]byte(token)), func(ctx context.Context) (Identity, time.Time, error) {
		// only a real validation takes a slot: cache hits and callers merged
		// into this one never get here
		if a.inFlight != nil {
			select {
			case a.inFlight <- struct{}{}:
				defer func() { <-a.inFlight }()
			default:
				return Identity{}, time.Time{}, fmt.Errorf("%w: %w", ErrUnavailable, ErrBusy)
			}
		}
		a.metrics.KeystoneInFlight(ctx, 1)
		start := time.Now()
		identity, err := a.validator.Validate(ctx, token)
		a.metrics.KeystoneCall(ctx, validationResult(err), time.Since(start))
		a.metrics.KeystoneInFlight(ctx, -1)
		if err != nil {
			return Identity{}, time.Time{}, err
		}
		expires := a.now().Add(a.cacheTTL)
		if identity.ExpiresAt.Before(expires) {
			expires = identity.ExpiresAt
		}
		return identity, expires, nil
	})
	if err != nil && !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrUnavailable) {
		// Keystone failures, timeouts and the caller going away
		err = fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return identity, source, err
}
