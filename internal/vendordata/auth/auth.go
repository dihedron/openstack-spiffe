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
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/clientaddr"
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

type cacheEntry struct {
	identity Identity
	expires  time.Time
}

// validation is an in-flight token validation, shared by every request
// carrying the same token.
type validation struct {
	done     chan struct{}
	identity Identity
	err      error
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

	mu       sync.Mutex
	cache    map[[sha256.Size]byte]cacheEntry
	inflight map[[sha256.Size]byte]*validation
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

// WithValidationTimeout bounds each Keystone validation (default: 5s).
func WithValidationTimeout(d time.Duration) Option {
	return func(a *Authenticator) { a.timeout = d }
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
		cache:      map[[sha256.Size]byte]cacheEntry{},
		inflight:   map[[sha256.Size]byte]*validation{},
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
	return a, nil
}

// Middleware rejects requests whose X-Auth-Token is missing or invalid (401),
// whose user is not authorized (403) or that cannot be validated (503), and
// passes the others to next. Rejected requests never reach next, and their
// bodies are never read.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		identity, err := a.Authenticate(ctx, r.Header.Get(TokenHeader))
		var status int
		switch {
		case err == nil:
			next.ServeHTTP(w, r)
			return
		case errors.Is(err, ErrMissingToken), errors.Is(err, ErrInvalidToken):
			slog.WarnContext(ctx, "rejecting unauthenticated request", "client_address", clientaddr.String(r), "reason", err)
			status = http.StatusUnauthorized
		case errors.Is(err, ErrForbidden):
			slog.WarnContext(ctx, "rejecting unauthorized caller", "client_address", clientaddr.String(r), "user_id", identity.UserID, "reason", err)
			status = http.StatusForbidden
		default:
			slog.ErrorContext(ctx, "cannot validate caller token", "error", err)
			status = http.StatusServiceUnavailable
		}
		http.Error(w, http.StatusText(status), status)
	})
}

// Authenticate validates the token and checks that its user is allowlisted
// and carries the required role. On ErrForbidden the returned identity is
// the (unauthorized) caller's, for logging.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, ErrMissingToken
	}
	identity, err := a.validate(ctx, token)
	if err != nil {
		return Identity{}, err
	}
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

// validate returns the identity behind the token, from the cache or from a
// (possibly shared) validation.
func (a *Authenticator) validate(ctx context.Context, token string) (Identity, error) {
	key := sha256.Sum256([]byte(token))

	a.mu.Lock()
	if entry, ok := a.cache[key]; ok {
		if a.now().Before(entry.expires) {
			a.mu.Unlock()
			return entry.identity, nil
		}
		delete(a.cache, key)
	}
	v, ok := a.inflight[key]
	if !ok {
		v = &validation{done: make(chan struct{})}
		a.inflight[key] = v
		// the validation outlives any single caller, so it runs detached
		// from the request context, bounded by its own timeout
		go a.run(context.WithoutCancel(ctx), key, token, v)
	}
	a.mu.Unlock()

	select {
	case <-v.done:
		return v.identity, v.err
	case <-ctx.Done():
		return Identity{}, fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
}

func (a *Authenticator) run(ctx context.Context, key [sha256.Size]byte, token string, v *validation) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	identity, err := a.validator.Validate(ctx, token)
	if err != nil && !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrUnavailable) {
		err = fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	a.mu.Lock()
	delete(a.inflight, key)
	if err == nil {
		a.store(key, identity)
	}
	a.mu.Unlock()

	v.identity, v.err = identity, err
	close(v.done)
}

// store caches a successful validation; callers must hold the lock.
func (a *Authenticator) store(key [sha256.Size]byte, identity Identity) {
	now := a.now()
	expires := now.Add(a.cacheTTL)
	if identity.ExpiresAt.Before(expires) {
		expires = identity.ExpiresAt
	}
	if !now.Before(expires) {
		return
	}
	if len(a.cache) >= a.maxEntries {
		for k, entry := range a.cache {
			if !now.Before(entry.expires) {
				delete(a.cache, k)
			}
		}
	}
	for len(a.cache) >= a.maxEntries {
		// still full: evict the entry closest to expiry
		var victim [sha256.Size]byte
		var earliest time.Time
		for k, entry := range a.cache {
			if earliest.IsZero() || entry.expires.Before(earliest) {
				victim, earliest = k, entry.expires
			}
		}
		delete(a.cache, victim)
	}
	a.cache[key] = cacheEntry{identity: identity, expires: expires}
}
