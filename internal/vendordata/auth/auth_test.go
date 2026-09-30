package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	novaUserID     = "0123456789abcdef0123456789abcdef"
	serviceToken   = "gAAAAABservice-token-of-nova"
	arbitraryToken = "gAAAAABtoken-of-some-user"
)

var testNow = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeValidator maps tokens to identities; unknown tokens are invalid.
type fakeValidator struct {
	mu         sync.Mutex
	identities map[string]Identity
	err        error
	calls      atomic.Int32
	// gate, if set, blocks every validation until it is closed.
	gate chan struct{}
}

func (f *fakeValidator) Validate(ctx context.Context, token string) (Identity, error) {
	f.calls.Add(1)
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Identity{}, f.err
	}
	id, ok := f.identities[token]
	if !ok {
		return Identity{}, fmt.Errorf("token not found: %w", ErrInvalidToken)
	}
	return id, nil
}

func novaIdentity(expiresIn time.Duration) Identity {
	return Identity{
		UserID: novaUserID, UserName: "nova", DomainID: "default", DomainName: "Default",
		Roles: []string{"reader", "service"}, ExpiresAt: testNow.Add(expiresIn),
	}
}

func newValidator() *fakeValidator {
	return &fakeValidator{identities: map[string]Identity{
		serviceToken: novaIdentity(time.Hour),
		arbitraryToken: {
			UserID: "fedcba9876543210fedcba9876543210", UserName: "alice", DomainID: "default", DomainName: "Default",
			Roles: []string{"member"}, ExpiresAt: testNow.Add(time.Hour),
		},
	}}
}

func newAuthenticator(t *testing.T, v TokenValidator, clock *testClock, options ...Option) *Authenticator {
	t.Helper()
	options = append([]Option{WithClock(clock.Now)}, options...)
	a, err := NewAuthenticator(v, []string{"nova@Default"}, "service", options...)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// protected returns the middleware around a handler that records whether it
// ran, standing in for the /attest handler and its minter.
func protected(a *Authenticator) (http.Handler, *atomic.Int32) {
	var reached atomic.Int32
	return a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	})), &reached
}

const wellFormedBody = `{"project-id":"f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d","instance-id":"8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a","hostname":"vm-01","metadata":{}}`

func post(h http.Handler, token string) *http.Response {
	r := httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(wellFormedBody))
	if token != "" {
		r.Header.Set("X-Auth-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

// TestMissingTokenRejectedAndNothingSigned is the spec's required negative
// test: a well-formed body without X-Auth-Token never reaches the handler.
func TestMissingTokenRejectedAndNothingSigned(t *testing.T) {
	v := newValidator()
	h, reached := protected(newAuthenticator(t, v, &testClock{now: testNow}))

	resp := post(h, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if reached.Load() != 0 {
		t.Fatal("request without X-Auth-Token reached the handler")
	}
	if v.calls.Load() != 0 {
		t.Fatal("Keystone consulted for a request without a token")
	}
}

func TestAllowlistedServiceUserPasses(t *testing.T) {
	h, reached := protected(newAuthenticator(t, newValidator(), &testClock{now: testNow}))
	if resp := post(h, serviceToken); resp.StatusCode != http.StatusOK || reached.Load() != 1 {
		t.Fatalf("status %d, handler reached %d times; want 200 and 1", resp.StatusCode, reached.Load())
	}
}

func TestRejections(t *testing.T) {
	boom := errors.New("dial tcp 10.0.0.5:5000: connection refused")
	tests := []struct {
		name   string
		setup  func(v *fakeValidator)
		token  string
		status int
	}{
		{"unknown token", nil, "gAAAAABforged", http.StatusUnauthorized},
		{"arbitrary user token", nil, arbitraryToken, http.StatusForbidden},
		{"allowlisted user without the role", func(v *fakeValidator) {
			id := novaIdentity(time.Hour)
			id.Roles = []string{"reader"}
			v.identities[serviceToken] = id
		}, serviceToken, http.StatusForbidden},
		{"same name in another domain", func(v *fakeValidator) {
			id := novaIdentity(time.Hour)
			id.UserID, id.DomainID, id.DomainName = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "d2", "Tenants"
			v.identities[serviceToken] = id
		}, serviceToken, http.StatusForbidden},
		{"token already expired", func(v *fakeValidator) {
			v.identities[serviceToken] = novaIdentity(-time.Second)
		}, serviceToken, http.StatusUnauthorized},
		{"keystone unreachable", func(v *fakeValidator) { v.err = fmt.Errorf("%w: %w", ErrUnavailable, boom) }, serviceToken, http.StatusServiceUnavailable},
		{"unclassified validator error", func(v *fakeValidator) { v.err = boom }, serviceToken, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newValidator()
			if tt.setup != nil {
				tt.setup(v)
			}
			h, reached := protected(newAuthenticator(t, v, &testClock{now: testNow}))
			resp := post(h, tt.token)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
			if reached.Load() != 0 {
				t.Fatal("rejected request reached the handler")
			}
			body, _ := io.ReadAll(resp.Body)
			for _, secret := range []string{tt.token, "10.0.0.5", novaUserID} {
				if strings.Contains(string(body), secret) {
					t.Fatalf("response body leaks %q: %s", secret, body)
				}
			}
		})
	}
}

func TestAuthenticateErrors(t *testing.T) {
	a := newAuthenticator(t, newValidator(), &testClock{now: testNow})
	ctx := context.Background()
	if _, err := a.Authenticate(ctx, ""); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("empty token: %v, want ErrMissingToken", err)
	}
	if _, err := a.Authenticate(ctx, "bogus"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("bogus token: %v, want ErrInvalidToken", err)
	}
	if _, err := a.Authenticate(ctx, arbitraryToken); !errors.Is(err, ErrForbidden) {
		t.Fatalf("arbitrary token: %v, want ErrForbidden", err)
	}
	id, err := a.Authenticate(ctx, serviceToken)
	if err != nil || id.UserID != novaUserID {
		t.Fatalf("service token: %+v, %v", id, err)
	}
}

func TestAllowlistByUserID(t *testing.T) {
	a, err := NewAuthenticator(newValidator(), []string{novaUserID}, "service", WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), serviceToken); err != nil {
		t.Fatalf("allowlisted by ID: %v", err)
	}
}

func TestAllowlistByDomainID(t *testing.T) {
	a, err := NewAuthenticator(newValidator(), []string{"nova@default"}, "service", WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), serviceToken); err != nil {
		t.Fatalf("allowlisted by domain ID: %v", err)
	}
}

func TestCacheHitAvoidsRevalidation(t *testing.T) {
	v := newValidator()
	clock := &testClock{now: testNow}
	h, _ := protected(newAuthenticator(t, v, clock))

	for range 5 {
		if resp := post(h, serviceToken); resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if n := v.calls.Load(); n != 1 {
		t.Fatalf("Keystone consulted %d times, want 1", n)
	}

	clock.Advance(time.Minute) // default validation_cache_ttl
	post(h, serviceToken)
	if n := v.calls.Load(); n != 2 {
		t.Fatalf("cache entry outlived the TTL: %d validations, want 2", n)
	}
}

func TestCacheNeverOutlivesTheToken(t *testing.T) {
	v := newValidator()
	v.identities[serviceToken] = novaIdentity(10 * time.Second)
	clock := &testClock{now: testNow}
	a := newAuthenticator(t, v, clock)
	ctx := context.Background()

	if _, err := a.Authenticate(ctx, serviceToken); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	clock.Advance(10 * time.Second)
	// the validator still returns the (now expired) identity, as Keystone
	// would never do: the cache must not serve it, and the expiry check must
	// reject it
	if _, err := a.Authenticate(ctx, serviceToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token: %v, want ErrInvalidToken", err)
	}
	if n := v.calls.Load(); n != 2 {
		t.Fatalf("%d validations, want 2", n)
	}
}

func TestCacheTTLOption(t *testing.T) {
	v := newValidator()
	clock := &testClock{now: testNow}
	a := newAuthenticator(t, v, clock, WithCacheTTL(5*time.Second))
	ctx := context.Background()
	a.Authenticate(ctx, serviceToken)
	clock.Advance(4 * time.Second)
	a.Authenticate(ctx, serviceToken)
	clock.Advance(time.Second)
	a.Authenticate(ctx, serviceToken)
	if n := v.calls.Load(); n != 2 {
		t.Fatalf("%d validations, want 2", n)
	}
}

func TestFailuresAreNotCached(t *testing.T) {
	v := newValidator()
	v.err = ErrUnavailable
	a := newAuthenticator(t, v, &testClock{now: testNow})
	ctx := context.Background()
	if _, err := a.Authenticate(ctx, serviceToken); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
	v.mu.Lock()
	v.err = nil
	v.mu.Unlock()
	if _, err := a.Authenticate(ctx, serviceToken); err != nil {
		t.Fatalf("recovered Keystone: %v", err)
	}
	if _, err := a.Authenticate(ctx, "bogus"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v", err)
	}
	if _, err := a.Authenticate(ctx, "bogus"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v", err)
	}
	if n := v.calls.Load(); n != 4 {
		t.Fatalf("%d validations, want 4 (failures are not cached)", n)
	}
}

func TestCacheIsBounded(t *testing.T) {
	v := newValidator()
	for i := range 10 {
		v.identities[fmt.Sprintf("token-%d", i)] = novaIdentity(time.Hour + time.Duration(i)*time.Minute)
	}
	a := newAuthenticator(t, v, &testClock{now: testNow}, WithMaxCacheEntries(3))
	ctx := context.Background()
	for i := range 10 {
		if _, err := a.Authenticate(ctx, fmt.Sprintf("token-%d", i)); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	if size := a.cache.Len(); size > 3 {
		t.Fatalf("cache holds %d entries, want at most 3", size)
	}
}

func TestCacheKeyIsTokenHash(t *testing.T) {
	a := newAuthenticator(t, newValidator(), &testClock{now: testNow})
	if _, err := a.Authenticate(context.Background(), serviceToken); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if a.cache.Len() != 1 {
		t.Fatalf("%d cache entries, want 1", a.cache.Len())
	}
	// the entry is found under the token's hash: no load happens (the cache
	// key type, a SHA-256 digest, rules out keying by the token itself)
	identity, err := a.cache.Get(context.Background(), sha256.Sum256([]byte(serviceToken)), func(context.Context) (Identity, time.Time, error) {
		return Identity{}, time.Time{}, errors.New("no entry under the SHA-256 of the token")
	})
	if err != nil || identity.UserID != novaUserID {
		t.Fatalf("lookup by token hash: %+v, %v", identity, err)
	}
}

func TestConcurrentValidationsOfTheSameTokenAreMerged(t *testing.T) {
	v := newValidator()
	v.gate = make(chan struct{})
	a := newAuthenticator(t, v, &testClock{now: testNow})

	const callers = 20
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			_, err := a.Authenticate(context.Background(), serviceToken)
			errs <- err
		})
	}
	// wait until the single validation is in flight, then release it
	deadline := time.Now().Add(5 * time.Second)
	for v.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the other callers queue up
	close(v.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	if n := v.calls.Load(); n != 1 {
		t.Fatalf("%d validations for %d concurrent callers, want 1", n, callers)
	}
}

func TestCallerCancellationDoesNotBlock(t *testing.T) {
	v := newValidator()
	v.gate = make(chan struct{})
	defer close(v.gate)
	a := newAuthenticator(t, v, &testClock{now: testNow})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.Authenticate(ctx, serviceToken); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestValidationTimeout(t *testing.T) {
	v := newValidator()
	v.gate = make(chan struct{})
	defer close(v.gate)
	a := newAuthenticator(t, v, &testClock{now: testNow}, WithValidationTimeout(20*time.Millisecond))
	if _, err := a.Authenticate(context.Background(), serviceToken); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestNewAuthenticatorValidation(t *testing.T) {
	v := newValidator()
	tests := []struct {
		name    string
		v       TokenValidator
		users   []string
		role    string
		options []Option
	}{
		{"nil validator", nil, []string{"nova@Default"}, "service", nil},
		{"no users", v, nil, "service", nil},
		{"bare name", v, []string{"nova"}, "service", nil},
		{"no role", v, []string{"nova@Default"}, "", nil},
		{"zero cache TTL", v, []string{"nova@Default"}, "service", []Option{WithCacheTTL(0)}},
		{"zero cache size", v, []string{"nova@Default"}, "service", []Option{WithMaxCacheEntries(0)}},
		{"zero timeout", v, []string{"nova@Default"}, "service", []Option{WithValidationTimeout(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewAuthenticator(tt.v, tt.users, tt.role, tt.options...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
