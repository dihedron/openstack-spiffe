package ratelimit

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/clientaddr"
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

func newLimiter(t *testing.T, events int, per time.Duration, clock *testClock, options ...Option) *Limiter {
	t.Helper()
	l, err := NewLimiter(events, per, append([]Option{WithClock(clock.Now)}, options...)...)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	return l
}

func TestOnePerFiveSeconds(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 1, 5*time.Second, clock)
	const instance = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"

	if ok, _ := l.Allow(instance); !ok {
		t.Fatal("first request denied")
	}
	ok, retry := l.Allow(instance)
	if ok {
		t.Fatal("second request within 5s allowed")
	}
	if retry != 5*time.Second {
		t.Fatalf("retry after %v, want 5s", retry)
	}

	clock.Advance(4 * time.Second)
	if ok, retry := l.Allow(instance); ok || retry != time.Second {
		t.Fatalf("after 4s: allowed %v, retry %v; want denied, 1s", ok, retry)
	}
	clock.Advance(time.Second)
	if ok, _ := l.Allow(instance); !ok {
		t.Fatal("request after 5s denied")
	}
}

func TestBurstThenRefill(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 200, time.Second, clock)
	for i := range 200 {
		if ok, _ := l.Allow("10.0.0.1"); !ok {
			t.Fatalf("request %d of the burst denied", i+1)
		}
	}
	if ok, retry := l.Allow("10.0.0.1"); ok || retry != 5*time.Millisecond {
		t.Fatalf("request 201: allowed %v, retry %v; want denied, 5ms", ok, retry)
	}
	clock.Advance(50 * time.Millisecond) // refills 10 tokens
	allowed := 0
	for range 20 {
		if ok, _ := l.Allow("10.0.0.1"); ok {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("%d requests allowed after 50ms, want 10", allowed)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 1, 5*time.Second, clock)
	l.Allow("instance-a")
	if ok, _ := l.Allow("instance-a"); ok {
		t.Fatal("instance-a not limited")
	}
	if ok, _ := l.Allow("instance-b"); !ok {
		t.Fatal("instance-b limited by instance-a's burst")
	}
}

func TestIdleBucketsAreSwept(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 1, 5*time.Second, clock)
	for i := range 100 {
		l.Allow(fmt.Sprintf("instance-%d", i))
	}
	if n := l.size(); n != 100 {
		t.Fatalf("%d buckets, want 100", n)
	}
	clock.Advance(5 * time.Second) // every bucket is full again
	l.Allow("instance-new")
	if n := l.size(); n != 1 {
		t.Fatalf("%d buckets after the sweep, want 1", n)
	}
}

func TestActiveBucketsSurviveTheSweep(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 2, 10*time.Second, clock)
	l.Allow("first") // first sweep, at t0
	clock.Advance(time.Second)
	l.Allow("busy")
	l.Allow("busy") // empty: full again only at t0+11s
	l.Allow("idle") // one token left: full again at t0+6s
	clock.Advance(9 * time.Second)
	l.Allow("other") // t0+10s: sweeps idle and first, not busy
	l.mu.Lock()
	_, idleKept := l.buckets["idle"]
	_, busyKept := l.buckets["busy"]
	l.mu.Unlock()
	if idleKept || !busyKept {
		t.Fatalf("after the sweep: idle kept %v, busy kept %v; want false, true", idleKept, busyKept)
	}
	if ok, _ := l.Allow("busy"); !ok { // 1.8 tokens refilled
		t.Fatal("busy should have one token again")
	}
	if ok, _ := l.Allow("busy"); ok {
		t.Fatal("busy's bucket was reset by the sweep")
	}
}

func TestKeyCountIsBounded(t *testing.T) {
	clock := &testClock{now: testNow}
	l := newLimiter(t, 1, time.Hour, clock, WithMaxKeys(50))
	for i := range 1000 {
		if ok, _ := l.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256)); !ok {
			t.Fatalf("new key %d denied", i)
		}
		if n := l.size(); n > 50 {
			t.Fatalf("%d buckets, want at most 50", n)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	l, err := NewLimiter(1000, time.Hour)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for g := range 8 {
		wg.Go(func() {
			for range 250 {
				if ok, _ := l.Allow(fmt.Sprintf("k%d", g%2)); ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	if allowed != 2000 {
		t.Fatalf("%d requests allowed, want 2000 (1000 per key)", allowed)
	}
}

func TestNewLimiterValidation(t *testing.T) {
	for _, tt := range []struct {
		events  int
		per     time.Duration
		options []Option
	}{
		{0, time.Second, nil},
		{-1, time.Second, nil},
		{1, 0, nil},
		{1, time.Second, []Option{WithMaxKeys(0)}},
	} {
		if _, err := NewLimiter(tt.events, tt.per, tt.options...); err == nil {
			t.Fatalf("NewLimiter(%d, %v) accepted", tt.events, tt.per)
		}
	}
}

// explodingBody fails the test if the body is read.
type explodingBody struct{ t *testing.T }

func (b explodingBody) Read([]byte) (int, error) {
	b.t.Error("request body read")
	return 0, io.EOF
}

func (b explodingBody) Close() error { return nil }

func request(t *testing.T, h http.Handler, remoteAddr string, body io.ReadCloser, contentLength int64) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/attest", nil)
	r.RemoteAddr = remoteAddr
	r.Body = body
	r.ContentLength = contentLength
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func TestSourceLimitRejectsBeforeReadingTheBody(t *testing.T) {
	clock := &testClock{now: testNow}
	reached := 0
	h, err := SourceMiddleware(newLimiter(t, 2, time.Second, clock), 1024, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
	}))
	if err != nil {
		t.Fatalf("SourceMiddleware: %v", err)
	}

	for range 2 {
		if resp := request(t, h, "10.0.0.1:40000", io.NopCloser(strings.NewReader("{}")), 2); resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
	}
	resp := request(t, h, "10.0.0.1:40001", explodingBody{t}, 2)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "1" {
		t.Fatalf("Retry-After %q, want 1", ra)
	}
	if reached != 2 {
		t.Fatalf("handler reached %d times, want 2", reached)
	}
	// another source is unaffected
	if resp := request(t, h, "10.0.0.2:40000", io.NopCloser(strings.NewReader("{}")), 2); resp.StatusCode != http.StatusOK {
		t.Fatalf("other source: status %d, want 200", resp.StatusCode)
	}
}

func TestSourceMiddlewareCapsTheBody(t *testing.T) {
	clock := &testClock{now: testNow}
	var readErr error
	h, err := SourceMiddleware(newLimiter(t, 100, time.Second, clock), 16, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	if err != nil {
		t.Fatalf("SourceMiddleware: %v", err)
	}

	// declared too large: rejected without reading or calling the handler
	if resp := request(t, h, "10.0.0.1:1", explodingBody{t}, 17); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("declared oversized body: status %d, want 400", resp.StatusCode)
	}
	// undeclared (chunked) and too large: the handler's read fails
	request(t, h, "10.0.0.1:1", io.NopCloser(strings.NewReader(strings.Repeat("x", 17))), -1)
	if _, ok := readErr.(*http.MaxBytesError); !ok {
		t.Fatalf("reading an oversized body: %v, want *http.MaxBytesError", readErr)
	}
	// within the cap
	request(t, h, "10.0.0.1:1", io.NopCloser(strings.NewReader(strings.Repeat("x", 16))), 16)
	if readErr != nil {
		t.Fatalf("reading a body within the cap: %v", readErr)
	}
}

func TestSourceKey(t *testing.T) {
	tests := []struct{ remoteAddr, want string }{
		{"10.0.0.1:40000", "10.0.0.1"},
		{"[2001:db8:1:2:aaaa::1]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:bbbb::7]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:3::1]:443", "2001:db8:1:3::/64"},
		{"[::ffff:10.0.0.1]:40000", "10.0.0.1"}, // IPv4-mapped
		{"not-an-address", "not-an-address"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodPost, "/attest", nil)
		r.RemoteAddr = tt.remoteAddr
		if got := sourceKey(r); got != tt.want {
			t.Fatalf("sourceKey(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
		}
	}
}

func TestIPv6SourcesShareTheirSlash64(t *testing.T) {
	clock := &testClock{now: testNow}
	h, err := SourceMiddleware(newLimiter(t, 1, time.Minute, clock), 1024, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatalf("SourceMiddleware: %v", err)
	}
	request(t, h, "[2001:db8:1:2::1]:1", io.NopCloser(strings.NewReader("")), 0)
	if resp := request(t, h, "[2001:db8:1:2::2]:1", explodingBody{t}, 0); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("address rotation within a /64: status %d, want 429", resp.StatusCode)
	}
}

func TestSourceKeyUsesTheResolvedClientAddress(t *testing.T) {
	resolver, err := clientaddr.NewResolver([]string{"10.0.10.0/24"}, "")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	clock := &testClock{now: testNow}
	h, err := SourceMiddleware(newLimiter(t, 1, time.Minute, clock), 1024, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatalf("SourceMiddleware: %v", err)
	}
	h = resolver.Middleware(h)
	send := func(peer, forwarded string) int {
		r := httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(""))
		r.RemoteAddr = peer
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// behind the trusted proxy, forwarded clients get separate buckets
	if code := send("10.0.10.3:1", "198.51.100.7"); code != http.StatusOK {
		t.Fatalf("first client: status %d", code)
	}
	if code := send("10.0.10.3:1", "198.51.100.8"); code != http.StatusOK {
		t.Fatalf("second client behind the same proxy: status %d, want 200", code)
	}
	// addresses the client prepends itself do not buy a fresh bucket
	if code := send("10.0.10.3:1", "203.0.113.1, 198.51.100.7"); code != http.StatusTooManyRequests {
		t.Fatalf("client-prepended address: status %d, want 429", code)
	}
	// a direct, untrusted peer cannot choose its key with a forged header
	if code := send("192.0.2.10:1", "198.51.100.9"); code != http.StatusOK {
		t.Fatalf("direct client: status %d", code)
	}
	if code := send("192.0.2.10:1", "198.51.100.10"); code != http.StatusTooManyRequests {
		t.Fatalf("forged header from an untrusted peer: status %d, want 429", code)
	}
}

func TestSourceMiddlewareValidation(t *testing.T) {
	l, _ := NewLimiter(1, time.Second)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := SourceMiddleware(nil, 1024, next); err == nil {
		t.Fatal("accepted a nil limiter")
	}
	if _, err := SourceMiddleware(l, 0, next); err == nil {
		t.Fatal("accepted a zero body cap")
	}
	if _, err := SourceMiddleware(l, 1024, nil); err == nil {
		t.Fatal("accepted a nil handler")
	}
}
