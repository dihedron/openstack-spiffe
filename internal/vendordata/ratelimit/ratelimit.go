// Package ratelimit implements the two rate-limiting stages of the signer:
// a per-source limit applied before the request body is read, and a
// per-instance limit the /attest handler applies right after decoding it.
// Both use Limiter, a keyed token bucket with a bounded number of keys.
package ratelimit

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/clientaddr"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a set of token buckets, one per key, each holding up to events
// tokens and refilling at events per period: "1/5s" allows one request, then
// one more every 5 seconds. Buckets that have refilled completely are
// forgotten, so memory tracks only recently active keys, and the number of
// keys is bounded. It is safe for concurrent use.
type Limiter struct {
	capacity float64
	// refill is the number of tokens gained per second.
	refill  float64
	period  time.Duration
	maxKeys int
	now     func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// WithMaxKeys bounds the number of keys tracked at once (default: 65536).
// When the bound is reached and no idle bucket can be forgotten, an
// arbitrary bucket is evicted: its key starts over with a full bucket, which
// errs on the side of letting requests through rather than growing without
// bound or denying every new key.
func WithMaxKeys(n int) Option {
	return func(l *Limiter) { l.maxKeys = n }
}

// NewLimiter creates a Limiter allowing events requests per period and key,
// in bursts of up to events.
func NewLimiter(events int, period time.Duration, options ...Option) (*Limiter, error) {
	if events <= 0 || period <= 0 {
		return nil, fmt.Errorf("creating rate limiter: %d/%v: events and period must be positive", events, period)
	}
	l := &Limiter{
		capacity: float64(events),
		refill:   float64(events) / period.Seconds(),
		period:   period,
		maxKeys:  65536,
		now:      time.Now,
		buckets:  map[string]*bucket{},
	}
	for _, option := range options {
		option(l)
	}
	if l.maxKeys <= 0 {
		return nil, fmt.Errorf("creating rate limiter: maximum number of keys %d must be positive", l.maxKeys)
	}
	return l, nil
}

// Allow takes a token from the key's bucket and reports whether there was
// one; if not, it also returns how long until the next token.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			for victim := range l.buckets {
				delete(l.buckets, victim)
				break
			}
		}
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens = l.tokensAt(b, now)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration(math.Ceil((1 - b.tokens) / l.refill * float64(time.Second)))
	return false, wait
}

// tokensAt returns the tokens the bucket holds at now.
func (l *Limiter) tokensAt(b *bucket, now time.Time) float64 {
	return min(l.capacity, b.tokens+now.Sub(b.last).Seconds()*l.refill)
}

// sweep forgets the buckets that are full again, at most once per period;
// callers must hold the lock.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.period {
		return
	}
	l.lastSweep = now
	for key, b := range l.buckets {
		if l.tokensAt(b, now) >= l.capacity {
			delete(l.buckets, key)
		}
	}
}

// size returns the number of tracked keys.
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// SourceMiddleware limits requests per source address before anything reads
// the request body, answering 429 with Retry-After when the source's bucket
// is empty. It rejects a declared body larger than maxBodyBytes with 400 and
// caps the body of the requests it lets through with http.MaxBytesReader.
// The source is the client address (see clientaddr: the address stored by
// clientaddr's middleware, else the TCP peer address); IPv6 sources are keyed
// by their /64 prefix, which a single host usually controls entirely.
func SourceMiddleware(limiter *Limiter, maxBodyBytes int64, next http.Handler) (http.Handler, error) {
	switch {
	case limiter == nil:
		return nil, errors.New("creating source rate limiter: no limiter")
	case maxBodyBytes <= 0:
		return nil, fmt.Errorf("creating source rate limiter: body cap %d must be positive", maxBodyBytes)
	case next == nil:
		return nil, errors.New("creating source rate limiter: no handler")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := sourceKey(r)
		if ok, retryAfter := limiter.Allow(source); !ok {
			// debug level: a flood must not turn into a logging flood
			slog.DebugContext(r.Context(), "per-source rate limit exceeded", "source", source)
			w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(retryAfter.Seconds())), 10))
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		if r.ContentLength > maxBodyBytes {
			slog.WarnContext(r.Context(), "request body too large", "source", source, "content_length", r.ContentLength, "max_body_bytes", maxBodyBytes)
			http.Error(w, "request body too large", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	}), nil
}

// sourceKey returns the rate-limiting key of a request's client address:
// the IPv4 address, or the /64 prefix of an IPv6 address; the raw peer
// address if it cannot be parsed.
func sourceKey(r *http.Request) string {
	addr, ok := clientaddr.From(r)
	if !ok {
		return r.RemoteAddr
	}
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return r.RemoteAddr
	}
	return prefix.String()
}
