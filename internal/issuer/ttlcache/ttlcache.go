// Package ttlcache is a bounded cache whose entries expire individually, and
// which loads a missing entry once for all the callers asking for it at the
// same time: during boot storms, many requests need the same Nova or
// Keystone record at once.
package ttlcache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Loader loads the value of a missing entry and returns it with its expiry.
// Errors are not cached, nor are values already expired.
type Loader[V any] func(ctx context.Context) (V, time.Time, error)

// Config configures a Cache; zero values select the defaults.
type Config struct {
	// MaxEntries bounds the number of entries (default: 4096).
	MaxEntries int
	// LoadTimeout bounds each load (default: 5s).
	LoadTimeout time.Duration
	// Now is the source of the current time (default: time.Now).
	Now func() time.Time
}

type entry[V any] struct {
	value   V
	expires time.Time
}

type call[V any] struct {
	done  chan struct{}
	value V
	err   error
}

// Cache is a bounded cache with per-entry expiry and merged concurrent
// loads. When full, it first purges expired entries (at most once per
// second) and otherwise evicts an arbitrary one. It is safe for concurrent
// use.
type Cache[K comparable, V any] struct {
	maxEntries int
	timeout    time.Duration
	now        func() time.Time

	mu        sync.Mutex
	entries   map[K]entry[V]
	inflight  map[K]*call[V]
	lastPurge time.Time
}

// New creates a Cache.
func New[K comparable, V any](cfg Config) (*Cache[K, V], error) {
	if cfg.MaxEntries < 0 || cfg.LoadTimeout < 0 {
		return nil, fmt.Errorf("creating cache: size %d and load timeout %v must not be negative", cfg.MaxEntries, cfg.LoadTimeout)
	}
	c := &Cache[K, V]{
		maxEntries: cfg.MaxEntries,
		timeout:    cfg.LoadTimeout,
		now:        cfg.Now,
		entries:    map[K]entry[V]{},
		inflight:   map[K]*call[V]{},
	}
	if c.maxEntries == 0 {
		c.maxEntries = 4096
	}
	if c.timeout == 0 {
		c.timeout = 5 * time.Second
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// Get returns the entry for key if it has not expired, or else loads it,
// sharing the load with any concurrent caller of the same key. The load runs
// detached from the caller's context, bounded by the load timeout, so that a
// caller going away does not fail the others; a caller whose context ends
// first gets its context's error.
func (c *Cache[K, V]) Get(ctx context.Context, key K, load Loader[V]) (V, error) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		if c.now().Before(e.expires) {
			c.mu.Unlock()
			return e.value, nil
		}
		delete(c.entries, key)
	}
	cl, ok := c.inflight[key]
	if !ok {
		cl = &call[V]{done: make(chan struct{})}
		c.inflight[key] = cl
		go c.load(context.WithoutCancel(ctx), key, load, cl)
	}
	c.mu.Unlock()

	select {
	case <-cl.done:
		return cl.value, cl.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

// Len returns the number of entries, expired ones included.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache[K, V]) load(ctx context.Context, key K, load Loader[V], cl *call[V]) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	value, expires, err := load(ctx)

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil && c.now().Before(expires) {
		c.store(key, entry[V]{value: value, expires: expires})
	}
	c.mu.Unlock()

	cl.value, cl.err = value, err
	close(cl.done)
}

// store adds an entry, making room if needed; callers must hold the lock.
func (c *Cache[K, V]) store(key K, e entry[V]) {
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.maxEntries {
		now := c.now()
		if now.Sub(c.lastPurge) >= time.Second {
			c.lastPurge = now
			for k, old := range c.entries {
				if !now.Before(old.expires) {
					delete(c.entries, k)
				}
			}
		}
		if len(c.entries) >= c.maxEntries {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[key] = e
}
