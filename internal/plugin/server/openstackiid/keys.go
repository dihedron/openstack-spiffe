package openstackiid

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
)

// keySourceConfig configures a keySource.
type keySourceConfig struct {
	// url is the JWK Set URL: the peered signers' or the JWKS aggregator's
	// /.well-known/jwks.json.
	url    string
	client *http.Client
	// refresh is the polling interval, fetchTimeout bounds each fetch, and
	// retention is how long the last successfully fetched keys stay in use.
	refresh, fetchTimeout, retention time.Duration
	// minRefetch is the minimum interval between re-fetches on an unknown
	// kid.
	minRefetch time.Duration
	now        func() time.Time
	// skipBackground disables background polling (tests poll by hand).
	skipBackground bool
}

// keySource holds the issuer's verification keys. It reuses the issuer's
// JWKS aggregation for a single URL, which brings the same fetch rules: https
// only, verified TLS, 200 only, at most 1 MiB and iid.MaxJWKSKeys keys, no
// redirects, key filtering, kids published with conflicting material
// excluded, and the last known good keys kept for the retention period.
type keySource struct {
	agg        *aggregator.Aggregator
	minRefetch time.Duration
	now        func() time.Time

	mu          sync.Mutex // serializes re-fetches
	lastRefetch time.Time
	refetched   bool

	cancel context.CancelFunc
	done   chan struct{}
}

func newKeySource(cfg keySourceConfig) (*keySource, error) {
	agg, err := aggregator.New([]string{cfg.url}, cfg.client,
		aggregator.WithPollInterval(cfg.refresh),
		aggregator.WithFetchTimeout(cfg.fetchTimeout),
		aggregator.WithStaleKeyRetention(cfg.retention),
		aggregator.WithClock(cfg.now),
	)
	if err != nil {
		return nil, fmt.Errorf("creating JWK Set client: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	k := &keySource{agg: agg, minRefetch: cfg.minRefetch, now: cfg.now, cancel: cancel, done: make(chan struct{})}
	if cfg.skipBackground {
		close(k.done)
	} else {
		go func() {
			defer close(k.done)
			if err := agg.Run(ctx); err != nil {
				slog.ErrorContext(ctx, "JWK Set polling stopped", "error", err)
			}
		}()
	}
	return k, nil
}

// close stops background polling and waits for it to end.
func (k *keySource) close() {
	k.cancel()
	<-k.done
}

// keys returns the current verification keys by kid.
func (k *keySource) keys(ctx context.Context) (map[string]keystore.PublicKey, error) {
	list, err := k.agg.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]keystore.PublicKey, len(list))
	for _, key := range list {
		keys[key.ID] = key
	}
	return keys, nil
}

// refetch fetches the JWK Set at once, unless it was re-fetched less than
// the minimum interval ago, and reports whether it did. Concurrent callers
// are merged: one fetches, the others wait for it and return false, so a
// flood of tokens with made-up kids cannot turn into a flood of fetches.
func (k *keySource) refetch(ctx context.Context) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if k.refetched && now.Sub(k.lastRefetch) < k.minRefetch {
		return false
	}
	k.lastRefetch, k.refetched = now, true
	k.agg.Refresh(ctx)
	return true
}
