package openstackiid

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// maxReplayEntries bounds the replay cache: far above any realistic number
// of attestations within a token's acceptance window.
const maxReplayEntries = 100_000

var (
	// ErrReplayed is returned (wrapped) for a token whose jti was already
	// accepted.
	ErrReplayed = errors.New("token already used")
	// ErrIssuedBeforeStart is returned (wrapped) for a token minted before
	// this plugin process started.
	ErrIssuedBeforeStart = errors.New("token issued before this server started")
	// ErrReplayCacheFull is returned (wrapped) when no token can be
	// recorded: attestations are refused rather than a jti forgotten early.
	ErrReplayCacheFull = errors.New("replay cache full")
)

// processStart is the startup watermark: tokens minted before it may have
// been accepted by a previous process, whose replay cache is lost.
var processStart = time.Now()

// replayCache accepts each token at most once. It is local to this SPIRE
// Server process: HA servers do not share it (a documented limitation), and
// the startup watermark covers what a restart forgets. It is safe for
// concurrent use.
type replayCache struct {
	max   int
	start time.Time

	mu      sync.Mutex
	entries map[string]time.Time // jti -> end of its acceptance window
}

func newReplayCache(max int, start time.Time) *replayCache {
	return &replayCache{max: max, start: start, entries: map[string]time.Time{}}
}

// record accepts the token's jti, unless the token was minted before the
// process start (plus the tolerance: the issuer's clock may run ahead of
// this server's by up to skew, so only then is every accepted token sure to
// have been minted after the start), or its jti was already accepted. An
// accepted jti is remembered until the end of the token's acceptance window,
// exp + skew; rejected tokens are not recorded.
func (r *replayCache) record(c iid.Claims, now time.Time, skew time.Duration) error {
	if time.Unix(c.IssuedAt, 0).Before(r.start.Add(skew)) {
		return fmt.Errorf("%w (iat %d)", ErrIssuedBeforeStart, c.IssuedAt)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, ok := r.entries[c.ID]; ok && now.Before(until) {
		return fmt.Errorf("%w (jti %s)", ErrReplayed, c.ID)
	}
	if _, ok := r.entries[c.ID]; !ok && len(r.entries) >= r.max {
		for jti, until := range r.entries {
			if !now.Before(until) {
				delete(r.entries, jti)
			}
		}
		if len(r.entries) >= r.max {
			return fmt.Errorf("%w (%d entries)", ErrReplayCacheFull, len(r.entries))
		}
	}
	r.entries[c.ID] = time.Unix(c.Expiry, 0).Add(skew)
	return nil
}

func (r *replayCache) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
