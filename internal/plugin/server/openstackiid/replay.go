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

// errSetFull is returned by expiringSet.add when every key is unexpired.
var errSetFull = errors.New("full")

// expiringSet holds keys, each until its own expiry, up to a bound: the
// replay cache's jtis and the TOFU reservations' agent IDs. It is safe for
// concurrent use.
type expiringSet struct {
	max int

	mu      sync.Mutex
	entries map[string]time.Time // key -> expiry
}

func newExpiringSet(max int) *expiringSet {
	return &expiringSet{max: max, entries: map[string]time.Time{}}
}

// add holds key until the given time and reports true, unless it is already
// held (false). When the set is full, expired keys are purged first; if
// none is, add fails with errSetFull and holds nothing.
func (s *expiringSet) add(key string, until, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expiry, ok := s.entries[key]; ok && now.Before(expiry) {
		return false, nil
	}
	if _, ok := s.entries[key]; !ok && len(s.entries) >= s.max {
		for k, expiry := range s.entries {
			if !now.Before(expiry) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= s.max {
			return false, errSetFull
		}
	}
	s.entries[key] = until
	return true, nil
}

// remove forgets key.
func (s *expiringSet) remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

func (s *expiringSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// replayCache accepts each token at most once. It is local to this SPIRE
// Server process: HA servers do not share it (a documented limitation), and
// the startup watermark covers what a restart forgets. It is safe for
// concurrent use.
type replayCache struct {
	start time.Time
	jtis  *expiringSet // jti -> end of its acceptance window
}

func newReplayCache(max int, start time.Time) *replayCache {
	return &replayCache{start: start, jtis: newExpiringSet(max)}
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
	added, err := r.jtis.add(c.ID, time.Unix(c.Expiry, 0).Add(skew), now)
	switch {
	case err != nil:
		return fmt.Errorf("%w (%d entries)", ErrReplayCacheFull, r.jtis.max)
	case !added:
		return fmt.Errorf("%w (jti %s)", ErrReplayed, c.ID)
	}
	return nil
}

func (r *replayCache) len() int { return r.jtis.len() }
