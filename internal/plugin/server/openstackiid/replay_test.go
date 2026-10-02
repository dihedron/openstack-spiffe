package openstackiid

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// claimsAt returns verified-looking claims issued at iat.
func claimsAt(jti string, iat time.Time) iid.Claims {
	return iid.Claims{ID: jti, IssuedAt: iat.Unix(), NotBefore: iat.Unix(), Expiry: iat.Add(iid.TTL).Unix()}
}

func TestReplayCacheRejectsReuse(t *testing.T) {
	start := testNow.Add(-time.Hour)
	r := newReplayCache(10, start)
	c := claimsAt("jti-1", testNow)
	if err := r.record(c, testNow, testSkew); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := r.record(c, testNow.Add(time.Second), testSkew); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second use: %v, want ErrReplayed", err)
	}
	// still rejected at the very end of the acceptance window
	end := time.Unix(c.Expiry, 0).Add(testSkew).Add(-time.Second)
	if err := r.record(c, end, testSkew); !errors.Is(err, ErrReplayed) {
		t.Fatalf("reuse at the end of the window: %v, want ErrReplayed", err)
	}
	if err := r.record(claimsAt("jti-2", testNow), testNow, testSkew); err != nil {
		t.Fatalf("another token: %v", err)
	}
}

func TestReplayCacheForgetsExpiredEntries(t *testing.T) {
	r := newReplayCache(1, testNow.Add(-time.Hour))
	if err := r.record(claimsAt("jti-1", testNow), testNow, testSkew); err != nil {
		t.Fatal(err)
	}
	// full: a second token is refused while the first is remembered
	if err := r.record(claimsAt("jti-2", testNow), testNow, testSkew); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache: %v, want ErrReplayCacheFull", err)
	}
	// once the first token's window has passed, its entry makes room
	later := testNow.Add(iid.TTL + testSkew)
	if err := r.record(claimsAt("jti-3", later), later, testSkew); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestReplayCacheBounded(t *testing.T) {
	r := newReplayCache(100, testNow.Add(-time.Hour))
	for i := range 100 {
		if err := r.record(claimsAt(fmt.Sprintf("jti-%d", i), testNow), testNow, testSkew); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if err := r.record(claimsAt("one-too-many", testNow), testNow, testSkew); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("101st entry: %v, want ErrReplayCacheFull (fail closed, never forget early)", err)
	}
	if n := r.len(); n != 100 {
		t.Fatalf("%d entries, want 100", n)
	}
}

func TestStartupWatermark(t *testing.T) {
	start := testNow
	r := newReplayCache(10, start)
	skew := int64(testSkew / time.Second)
	tests := []struct {
		name string
		iat  int64
		ok   bool
	}{
		{"minted before the start", start.Unix() - 10, false},
		{"minted at the start", start.Unix(), false},
		{"minted within the tolerance after the start", start.Unix() + skew - 1, false},
		{"minted at start + tolerance", start.Unix() + skew, true},
		{"minted later", start.Unix() + skew + 60, true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := claimsAt(fmt.Sprintf("jti-%d", i), time.Unix(tt.iat, 0))
			err := r.record(c, time.Unix(tt.iat, 0), testSkew)
			if tt.ok != (err == nil) {
				t.Fatalf("record error = %v, want ok=%v", err, tt.ok)
			}
			if !tt.ok && !errors.Is(err, ErrIssuedBeforeStart) {
				t.Fatalf("error = %v, want ErrIssuedBeforeStart", err)
			}
		})
	}
	if n := r.len(); n != 2 {
		t.Fatalf("%d entries recorded, want 2: rejected tokens are not recorded", n)
	}
}
