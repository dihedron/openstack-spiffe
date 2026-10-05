package keystore

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// lifecycleLog captures the default logger's records as JSON objects.
type lifecycleLog struct {
	buf bytes.Buffer
}

func captureLifecycle(t *testing.T) *lifecycleLog {
	t.Helper()
	l := &lifecycleLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&l.buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return l
}

// records returns the key_lifecycle audit records logged since the last
// call, in order.
func (l *lifecycleLog) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(l.buf.String()) {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		if r[syslog.AuditKey] == "key_lifecycle" {
			out = append(out, r)
		}
	}
	l.buf.Reset()
	return out
}

type lifecycleEvent struct{ event, kid string }

func events(records []map[string]any) []lifecycleEvent {
	var out []lifecycleEvent
	for _, r := range records {
		out = append(out, lifecycleEvent{r["event"].(string), r["kid"].(string)})
	}
	return out
}

func mustMaintain(t *testing.T, s *Ephemeral) {
	t.Helper()
	if _, err := s.maintain(context.Background()); err != nil {
		t.Fatalf("maintain: %v", err)
	}
}

func thumbprints(t *testing.T, s *Ephemeral, into map[string]string) {
	t.Helper()
	keys, err := s.PublicKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		tp, err := Thumbprint(k)
		if err != nil {
			t.Fatal(err)
		}
		into[k.ID] = tp
	}
}

func TestKeyLifecycleRecords(t *testing.T) {
	log := captureLifecycle(t)
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "ES256")
	first := activeOrPending(t, s)
	tps := map[string]string{}
	thumbprints(t, s, tps)
	var all []map[string]any

	step := func(name string, want ...lifecycleEvent) {
		t.Helper()
		got := log.records(t)
		if !slices.Equal(events(got), want) {
			t.Fatalf("%s: events %v, want %v", name, events(got), want)
		}
		all = append(all, got...)
	}

	step("creation", lifecycleEvent{"generated", first}, lifecycleEvent{"published", first})
	mustMaintain(t, s)
	step("maintenance before activation")

	clock.Advance(testPublishAhead)
	mustMaintain(t, s)
	step("activation", lifecycleEvent{"active", first})
	mustMaintain(t, s)
	step("repeated maintenance")

	next := rotate(t, s, clock)
	thumbprints(t, s, tps)
	step("rotation", lifecycleEvent{"generated", next}, lifecycleEvent{"published", next})

	clock.Advance(testPublishAhead)
	mustMaintain(t, s)
	step("cutover", lifecycleEvent{"active", next}, lifecycleEvent{"retired", first})
	retiredAt := clock.Now()

	clock.Advance(iid.TTL)
	mustMaintain(t, s)
	step("purge", lifecycleEvent{"dropped", first})
	mustMaintain(t, s)
	step("repeated maintenance after purge")

	for _, r := range all {
		kid := r["kid"].(string)
		if r["replica_id"] != "signer-a" || r["algorithm"] != "ES256" || r["thumbprint"] != tps[kid] {
			t.Errorf("record %v: want replica signer-a, ES256 and thumbprint %s", r, tps[kid])
		}
		wantLevel := "INFO"
		if r["event"] == "dropped" {
			wantLevel = "INFO+2" // syslog.LevelNotice
		}
		if r["level"] != wantLevel {
			t.Errorf("%s record at level %v, want %s", r["event"], r["level"], wantLevel)
		}
	}
	effective := func(event, kid string) time.Time {
		for _, r := range all {
			if r["event"] == event && r["kid"] == kid {
				at, err := time.Parse(time.RFC3339Nano, r["effective_at"].(string))
				if err != nil {
					t.Fatalf("%s %s: effective_at: %v", event, kid, err)
				}
				return at
			}
		}
		t.Fatalf("no %s record for %s", event, kid)
		return time.Time{}
	}
	if got, want := effective("active", first), testStart.Add(testPublishAhead); !got.Equal(want) {
		t.Errorf("first key active at %v, want %v", got, want)
	}
	if got := effective("retired", first); !got.Equal(retiredAt) || !got.Equal(effective("active", next)) {
		t.Errorf("first key retired at %v, want %v, when its successor activated", got, retiredAt)
	}
	if got, want := effective("dropped", first), retiredAt.Add(iid.TTL); !got.Equal(want) {
		t.Errorf("first key dropped at %v, want %v", got, want)
	}
}

func TestKeyLifecycleRecordsAfterLateMaintenance(t *testing.T) {
	log := captureLifecycle(t)
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "ES256")
	first := activeOrPending(t, s)
	clock.Advance(testPublishAhead)
	mustMaintain(t, s)
	next := rotate(t, s, clock)
	log.records(t)

	// maintenance ran late: activation, retirement and purge all passed
	clock.Advance(testPublishAhead + iid.TTL + time.Minute)
	mustMaintain(t, s)
	want := []lifecycleEvent{{"active", next}, {"retired", first}, {"dropped", first}}
	if got := events(log.records(t)); !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
}
