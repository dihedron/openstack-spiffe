package syslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newAuditLogger(t *testing.T, syslogOptions []Option, options ...AuditOption) (*slog.Logger, *AuditHandler, *net.UnixConn) {
	t.Helper()
	conn, path := listen(t)
	s, err := New(append([]Option{WithSocket(path), WithApplication("issuer")}, syslogOptions...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h, err := NewAuditHandler(s, FacilityAuthpriv, options...)
	if err != nil {
		t.Fatalf("NewAuditHandler: %v", err)
	}
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	return slog.New(h), h, conn
}

// decode parses the JSON text of an audit message.
func decode(t *testing.T, text string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(text), &object); err != nil {
		t.Fatalf("message text %q is not a JSON object: %v", text, err)
	}
	return object
}

func TestAuditForwardsOnlyAuditRecords(t *testing.T) {
	logger, _, conn := newAuditLogger(t, nil)
	logger.Info("not an audit record", "instance_id", "i-1")
	logger.Info("token issued", "audit", "token_issued", "jti", "j-1", "count", 3, "ok", true)
	logger.Warn("not an audit record either")

	// RFC 3164, which journald parses: the tag is the application, and the
	// audit kind and the exact time are in the JSON text
	pri, _, tag, _, text := rfc3164(t, receive(t, conn))
	if pri != "<86>" || tag != "issuer" {
		t.Errorf("header: got %s %s", pri, tag)
	}
	got := decode(t, text)
	if _, err := time.Parse(time.RFC3339Nano, fmt.Sprint(got["time"])); err != nil {
		t.Errorf("time: %v", err)
	}
	delete(got, "time")
	want := map[string]any{"msg": "token issued", "level": "INFO", "audit": "token_issued", "jti": "j-1", "count": float64(3), "ok": true}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("text: got %v, want %v", got, want)
	}
	if !strings.HasPrefix(text, `{"msg":"token issued","level":"INFO","time":`) {
		t.Errorf("members out of order: %s", text)
	}
	receiveNothing(t, conn)
}

func TestAuditSeverities(t *testing.T) {
	logger, h, conn := newAuditLogger(t, nil)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("enabled at debug level")
	}
	tests := []struct {
		level    slog.Level
		priority string
	}{
		{slog.LevelInfo, "<86>"},
		{LevelNotice, "<85>"},
		{slog.LevelWarn, "<84>"},
		{slog.LevelError, "<83>"},
		{slog.LevelError + 8, "<83>"}, // never alert or emergency
	}
	for _, test := range tests {
		logger.Log(context.Background(), test.level, "event", "audit", "key_lifecycle")
		if got, _, _, _, _ := rfc3164(t, receive(t, conn)); got != test.priority {
			t.Errorf("level %v: got %s, want %s", test.level, got, test.priority)
		}
	}
	logger.Debug("event", "audit", "key_lifecycle")
	receiveNothing(t, conn)
}

func TestAuditAttributes(t *testing.T) {
	logger, _, conn := newAuditLogger(t, nil)
	when := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	logger.With("audit", "key_lifecycle", "replica", "signer-a").
		WithGroup("key").
		Info("generated", "kid", "k-1", slog.Group("x", "y", 1),
			"error", errors.New("boom"), "at", when, "ttl", 5*time.Minute, "text", "line\nbreak \"quoted\" <b>")

	_, _, _, _, text := rfc3164(t, receive(t, conn))
	if strings.Contains(text, "\n") {
		t.Errorf("text spans several lines: %q", text)
	}
	got := decode(t, text)
	delete(got, "time")
	want := map[string]any{
		"msg":       "generated",
		"level":     "INFO",
		"audit":     "key_lifecycle",
		"replica":   "signer-a",
		"key.kid":   "k-1",
		"key.x.y":   float64(1),
		"key.error": "boom",
		"key.at":    "2026-10-04T12:00:00Z",
		"key.ttl":   "5m0s",
		"key.text":  "line\nbreak \"quoted\" <b>",
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %#v, want %#v", k, got[k], v)
		}
	}
}

func TestAuditUsesRecordTime(t *testing.T) {
	_, h, conn := newAuditLogger(t, nil)
	when := time.Date(2026, 10, 4, 12, 0, 0, 987654321, time.UTC)
	record := slog.NewRecord(when, slog.LevelInfo, "token issued", 0)
	record.AddAttrs(slog.String("audit", "token_issued"))
	if err := h.Handle(context.Background(), record); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	_, timestamp, _, _, text := rfc3164(t, receive(t, conn))
	if want := when.Local().Format(time.Stamp); timestamp != want {
		t.Errorf("header timestamp: got %q, want %q", timestamp, want)
	}
	// the exact time, which the RFC 3164 header cannot carry
	if got := decode(t, text)["time"]; got != "2026-10-04T12:00:00.987654321Z" {
		t.Errorf("time: got %v", got)
	}
}

func TestAuditTruncatesKeepingValidJSON(t *testing.T) {
	logger, _, conn := newAuditLogger(t, []Option{WithMaxSize(300)})
	logger.Info("token issued", "jti", "j-1", "big", strings.Repeat("x", 1000), "audit", "token_issued", "after", "a")

	datagram := receive(t, conn)
	if len(datagram) > 300 {
		t.Errorf("message of %d bytes, over the maximum size", len(datagram))
	}
	_, _, _, _, text := rfc3164(t, datagram)
	got := decode(t, text)
	if got["truncated"] != true || got["audit"] != "token_issued" || got["jti"] != "j-1" || got["msg"] != "token issued" || got["time"] == nil {
		t.Errorf("got %v", got)
	}
	if _, ok := got["big"]; ok {
		t.Error("oversized attribute kept")
	}
}

// fakeSender stands in for Syslog in the queueing tests.
type fakeSender struct {
	send   func(*Message) error
	mu     sync.Mutex
	sent   []*Message
	closed atomic.Bool
}

func (f *fakeSender) Send(m *Message) error {
	if f.send != nil {
		if err := f.send(m); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeSender) room(m *Message) (int, error) {
	return 4096, validateHeaderField("MSGID", m.ID, 32)
}

func (f *fakeSender) Close() error {
	f.closed.Store(true)
	return nil
}

// eventually waits until condition holds.
func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if condition() {
			return
		}
	}
	t.Fatal("condition not met in time")
}

type reports struct {
	mu         sync.Mutex
	failures   []error
	recoveries []uint64
}

func (r *reports) options() []AuditOption {
	return []AuditOption{
		WithFailureFunc(func(err error) { r.mu.Lock(); r.failures = append(r.failures, err); r.mu.Unlock() }),
		WithRecoveryFunc(func(n uint64) { r.mu.Lock(); r.recoveries = append(r.recoveries, n); r.mu.Unlock() }),
	}
}

func (r *reports) get() ([]error, []uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.failures...), append([]uint64(nil), r.recoveries...)
}

func TestAuditDropsWhenQueueFull(t *testing.T) {
	started := make(chan struct{}, 10)
	release := make(chan struct{})
	sender := &fakeSender{send: func(*Message) error {
		started <- struct{}{}
		<-release
		return nil
	}}
	var r reports
	h, err := newAuditHandler(sender, FacilityAuthpriv, append(r.options(), WithQueueSize(1))...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close(context.Background()) }()
	logger := slog.New(h)

	logger.Info("one", "audit", "token_issued")
	<-started // the sender is now blocked on the first record
	done := make(chan struct{})
	go func() {
		logger.Info("two", "audit", "token_issued")   // queued
		logger.Info("three", "audit", "token_issued") // dropped
		logger.Info("four", "audit", "token_issued")  // dropped
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("logging blocked on a full queue")
	}
	if failures, _ := r.get(); len(failures) != 1 || !errors.Is(failures[0], ErrQueueFull) {
		t.Fatalf("failures: got %v, want one ErrQueueFull", failures)
	}

	close(release)
	eventually(t, func() bool { return sender.count() == 2 })
	eventually(t, func() bool { _, recoveries := r.get(); return len(recoveries) == 1 })
	if _, recoveries := r.get(); recoveries[0] != 2 {
		t.Errorf("recovery: got %d dropped, want 2", recoveries[0])
	}
}

func TestAuditReportsSendFailures(t *testing.T) {
	var calls atomic.Int32
	failure := errors.New("socket down")
	sender := &fakeSender{send: func(*Message) error {
		if calls.Add(1) <= 3 {
			return failure
		}
		return nil
	}}
	var r reports
	h, err := newAuditHandler(sender, FacilityAuthpriv, r.options()...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close(context.Background()) }()
	logger := slog.New(h)
	for range 4 {
		logger.Info("event", "audit", "token_issued")
	}
	eventually(t, func() bool { return sender.count() == 1 })
	eventually(t, func() bool { _, recoveries := r.get(); return len(recoveries) == 1 })
	failures, recoveries := r.get()
	if len(failures) != 1 || !errors.Is(failures[0], failure) {
		t.Errorf("failures: got %v, want one %v", failures, failure)
	}
	if recoveries[0] != 3 {
		t.Errorf("recovery: got %d dropped, want 3", recoveries[0])
	}
}

func TestAuditDropsInvalidKind(t *testing.T) {
	sender := &fakeSender{}
	var r reports
	h, err := newAuditHandler(sender, FacilityAuthpriv, r.options()...)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(h).Info("event", "audit", "not a valid msgid")
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sender.count() != 0 {
		t.Error("record with an invalid audit kind sent")
	}
	if failures, _ := r.get(); len(failures) != 1 {
		t.Errorf("failures: got %v, want one", failures)
	}
}

func TestAuditCloseDrainsQueue(t *testing.T) {
	logger, h, conn := newAuditLogger(t, nil)
	for range 10 {
		logger.Info("event", "audit", "token_issued")
	}
	if err := h.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for range 10 {
		receive(t, conn)
	}
	logger.Info("after close", "audit", "token_issued") // ignored, no panic
	receiveNothing(t, conn)
	if err := h.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestAuditCloseHonoursContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	sender := &fakeSender{send: func(*Message) error { <-release; return nil }}
	h, err := newAuditHandler(sender, FacilityAuthpriv)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(h).Info("event", "audit", "token_issued")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want context.DeadlineExceeded", err)
	}
	if !sender.closed.Load() {
		t.Error("syslog connection not closed")
	}
}

func TestAuditConcurrentUse(t *testing.T) {
	sender := &fakeSender{}
	h, err := newAuditHandler(sender, FacilityAuthpriv, WithQueueSize(10000))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(h).With("audit", "token_issued")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			l := logger.WithGroup("g").With("worker", i)
			for j := range 50 {
				l.Info("event", "n", j)
			}
		})
	}
	wg.Wait()
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != 1000 {
		t.Errorf("sent %d records, want 1000", got)
	}
}

func TestParseFacility(t *testing.T) {
	for name, want := range map[string]Facility{
		"auth":     FacilityAuth,
		"authpriv": FacilityAuthpriv,
		"daemon":   FacilityDaemon,
		"local0":   FacilityLocal0,
		"local7":   FacilityLocal7,
	} {
		if got, err := ParseFacility(name); err != nil || got != want {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
	}
	for _, name := range []string{"", "kern", "user", "AUTHPRIV", "local8"} {
		if _, err := ParseFacility(name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestAuditStatsAcrossEpisodes(t *testing.T) {
	var calls atomic.Int32
	sender := &fakeSender{send: func(*Message) error {
		switch calls.Add(1) {
		case 1, 2, 4: // two failure episodes: 2 records, then 1
			return errors.New("socket down")
		}
		return nil
	}}
	var r reports
	h, err := newAuditHandler(sender, FacilityAuthpriv, r.options()...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close(context.Background()) }()
	logger := slog.New(h)
	for range 5 {
		logger.Info("event", "audit", "token_issued")
	}
	eventually(t, func() bool { _, recoveries := r.get(); return len(recoveries) == 2 })
	if got := h.Stats(); got.Dropped != 3 || got.Queued != 0 {
		t.Errorf("stats %+v, want 3 dropped in all and an empty queue", got)
	}
}
