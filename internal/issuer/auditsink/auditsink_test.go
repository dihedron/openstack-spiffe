package auditsink

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/requestid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// levelOff is OPENSTACK_SPIRE_ISSUER_LOG_LEVEL=off.
const levelOff = slog.Level(1000)

func listen(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, path
}

// datagram is a received message, split into its fields.
type datagram struct {
	pri, tag string
	msg      map[string]any
}

func receive(t *testing.T, conn *net.UnixConn) datagram {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	// RFC 3164, as journald parses it: <PRI>Mmm dd hh:mm:ss TAG[PID]: MSG
	raw := string(buf[:n])
	end := strings.IndexByte(raw, '>')
	head, text, ok := strings.Cut(raw[end+1:], ": ")
	if !strings.HasPrefix(raw, "<") || end < 0 || !ok || len(head) < 16 {
		t.Fatalf("not an RFC 3164 message: %q", raw)
	}
	tag, _, _ := strings.Cut(head[16:], "[")
	d := datagram{pri: raw[:end+1], tag: tag}
	if err := json.Unmarshal([]byte(text), &d.msg); err != nil {
		t.Fatalf("MSG %q is not a JSON object: %v", text, err)
	}
	return d
}

func expectNothing(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("unexpected datagram %q", buf[:n])
	}
}

// syncBuffer is the regular log stream.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// regular returns the issuer's regular log handler at the given level, as
// the binary's init installs it.
func regular(level slog.Level) (slog.Handler, *syncBuffer) {
	buf := &syncBuffer{}
	return syslog.KeepAudit(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: min(level, slog.LevelInfo)}), level), buf
}

func enabled(socket string) config.AuditSyslog {
	return config.AuditSyslog{Enabled: true, Socket: socket, Facility: "local3", AppName: "issuer-test"}
}

func newHandler(t *testing.T, base slog.Handler, cfg config.AuditSyslog) *slog.Logger {
	t.Helper()
	sink, err := New(base, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close(context.Background()) })
	return slog.New(sink.Handler)
}

// inRequest runs f with the context of an HTTP request, which carries a
// request ID, and returns that ID.
func inRequest(f func(ctx context.Context)) string {
	w := httptest.NewRecorder()
	requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f(r.Context())
	})).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/attest", nil))
	return w.Header().Get(requestid.Header)
}

func TestTokenIssuedReachesSyslogWithLoggingOff(t *testing.T) {
	conn, path := listen(t)
	base, stream := regular(levelOff)
	logger := newHandler(t, base, enabled(path))

	id := inRequest(func(ctx context.Context) {
		logger.InfoContext(ctx, "token issued", syslog.AuditKey, "token_issued", "jti", "j-1", "kid", "k-1")
	})

	d := receive(t, conn)
	// local3 (19) * 8 + informational (6)
	if d.pri != "<158>" || d.tag != "issuer-test" || d.msg["audit"] != "token_issued" || d.msg["time"] == nil {
		t.Fatalf("datagram %+v, want PRI <158>, tag issuer-test, audit token_issued and the time", d)
	}
	if d.msg["jti"] != "j-1" || d.msg["kid"] != "k-1" || d.msg["request_id"] != id {
		t.Fatalf("MSG %v, want jti j-1, kid k-1 and request_id %s", d.msg, id)
	}
	expectNothing(t, conn)

	// the regular stream keeps the audit trail even with logging off
	if out := stream.String(); !strings.Contains(out, "token issued") || !strings.Contains(out, "request_id="+id) {
		t.Fatalf("regular stream lacks the audit record:\n%s", out)
	}
}

func TestDroppedKeyIsNotice(t *testing.T) {
	conn, path := listen(t)
	base, _ := regular(slog.LevelInfo)
	logger := newHandler(t, base, enabled(path))
	logger.Log(context.Background(), syslog.LevelNotice, "signing key dropped", syslog.AuditKey, "key_lifecycle", "event", "dropped")

	// local3 (19) * 8 + notice (5)
	if d := receive(t, conn); d.pri != "<157>" || d.msg["audit"] != "key_lifecycle" {
		t.Fatalf("datagram %+v, want PRI <157> and audit key_lifecycle", d)
	}
}

func TestOrdinaryRecordsNeverReachSyslog(t *testing.T) {
	conn, path := listen(t)
	base, stream := regular(slog.LevelDebug)
	logger := newHandler(t, base, enabled(path))
	logger.Debug("debug")
	logger.Info("serving")
	logger.Error("cannot sign token")
	expectNothing(t, conn)
	if out := stream.String(); !strings.Contains(out, "serving") || !strings.Contains(out, "cannot sign token") {
		t.Fatalf("regular stream lost ordinary records:\n%s", out)
	}
}

func TestDisabledSinkKeepsTheRegularLog(t *testing.T) {
	base, stream := regular(slog.LevelInfo)
	cfg := enabled(filepath.Join(t.TempDir(), "no-such-socket"))
	cfg.Enabled = false
	logger := newHandler(t, base, cfg)
	id := inRequest(func(ctx context.Context) {
		logger.InfoContext(ctx, "token issued", syslog.AuditKey, "token_issued")
	})
	if out := stream.String(); !strings.Contains(out, "request_id="+id) {
		t.Fatalf("regular stream lacks the request ID:\n%s", out)
	}
}

func TestUnopenableSocketIsAnError(t *testing.T) {
	base, _ := regular(slog.LevelInfo)
	_, err := New(base, enabled(filepath.Join(t.TempDir(), "no-such-socket")))
	if err == nil {
		t.Fatal("New succeeded without a syslog socket")
	}
}

func TestDropsAreReportedOnceOnTheRegularLog(t *testing.T) {
	conn, path := listen(t)
	base, stream := regular(slog.LevelInfo)
	logger := newHandler(t, base, enabled(path))

	// the daemon goes away: every send fails
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		logger.Info("token issued", syslog.AuditKey, "token_issued")
	}
	waitFor(t, func() bool { return strings.Contains(stream.String(), "syslog audit records dropped") })
	time.Sleep(100 * time.Millisecond)
	if n := strings.Count(stream.String(), "syslog audit records dropped"); n != 1 {
		t.Fatalf("drop reported %d times, want once:\n%s", n, stream)
	}

	// the daemon comes back: the next record is delivered, with the count
	restarted, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	logger.Info("token issued", syslog.AuditKey, "token_issued")
	receive(t, restarted)
	waitFor(t, func() bool { return strings.Contains(stream.String(), "syslog audit records delivered again") })
	if !strings.Contains(stream.String(), "dropped=3") {
		t.Fatalf("recovery does not report 3 dropped records:\n%s", stream)
	}
}

func TestCloseDrainsTheQueue(t *testing.T) {
	conn, path := listen(t)
	base, _ := regular(slog.LevelInfo)
	sink, err := New(base, enabled(path))
	if err != nil {
		t.Fatal(err)
	}
	closeSink := sink.Close
	logger := slog.New(sink.Handler)
	for range 5 {
		logger.Info("token issued", syslog.AuditKey, "token_issued")
	}
	if err := closeSink(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	for range 5 {
		receive(t, conn)
	}
	// records logged after Close still reach the regular log, not syslog
	logger.Info("token issued", syslog.AuditKey, "token_issued")
	expectNothing(t, conn)
	if err := closeSink(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("second close: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRejectsSlogBuiltinDefault(t *testing.T) {
	cfg := enabled("/nonexistent")
	cfg.Enabled = false
	if _, err := New(slog.Default().Handler(), cfg); !errors.Is(err, errBuiltin) {
		t.Fatalf("New with slog's built-in handler = %v, want errBuiltin", err)
	}
}

func TestStats(t *testing.T) {
	base, _ := regular(slog.LevelInfo)
	disabled, err := New(base, config.AuditSyslog{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := disabled.Stats(); ok {
		t.Error("stats from a disabled sink")
	}
	_, path := listen(t)
	sink, err := New(base, enabled(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close(context.Background()) }()
	if stats, ok := sink.Stats(); !ok || stats.Dropped != 0 {
		t.Errorf("stats %+v, %v", stats, ok)
	}
}
