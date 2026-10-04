package syslog

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/juju/rfc/v2/rfc5424"
)

// listen opens a Unix datagram socket standing in for /dev/log.
func listen(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, path
}

// receive reads one datagram.
func receive(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64*1024)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("reading datagram: %v", err)
	}
	return string(buffer[:n])
}

// receiveNothing checks that no datagram arrives shortly.
func receiveNothing(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 64*1024)
	if n, err := conn.Read(buffer); err == nil {
		t.Fatalf("unexpected datagram %q", buffer[:n])
	}
}

// fields splits a message without structured data into its eight parts:
// PRI and VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, SD, MSG.
func fields(t *testing.T, datagram string) []string {
	t.Helper()
	parts := strings.SplitN(datagram, " ", 8)
	if len(parts) != 8 {
		t.Fatalf("malformed message %q", datagram)
	}
	return parts
}

func hostname(t *testing.T) string {
	t.Helper()
	name, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func open(t *testing.T, options ...Option) (*Syslog, *net.UnixConn) {
	t.Helper()
	conn, path := listen(t)
	s, err := New(append([]Option{WithSocket(path)}, options...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, conn
}

func TestSendFormat(t *testing.T) {
	s, conn := open(t, WithApplication("my-app"), WithProcess("proc-1"))
	when := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("CEST", 2*3600))
	if err := s.Send(&Message{
		Facility: rfc5424.FacilityAuthpriv,
		Severity: rfc5424.SeverityInformational,
		ID:       "Login",
		Time:     when,
		Content:  "a message sent to syslog",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// authpriv (10) * 8 + info (6) = 86; the time in UTC, to the microsecond
	want := fmt.Sprintf("<86>1 2026-01-02T01:04:05.123456Z %s my-app proc-1 Login - a message sent to syslog", hostname(t))
	if got := receive(t, conn); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestSendDefaults(t *testing.T) {
	s, conn := open(t)
	before := time.Now().Add(-time.Second)
	if err := s.Send(&Message{Facility: rfc5424.FacilityDaemon, Severity: rfc5424.SeverityNotice, Content: "x"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	parts := fields(t, receive(t, conn))
	if parts[0] != "<29>1" {
		t.Errorf("priority: got %q, want <29>1", parts[0])
	}
	timestamp, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil || timestamp.Before(before) || timestamp.After(time.Now()) {
		t.Errorf("timestamp %q not the current time (%v)", parts[1], err)
	}
	if app := filepath.Base(os.Args[0]); parts[3] != app {
		t.Errorf("application: got %q, want %q", parts[3], app)
	}
	if pid := fmt.Sprint(os.Getpid()); parts[4] != pid {
		t.Errorf("process: got %q, want %q", parts[4], pid)
	}
	if parts[5] != "-" || parts[6] != "-" {
		t.Errorf("MSGID and SD: got %q and %q, want - and -", parts[5], parts[6])
	}
}

func TestSendObjectAsJSON(t *testing.T) {
	s, conn := open(t)
	content := struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}{"Funtò", 3}
	if err := s.Send(&Message{Facility: rfc5424.FacilityAuthpriv, Severity: rfc5424.SeverityInformational, ID: "Login", Content: content}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := fields(t, receive(t, conn))[7]; got != `{"name":"Funtò","count":3}` {
		t.Errorf("got %q", got)
	}
}

func TestSendStructuredData(t *testing.T) {
	s, conn := open(t, WithEnterprise("32473"))
	if err := s.Send(&Message{
		Facility: rfc5424.FacilityAuthpriv,
		Severity: rfc5424.SeverityInformational,
		ID:       "Login",
		Content:  "text",
		Data: map[string][]string{
			"user":   {"name=John", `quote=a"b\c]d=e`},
			"tenant": {"id=1234567890"},
		},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// sorted by ID, parameters in order, values escaped once
	want := `Login [tenant@32473 id="1234567890"][user@32473 name="John" quote="a\"b\\c\]d=e"] text`
	if got := receive(t, conn); !strings.HasSuffix(got, want) {
		t.Errorf("got %q, want suffix %q", got, want)
	}
}

func TestSendRejectsInvalidStructuredData(t *testing.T) {
	tests := []struct {
		name       string
		enterprise string
		data       map[string][]string
	}{
		{"no enterprise number", "", map[string][]string{"user": {"name=John"}}},
		{"parameter without =", "32473", map[string][]string{"user": {"John"}}},
		{"parameter name with a space", "32473", map[string][]string{"user": {"first name=John"}}},
		{"ID with @", "32473", map[string][]string{"user@x": {"name=John"}}},
		{"ID over 32 characters", "32473", map[string][]string{strings.Repeat("u", 30): {"name=John"}}},
		{"invalid UTF-8 value", "32473", map[string][]string{"user": {"name=\xff"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, conn := open(t, WithEnterprise(test.enterprise))
			err := s.Send(&Message{Facility: rfc5424.FacilityAuthpriv, Severity: rfc5424.SeverityInformational, Content: "text", Data: test.data})
			if err == nil {
				t.Fatal("Send succeeded")
			}
			receiveNothing(t, conn)
		})
	}
}

func TestSendRejectsInvalidMessage(t *testing.T) {
	tests := []struct {
		name    string
		message Message
	}{
		{"MSGID with a space", Message{Severity: rfc5424.SeverityInformational, ID: "a b", Content: "x"}},
		{"MSGID over 32 characters", Message{Severity: rfc5424.SeverityInformational, ID: strings.Repeat("m", 33), Content: "x"}},
		{"unknown severity", Message{Severity: 42, Content: "x"}},
		{"unknown facility", Message{Facility: 99, Severity: rfc5424.SeverityInformational, Content: "x"}},
		{"no content", Message{Severity: rfc5424.SeverityInformational}},
		{"invalid UTF-8 text", Message{Severity: rfc5424.SeverityInformational, Content: "\xff"}},
		{"content not encodable", Message{Severity: rfc5424.SeverityInformational, Content: make(chan int)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, conn := open(t)
			if err := s.Send(&test.message); err == nil {
				t.Fatal("Send succeeded")
			}
			receiveNothing(t, conn)
		})
	}
}

func TestNewValidatesOptions(t *testing.T) {
	_, path := listen(t)
	tests := []struct {
		name    string
		options []Option
	}{
		{"enterprise not a number", []Option{WithEnterprise("dihedron")}},
		{"application with a space", []Option{WithApplication("my app")}},
		{"application over 48 characters", []Option{WithApplication(strings.Repeat("a", 49))}},
		{"process with a space", []Option{WithProcess("my process")}},
		{"missing socket", []Option{WithSocket(filepath.Join(t.TempDir(), "none"))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if s, err := New(append([]Option{WithSocket(path)}, test.options...)...); err == nil {
				s.Close()
				t.Fatal("New succeeded")
			}
		})
	}
	if s, err := New(WithSocket(path), WithEnterprise("32473.1.2")); err != nil {
		t.Errorf("enterprise with sub-identifiers: %v", err)
	} else {
		s.Close()
	}
}

func TestSendTruncatesOnCharacterBoundary(t *testing.T) {
	s, conn := open(t, WithMaxSize(200))
	if err := s.Send(&Message{Severity: rfc5424.SeverityInformational, Content: strings.Repeat("é", 200)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := receive(t, conn)
	if len(got) > 200 || len(got) < 198 {
		t.Errorf("message of %d bytes, want 198 to 200", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncated message is not valid UTF-8")
	}
	if !strings.HasSuffix(got, "éé") {
		t.Errorf("text missing: %q", got)
	}
}

func TestSendHeaderOverMaxSize(t *testing.T) {
	s, conn := open(t, WithMaxSize(20))
	if err := s.Send(&Message{Severity: rfc5424.SeverityInformational, Content: "x"}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	receiveNothing(t, conn)
}

func TestSendRedialsAfterDaemonRestart(t *testing.T) {
	conn, path := listen(t)
	s, err := New(WithSocket(path))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	message := &Message{Severity: rfc5424.SeverityInformational, Content: "x"}
	if err := s.Send(message); err != nil {
		t.Fatalf("Send: %v", err)
	}
	receive(t, conn)

	// the daemon restarts: its socket is removed and created again
	conn.Close()
	os.Remove(path)
	restarted, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()

	if err := s.Send(message); err != nil {
		t.Fatalf("Send after restart: %v", err)
	}
	receive(t, restarted)
}

func TestSendFailsWhileDaemonDown(t *testing.T) {
	conn, path := listen(t)
	s, err := New(WithSocket(path))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	conn.Close()
	os.Remove(path)
	if err := s.Send(&Message{Severity: rfc5424.SeverityInformational, Content: "x"}); err == nil {
		t.Fatal("Send succeeded without a socket")
	}
}

func TestSendAfterClose(t *testing.T) {
	s, conn := open(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Send(&Message{Severity: rfc5424.SeverityInformational, Content: "x"}); !errors.Is(err, ErrClosed) {
		t.Errorf("got %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	receiveNothing(t, conn)
}
