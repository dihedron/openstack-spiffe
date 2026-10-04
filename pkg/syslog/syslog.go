// Package syslog sends RFC 5424 messages to the local syslog daemon over a
// Unix datagram socket (e.g. /dev/log), and provides AuditHandler, a
// slog.Handler forwarding audit records there.
//
// The rfc5424 package provides the message types and their validation, but
// the message is serialized here: its timestamp carries nanoseconds, where
// RFC 5424 allows at most microseconds, and its structured data parameters
// are escaped twice.
package syslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/juju/rfc/v2/rfc5424"
)

const (
	// DefaultSocket is the Unix datagram socket of the local syslog daemon.
	DefaultSocket = "/dev/log"
	// DefaultSendTimeout bounds each write to the socket.
	DefaultSendTimeout = 1 * time.Second
	// DefaultMaxSize is the maximum size of a serialized message: Unix
	// datagram sockets reject larger ones.
	DefaultMaxSize = 8 * 1024
)

var (
	// ErrClosed is returned when sending through a closed Syslog.
	ErrClosed = errors.New("syslog client closed")
	// ErrTooLarge is returned when a message's header and structured data
	// alone exceed the maximum size.
	ErrTooLarge = errors.New("syslog message header exceeds the maximum size")
)

// enterpriseNumber is an IANA private enterprise number, optionally followed
// by sub-identifiers (RFC 5424, section 7.2.2).
var enterpriseNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// Option is a functional option type that allows us to configure the Syslog.
type Option func(*Syslog)

// WithApplication allows to specify the name of the application that is
// going to send events to the syslog (RFC 5424 APP-NAME).
func WithApplication(application string) Option {
	return func(sl *Syslog) {
		if application != "" {
			sl.application = application
		}
	}
}

// WithEnterprise allows to specify the IANA private enterprise number that
// qualifies the IDs of the structured data elements (e.g. "32473" gives
// "user@32473"). Without it, messages cannot carry structured data.
func WithEnterprise(enterprise string) Option {
	return func(sl *Syslog) {
		if enterprise != "" {
			sl.enterprise = enterprise
		}
	}
}

// WithProcess allows to specify the name of the process that is
// sending events to the syslog (RFC 5424 PROCID).
func WithProcess(process string) Option {
	return func(sl *Syslog) {
		if process != "" {
			sl.process = process
		}
	}
}

// WithSocket allows to specify the path of the Unix datagram socket of the
// syslog daemon.
func WithSocket(socket string) Option {
	return func(sl *Syslog) {
		if socket != "" {
			sl.socket = socket
		}
	}
}

// WithMaxSize allows to specify the maximum size of a serialized message;
// longer message texts are truncated on a UTF-8 character boundary. Zero
// disables the limit.
func WithMaxSize(size int) Option {
	return func(sl *Syslog) {
		if size >= 0 {
			sl.maxSize = size
		}
	}
}

// WithSendTimeout allows to specify the timeout of each write to the socket.
func WithSendTimeout(timeout time.Duration) Option {
	return func(sl *Syslog) {
		if timeout > 0 {
			sl.timeout = timeout
		}
	}
}

// Syslog wraps a syslog connection and stores all common
// configuration elements. It is safe for concurrent use.
type Syslog struct {
	application string
	hostname    string
	enterprise  string
	process     string
	socket      string
	maxSize     int
	timeout     time.Duration

	mu     sync.Mutex
	conn   net.Conn // nil after a failed redial, until the next send
	closed bool
}

// New creates a new Syslog connected to the syslog socket, initialising all
// relevant fields to the defaults unless options are provided: the
// application defaults to the base name of the executable, the process to
// the current PID, the socket to DefaultSocket, the maximum size to
// DefaultMaxSize and the send timeout to DefaultSendTimeout; there is no
// default enterprise number.
func New(options ...Option) (*Syslog, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("retrieving hostname: %w", err)
	}

	syslog := &Syslog{
		application: filepath.Base(os.Args[0]),
		hostname:    hostname,
		process:     fmt.Sprintf("%d", os.Getpid()),
		socket:      DefaultSocket,
		maxSize:     DefaultMaxSize,
		timeout:     DefaultSendTimeout,
	}
	// apply functional options
	for _, option := range options {
		option(syslog)
	}

	if err := rfc5424.AppName(syslog.application).Validate(); err != nil {
		return nil, fmt.Errorf("invalid application name %q: %w", syslog.application, err)
	}
	if err := rfc5424.ProcID(syslog.process).Validate(); err != nil {
		return nil, fmt.Errorf("invalid process %q: %w", syslog.process, err)
	}
	if syslog.enterprise != "" && !enterpriseNumber.MatchString(syslog.enterprise) {
		return nil, fmt.Errorf("invalid enterprise %q: not an IANA private enterprise number", syslog.enterprise)
	}

	if syslog.conn, err = syslog.dial(); err != nil {
		return nil, err
	}
	return syslog, nil
}

func (s *Syslog) dial() (net.Conn, error) {
	conn, err := net.Dial("unixgram", s.socket)
	if err != nil {
		return nil, fmt.Errorf("opening syslog socket %s: %w", s.socket, err)
	}
	return conn, nil
}

// Close closes the connection; any later Send fails with ErrClosed.
func (s *Syslog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// Send prepares a message in RFC5424-compliant format and sends it to the
// syslog socket. The message is validated first, and its text truncated on
// a UTF-8 character boundary if the whole would exceed the maximum size.
// If the write fails (e.g. because the syslog daemon restarted), the socket
// is dialed again and the write retried once.
func (s *Syslog) Send(message *Message) error {
	data, err := s.serialize(message)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.conn != nil {
		if err = s.write(data); err == nil {
			return nil
		}
		s.conn.Close()
		s.conn = nil
	}
	if s.conn, err = s.dial(); err != nil {
		return err
	}
	if err := s.write(data); err != nil {
		return fmt.Errorf("writing to syslog socket %s: %w", s.socket, err)
	}
	return nil
}

func (s *Syslog) write(data []byte) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	_, err := s.conn.Write(data)
	return err
}

// Message contains the set of information that is specific
// to a given message: its priority (in terms of facility and
// severity), the message type identifier (to group similar
// messages, the message text and optionally a set of
// parameters.
type Message struct {
	Facility rfc5424.Facility
	Severity rfc5424.Severity
	ID       string
	// Time is the time of the event; the zero value means now.
	Time    time.Time
	Content any // either a string or an object that will be marshalled to JSON
	// Data holds the structured data elements, by ID; each parameter has the
	// form "name=value". It requires an enterprise number (WithEnterprise).
	Data map[string][]string
}

// serialize validates the message and renders it, truncating its text to
// the maximum size.
func (s *Syslog) serialize(message *Message) ([]byte, error) {
	var text string
	switch content := message.Content.(type) {
	case nil:
		return nil, errors.New("no text in message")
	case string:
		text = content
	default:
		data, err := json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("encoding message content: %w", err)
		}
		text = string(data)
	}
	if !utf8.ValidString(text) {
		return nil, errors.New("invalid syslog message: text is not valid UTF-8")
	}

	head, err := s.head(message)
	if err != nil {
		return nil, err
	}
	if text == "" {
		return []byte(head), nil
	}
	if s.maxSize > 0 {
		room := s.maxSize - len(head) - 1
		if room <= 0 {
			return nil, ErrTooLarge
		}
		text = truncate(text, room)
	}
	return []byte(head + " " + text), nil
}

// room returns how many bytes of text fit in the message.
func (s *Syslog) room(message *Message) (int, error) {
	head, err := s.head(message)
	if err != nil {
		return 0, err
	}
	if s.maxSize == 0 {
		return int(^uint(0) >> 1), nil
	}
	return s.maxSize - len(head) - 1, nil
}

// head validates and renders the header and structured data of a message.
func (s *Syslog) head(message *Message) (string, error) {
	when := message.Time
	if when.IsZero() {
		when = time.Now()
	}
	header := rfc5424.Header{
		Priority: rfc5424.Priority{
			Severity: message.Severity,
			Facility: message.Facility,
		},
		Hostname: rfc5424.Hostname{FQDN: s.hostname},
		AppName:  rfc5424.AppName(s.application),
		ProcID:   rfc5424.ProcID(s.process),
		MsgID:    rfc5424.MsgID(message.ID),
	}
	if err := header.Validate(); err != nil {
		return "", fmt.Errorf("invalid syslog message: %w", err)
	}
	data, err := s.structuredData(message.Data)
	if err != nil {
		return "", fmt.Errorf("invalid syslog message: %w", err)
	}
	// RFC 5424 TIME-SECFRAC has at most 6 digits
	timestamp := when.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	return fmt.Sprintf("%s%d %s %s %s %s %s %s",
		header.Priority, rfc5424.ProtocolVersion, timestamp, header.Hostname, header.AppName,
		header.ProcID, header.MsgID, data), nil
}

// structuredData validates and renders the structured data elements, in
// order of ID and, within each element, in the order given.
func (s *Syslog) structuredData(elements map[string][]string) (string, error) {
	if len(elements) == 0 {
		return "-", nil
	}
	if s.enterprise == "" {
		return "", errors.New("structured data requires an enterprise number")
	}
	var b strings.Builder
	for _, id := range slices.Sorted(maps.Keys(elements)) {
		name := rfc5424.StructuredDataName(id + "@" + s.enterprise)
		if strings.Contains(id, "@") {
			return "", fmt.Errorf("structured data ID %q: contains '@'", id)
		}
		if err := name.Validate(); err != nil {
			return "", fmt.Errorf("structured data ID %q: %w", name, err)
		}
		b.WriteString("[")
		b.WriteString(string(name))
		for _, parameter := range elements[id] {
			key, value, ok := strings.Cut(parameter, "=")
			if !ok {
				return "", fmt.Errorf("structured data %q: parameter %q is not of the form name=value", id, parameter)
			}
			if err := rfc5424.StructuredDataName(key).Validate(); err != nil {
				return "", fmt.Errorf("structured data %q: parameter name %q: %w", id, key, err)
			}
			if !utf8.ValidString(value) {
				return "", fmt.Errorf("structured data %q: parameter %q: value is not valid UTF-8", id, key)
			}
			b.WriteString(" ")
			b.WriteString(key)
			b.WriteString(`="`)
			b.WriteString(paramEscaper.Replace(value))
			b.WriteString(`"`)
		}
		b.WriteString("]")
	}
	return b.String(), nil
}

// paramEscaper escapes the characters RFC 5424 reserves in PARAM-VALUE.
var paramEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)

// truncate cuts s to at most n bytes, on a UTF-8 character boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
