package syslog

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// AuditKey is the attribute that marks a record as an audit record; its
	// value, the audit kind (e.g. "token_issued"), becomes the MSGID.
	AuditKey = "audit"
	// LevelNotice is the slog level mapped to the syslog notice severity.
	LevelNotice = slog.LevelInfo + 2
	// DefaultQueueSize is the number of audit records waiting to be sent
	// beyond which new ones are dropped.
	DefaultQueueSize = 1024
)

// ErrQueueFull is reported when audit records are dropped because the
// queue is full.
var ErrQueueFull = errors.New("syslog audit queue full")

// AuditOption is a functional option type that allows us to configure the
// AuditHandler.
type AuditOption func(*auditSink)

// WithQueueSize allows to specify the number of audit records waiting to be
// sent beyond which new ones are dropped.
func WithQueueSize(size int) AuditOption {
	return func(s *auditSink) {
		if size > 0 {
			s.queueSize = size
		}
	}
}

// WithFailureFunc allows to specify a function called when audit records
// start being dropped, with the cause (ErrQueueFull, or the error of a
// failed send). It is called once per failure episode, not per record, and
// may be called from any goroutine.
func WithFailureFunc(f func(err error)) AuditOption {
	return func(s *auditSink) {
		s.onFailure = f
	}
}

// WithRecoveryFunc allows to specify a function called when an audit record
// is delivered again after a failure episode, with the number of records
// dropped during it. It may be called from any goroutine.
func WithRecoveryFunc(f func(dropped uint64)) AuditOption {
	return func(s *auditSink) {
		s.onRecovery = f
	}
}

// sender is what the sink needs from a Syslog.
type sender interface {
	Send(*Message) error
	room(*Message) (int, error)
	Close() error
}

// auditSink is the state shared by an AuditHandler and the handlers derived
// from it: the queue, the goroutine draining it into the syslog socket and
// the delivery failure accounting.
type auditSink struct {
	syslog     sender
	facility   Facility
	queueSize  int
	onFailure  func(error)
	onRecovery func(uint64)

	mu     sync.RWMutex // guards closed against sends on a closed queue
	closed bool
	queue  chan *Message
	done   chan struct{}

	failing atomic.Bool
	dropped atomic.Uint64
}

// AuditHandler is a slog.Handler that forwards to syslog only the records
// carrying an AuditKey attribute, either on the record or added with
// WithAttrs; other records are ignored. It is meant to be combined with the
// regular handler (e.g. with slog.NewMultiHandler).
//
// Each audit record becomes an RFC 5424 message whose MSGID is the audit
// kind and whose text is a single-line JSON object holding the record's
// message ("msg"), its level ("level") and its attributes, attributes in
// groups under dotted keys (e.g. "req.id"). If it does not fit in the
// maximum message size, attributes are left out, last first, and
// "truncated" is set to true.
//
// Records are sent asynchronously, through a bounded queue: Handle never
// blocks on the socket, and records are dropped when the queue is full or
// the send fails (see WithFailureFunc and WithRecoveryFunc). Audit records
// must be logged at slog.LevelInfo or above.
type AuditHandler struct {
	sink   *auditSink
	attrs  []field // attributes added with WithAttrs, already flattened
	groups []string
	kind   string // audit kind added with WithAttrs, if any
}

// NewAuditHandler returns an AuditHandler sending audit records through s,
// with the given facility, and starts the goroutine sending them; Close
// stops it and closes s.
func NewAuditHandler(s *Syslog, facility Facility, options ...AuditOption) (*AuditHandler, error) {
	return newAuditHandler(s, facility, options...)
}

func newAuditHandler(s sender, facility Facility, options ...AuditOption) (*AuditHandler, error) {
	if err := facility.Validate(); err != nil {
		return nil, fmt.Errorf("invalid facility: %w", err)
	}
	sink := &auditSink{
		syslog:     s,
		facility:   facility,
		queueSize:  DefaultQueueSize,
		onFailure:  func(error) {},
		onRecovery: func(uint64) {},
		done:       make(chan struct{}),
	}
	for _, option := range options {
		option(sink)
	}
	sink.queue = make(chan *Message, sink.queueSize)
	go sink.run()
	return &AuditHandler{sink: sink}, nil
}

// Enabled reports whether level can carry audit records.
func (h *AuditHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

// Handle queues the record for syslog if it is an audit record.
func (h *AuditHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Level < slog.LevelInfo {
		return nil
	}
	fields := slices.Clone(h.attrs)
	prefix := groupPrefix(h.groups)
	record.Attrs(func(a slog.Attr) bool {
		fields = flatten(fields, prefix, a)
		return true
	})
	kind := h.kind
	for _, f := range fields {
		if f.key == AuditKey {
			kind = f.value.String()
		}
	}
	if kind == "" {
		return nil
	}

	message := &Message{
		Facility: h.sink.facility,
		Severity: severity(record.Level),
		ID:       kind,
		Time:     record.Time,
	}
	room, err := h.sink.syslog.room(message)
	if err != nil {
		// an audit kind that is not a valid MSGID: a programming error
		h.sink.drop(fmt.Errorf("audit record %q: %w", kind, err))
		return nil
	}
	message.Content = encode(record.Message, record.Level, fields, room)
	h.sink.enqueue(message)
	return nil
}

// WithAttrs returns a handler whose records carry attrs.
func (h *AuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	clone := *h
	clone.attrs = slices.Clone(h.attrs)
	prefix := groupPrefix(h.groups)
	for _, a := range attrs {
		clone.attrs = flatten(clone.attrs, prefix, a)
	}
	for _, f := range clone.attrs {
		if f.key == AuditKey {
			clone.kind = f.value.String()
		}
	}
	return &clone
}

// WithGroup returns a handler whose later attributes are in group name.
func (h *AuditHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.groups = append(slices.Clone(h.groups), name)
	return &clone
}

// Close stops accepting audit records, sends those still queued until ctx
// is done, and closes the syslog connection. It closes the handlers derived
// from h too, and only the first call has any effect.
func (h *AuditHandler) Close(ctx context.Context) error {
	s := h.sink
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.queue)
	s.mu.Unlock()

	select {
	case <-s.done:
	case <-ctx.Done():
		// the goroutine stops at its next send, which fails on the closed
		// connection
	}
	err := s.syslog.Close()
	if ctx.Err() != nil {
		return fmt.Errorf("draining syslog audit queue: %w", ctx.Err())
	}
	return err
}

func (s *auditSink) enqueue(message *Message) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.queue <- message:
	default:
		s.drop(ErrQueueFull)
	}
}

func (s *auditSink) run() {
	defer close(s.done)
	for message := range s.queue {
		if err := s.syslog.Send(message); err != nil {
			s.drop(err)
			continue
		}
		if s.failing.CompareAndSwap(true, false) {
			s.onRecovery(s.dropped.Swap(0))
		}
	}
}

// drop counts a dropped record, and reports the start of a failure episode.
func (s *auditSink) drop(err error) {
	s.dropped.Add(1)
	if s.failing.CompareAndSwap(false, true) {
		s.onFailure(err)
	}
}

// facilities are the facilities audit records may be sent with.
var facilities = map[string]Facility{
	"auth":     FacilityAuth,
	"authpriv": FacilityAuthpriv,
	"daemon":   FacilityDaemon,
	"local0":   FacilityLocal0,
	"local1":   FacilityLocal1,
	"local2":   FacilityLocal2,
	"local3":   FacilityLocal3,
	"local4":   FacilityLocal4,
	"local5":   FacilityLocal5,
	"local6":   FacilityLocal6,
	"local7":   FacilityLocal7,
}

// ParseFacility returns the facility named name: auth, authpriv, daemon or
// local0 to local7.
func ParseFacility(name string) (Facility, error) {
	facility, ok := facilities[name]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %q: expected auth, authpriv, daemon or local0 to local7", name)
	}
	return facility, nil
}

// severity maps a slog level to a syslog severity; it never yields the
// alert or emergency severities, which journald forwards to every terminal.
func severity(level slog.Level) Severity {
	switch {
	case level < slog.LevelInfo:
		return SeverityDebug
	case level < LevelNotice:
		return SeverityInformational
	case level < slog.LevelWarn:
		return SeverityNotice
	case level < slog.LevelError:
		return SeverityWarning
	default:
		return SeverityError
	}
}

// field is a flattened attribute.
type field struct {
	key   string
	value slog.Value
}

func groupPrefix(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return strings.Join(groups, ".") + "."
}

// flatten appends a, resolved, to fields; group members get dotted keys.
func flatten(fields []field, prefix string, a slog.Attr) []field {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return fields
	}
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			prefix += a.Key + "."
		}
		for _, member := range a.Value.Group() {
			fields = flatten(fields, prefix, member)
		}
		return fields
	}
	return append(fields, field{key: prefix + a.Key, value: a.Value})
}

// encode renders the record as a JSON object of at most room bytes, leaving
// out attributes, last first, if needed; the audit kind is always kept.
func encode(msg string, level slog.Level, fields []field, room int) string {
	members := make([]string, 0, len(fields)+2)
	members = append(members, member("msg", slog.StringValue(msg)), member("level", slog.StringValue(level.String())))
	for _, f := range fields {
		members = append(members, member(f.key, f.value))
	}
	full := "{" + strings.Join(members, ",") + "}"
	if len(full) <= room {
		return full
	}

	const truncated = `"truncated":true`
	kept := []string{members[0], members[1]}
	size := len(kept[0]) + len(kept[1]) + len(truncated) + 4 // braces and commas
	for i, f := range fields {
		if f.key == AuditKey {
			kept = append(kept, members[i+2])
			size += len(members[i+2]) + 1
		}
	}
	for i, f := range fields {
		if f.key == AuditKey {
			continue
		}
		if size+len(members[i+2])+1 > room {
			break
		}
		kept = append(kept, members[i+2])
		size += len(members[i+2]) + 1
	}
	return "{" + strings.Join(append(kept, truncated), ",") + "}"
}

// member renders a JSON object member; values that cannot be encoded are
// rendered as strings.
func member(key string, value slog.Value) string {
	k, _ := marshal(key)
	v, err := marshal(jsonValue(value))
	if err != nil {
		v, _ = marshal(fmt.Sprint(value.Any()))
	}
	return k + ":" + v
}

func jsonValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindAny:
		switch a := v.Any().(type) {
		case json.Marshaler, encoding.TextMarshaler:
			return a
		case error:
			return a.Error()
		case fmt.Stringer:
			return a.String()
		default:
			return a
		}
	default:
		return v.Any()
	}
}

func marshal(v any) (string, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
