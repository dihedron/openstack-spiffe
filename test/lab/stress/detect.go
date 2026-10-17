//go:build lab

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Journal entries ------------------------------------------------------------

// Entry is a journald entry from one of the followed journals.
type Entry struct {
	VM        string
	Time      time.Time
	Cursor    string
	Unit      string
	Ident     string
	Transport string
	Priority  int
	Message   string
}

// parseEntry parses a line of "journalctl -o json".
func parseEntry(vm string, line []byte) (Entry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return Entry{}, fmt.Errorf("journal entry: %w", err)
	}
	field := func(name string) string {
		v, ok := raw[name]
		if !ok {
			return ""
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
		// a value that is not valid UTF-8 comes as an array of bytes
		var b []byte
		var ints []int
		if err := json.Unmarshal(v, &ints); err == nil {
			for _, i := range ints {
				b = append(b, byte(i))
			}
			return string(b)
		}
		return ""
	}
	e := Entry{VM: vm, Cursor: field("__CURSOR"), Unit: field("_SYSTEMD_UNIT"), Ident: field("SYSLOG_IDENTIFIER"),
		Transport: field("_TRANSPORT"), Message: field("MESSAGE"), Priority: -1}
	if us, err := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		e.Time = time.UnixMicro(us).UTC()
	}
	if p, err := strconv.Atoi(field("PRIORITY")); err == nil {
		e.Priority = p
	}
	return e, nil
}

// logfmt parses the key=value pairs of a slog text or logrus record.
func logfmt(s string) map[string]string {
	fields := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			continue
		}
		key := s[start:i]
		i++
		var value strings.Builder
		if i < len(s) && s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				value.WriteByte(s[i])
				i++
			}
			i++
		} else {
			for i < len(s) && s[i] != ' ' {
				value.WriteByte(s[i])
				i++
			}
		}
		fields[key] = value.String()
	}
	return fields
}

// --- Facts ------------------------------------------------------------------------

// Token is an issuer's token_issued audit record.
type Token struct {
	VM, JTI, Instance, KID string
	Time                   time.Time
}

// Attested is the server plugin's agent_attested audit record.
type Attested struct {
	JTI, Instance, AgentID, KID string
	Time                        time.Time
}

// Alert is the server plugin's reattest_alert audit record.
type Alert struct {
	Instance, JTI, PrevJTI string
	Time                   time.Time
}

// Rejection kinds of the server plugin.
const (
	rejectAlreadyUsed = "already_used"
	rejectBeforeStart = "before_start"
	rejectOther       = "other"
)

// Rejection is an attestation the server plugin rejected.
type Rejection struct {
	Instance, Kind, Message string
	Time                    time.Time
}

// ErrorRecord is an error-level record of an issuer or the server plugin.
type ErrorRecord struct {
	VM, Message, Instance string
	Time                  time.Time
}

// NovaProblem is a warning or error of nova-api-metadata about the dynamic
// vendordata.
type NovaProblem struct {
	Message   string
	Instances []string
	Time      time.Time
}

// Facts are what the followed journals said during the run.
type Facts struct {
	Tokens       []Token
	Attested     []Attested
	Alerts       []Alert
	Rejections   []Rejection
	Errors       []ErrorRecord
	UnknownKID   []ErrorRecord
	NovaProblems []NovaProblem
	// IssuerProblems are the issuers' warnings and errors about an instance
	IssuerProblems []ErrorRecord
}

// Ledger accumulates the facts from the followed journals; it is safe for
// concurrent use.
type Ledger struct {
	mu    sync.Mutex
	facts Facts
}

func newLedger() *Ledger { return &Ledger{} }

var (
	uuidPattern    = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	agentIDPattern = regexp.MustCompile(`/spire/agent/openstack_iid/[^/\s"]+/([^/\s"]+)`)
)

// rejectionWindow merges the records of one rejection: the plugin's and
// SPIRE Server's own, a moment later.
const rejectionWindow = 2 * time.Second

// Add interprets a journal entry.
func (l *Ledger) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case e.Transport == "syslog" && e.Ident == "openstack-spire-issuer":
		var r map[string]any
		if json.Unmarshal([]byte(e.Message), &r) == nil && r["audit"] == "token_issued" {
			l.facts.Tokens = append(l.facts.Tokens, Token{VM: e.VM, JTI: str(r["jti"]), Instance: str(r["instance_id"]), KID: str(r["kid"]), Time: e.Time})
		}
	case e.Transport == "syslog" && e.Ident == "openstack-server-plugin":
		var r map[string]any
		if json.Unmarshal([]byte(e.Message), &r) != nil {
			return
		}
		switch r["audit"] {
		case "agent_attested":
			l.facts.Attested = append(l.facts.Attested, Attested{JTI: str(r["jti"]), Instance: str(r["instance_id"]), AgentID: str(r["spiffe_id"]), KID: str(r["kid"]), Time: e.Time})
		case "reattest_alert":
			l.facts.Alerts = append(l.facts.Alerts, Alert{Instance: str(r["instance_id"]), JTI: str(r["jti"]), PrevJTI: str(r["previous_jti"]), Time: e.Time})
		}
	case strings.HasPrefix(e.Unit, "openstack-spire-issuer"):
		f := logfmt(e.Message)
		level := strings.ToUpper(f["level"])
		if level != "ERROR" && level != "WARN" {
			return
		}
		r := ErrorRecord{VM: e.VM, Message: describe(f, e.Message), Instance: f["instance_id"], Time: e.Time}
		if r.Instance != "" {
			l.facts.IssuerProblems = append(l.facts.IssuerProblems, r)
		}
		if level == "ERROR" {
			l.facts.Errors = append(l.facts.Errors, r)
		}
	case strings.HasPrefix(e.Unit, "spire-server"):
		l.addSpire(e)
	case strings.HasPrefix(e.Unit, "devstack@n-api-meta"):
		if novaProblem(e) {
			if strings.Contains(strings.ToLower(e.Message), "vendordata") || strings.Contains(e.Message, "openstack_iid") {
				l.facts.NovaProblems = append(l.facts.NovaProblems, NovaProblem{Message: e.Message, Instances: uuidPattern.FindAllString(e.Message, -1), Time: e.Time})
			}
		}
	}
}

// novaProblem reports whether a nova-api-metadata record is a warning or an
// error: oslo.log writes its level as the message's first word, and
// journald records the unit's output at the info priority.
func novaProblem(e Entry) bool {
	if e.Priority >= 0 && e.Priority <= 4 {
		return true
	}
	level, _, _ := strings.Cut(strings.TrimSpace(e.Message), " ")
	return level == "WARNING" || level == "ERROR" || level == "CRITICAL"
}

// addSpire interprets a record of SPIRE Server's journal: only those about
// the openstack_iid plugin count.
func (l *Ledger) addSpire(e Entry) {
	if !strings.Contains(e.Message, "openstack_iid") {
		return
	}
	f := logfmt(e.Message)
	level := strings.ToLower(f["level"])
	instance := f["instance_id"]
	if instance == "" {
		if m := agentIDPattern.FindStringSubmatch(e.Message); m != nil {
			instance = m[1]
		}
	}
	text := describe(f, e.Message)
	if strings.Contains(e.Message, "unknown kid") {
		l.facts.UnknownKID = append(l.facts.UnknownKID, ErrorRecord{VM: e.VM, Message: text, Instance: instance, Time: e.Time})
	}
	if strings.Contains(e.Message, "attestation rejected") {
		kind := rejectOther
		switch {
		case strings.Contains(e.Message, "token already used"):
			kind = rejectAlreadyUsed
		case strings.Contains(e.Message, "token issued before this server started"):
			kind = rejectBeforeStart
		}
		for i := len(l.facts.Rejections) - 1; i >= 0; i-- {
			r := l.facts.Rejections[i]
			if e.Time.Sub(r.Time) > rejectionWindow {
				break
			}
			if r.Kind == kind && (r.Instance == instance || instance == "" || r.Instance == "") {
				if r.Instance == "" {
					l.facts.Rejections[i].Instance = instance
				}
				return
			}
		}
		l.facts.Rejections = append(l.facts.Rejections, Rejection{Instance: instance, Kind: kind, Message: text, Time: e.Time})
		return
	}
	if level == "error" {
		l.facts.Errors = append(l.facts.Errors, ErrorRecord{VM: e.VM, Message: text, Instance: instance, Time: e.Time})
	}
}

func describe(f map[string]string, raw string) string {
	msg := f["msg"]
	if msg == "" {
		return raw
	}
	if err := f["error"]; err != "" {
		return msg + ": " + err
	}
	return msg
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// Facts is a copy of the facts so far.
func (l *Ledger) Facts() Facts {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.facts
	f.Tokens = slices.Clone(f.Tokens)
	f.Attested = slices.Clone(f.Attested)
	f.Alerts = slices.Clone(f.Alerts)
	f.Rejections = slices.Clone(f.Rejections)
	f.Errors = slices.Clone(f.Errors)
	f.UnknownKID = slices.Clone(f.UnknownKID)
	f.NovaProblems = slices.Clone(f.NovaProblems)
	f.IssuerProblems = slices.Clone(f.IssuerProblems)
	return f
}

// TokensFor is the number of tokens issued for an instance.
func (l *Ledger) TokensFor(instance string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, t := range l.facts.Tokens {
		if t.Instance == instance {
			n++
		}
	}
	return n
}

// IssuerProblems is the number of the issuers' warnings and errors about an
// instance.
func (l *Ledger) IssuerProblems(instance string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.facts.IssuerProblems {
		if r.Instance == instance {
			n++
		}
	}
	return n
}

// AttestedSince is the agent_attested records of an instance since a time.
func (l *Ledger) AttestedSince(instance string, since time.Time) []Attested {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Attested
	for _, a := range l.facts.Attested {
		if a.Instance == instance && !a.Time.Before(since) {
			out = append(out, a)
		}
	}
	return out
}

// RejectionsSince is the rejections of an instance's attestations since a
// time.
func (l *Ledger) RejectionsSince(instance string, since time.Time) []Rejection {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Rejection
	for _, r := range l.facts.Rejections {
		if r.Instance == instance && !r.Time.Before(since) {
			out = append(out, r)
		}
	}
	return out
}

// ErrorsSince is the number of error records about an instance since a
// time.
func (l *Ledger) ErrorsSince(instance string, since time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.facts.Errors {
		if r.Instance == instance && !r.Time.Before(since) {
			n++
		}
	}
	return n
}

// --- Run-wide checks --------------------------------------------------------------

// InvariantInputs is what the run-wide checks look at.
type InvariantInputs struct {
	Facts     Facts
	Cycles    []CycleResult
	Faults    []FaultWindow
	Evictions map[string][]time.Time // agent ID → when the run evicted it
	TOFU      bool
	// CounterDelta is the growth of issuer-a's tokens_issued_total during
	// the run, nil when it cannot be compared (issuer-a restarted)
	CounterDelta *int64
}

// checkInvariants runs the run-wide checks (spec, detection).
func checkInvariants(in InvariantInputs) []Failure {
	var failures []Failure
	flag := func(reason string, security bool, instance string, at time.Time) {
		failures = append(failures, Failure{Time: at, Class: ClassInvariant, Reason: reason, Security: security, InstanceID: instance})
	}
	cycles := map[string]CycleResult{}
	for _, c := range in.Cycles {
		if c.InstanceID != "" {
			cycles[c.InstanceID] = c
		}
	}
	inFault := func(t time.Time) bool {
		for _, w := range in.Faults {
			if w.contains(t) {
				return true
			}
		}
		return false
	}

	issued := map[string]bool{}
	for _, t := range in.Facts.Tokens {
		issued[t.JTI] = true
	}
	seen := map[string]int{}
	for _, a := range in.Facts.Attested {
		seen[a.JTI]++
		if !issued[a.JTI] {
			flag(fmt.Sprintf("agent_attested jti %s (instance %s) has no token_issued record on the issuers", a.JTI, a.Instance), false, a.Instance, a.Time)
		}
	}
	for jti, n := range seen {
		if n > 1 {
			flag(fmt.Sprintf("jti %s attested %d times", jti, n), true, "", time.Time{})
		}
	}
	for _, r := range in.Facts.UnknownKID {
		flag("attestation rejected on an unknown kid: "+r.Message, false, r.Instance, r.Time)
	}
	for _, a := range in.Facts.Alerts {
		c, ours := cycles[a.Instance]
		if !ours {
			continue
		}
		if c.Kind == KindRestart && c.SVIDExpiredWhileStopped && !in.TOFU {
			continue
		}
		flag(fmt.Sprintf("reattest_alert for %s, a %s cycle's instance (%s)", a.Instance, c.Kind, c.ID), false, a.Instance, a.Time)
	}
	// errors not explained by a failed cycle or a fault, one per message
	unexplained := map[string][]ErrorRecord{}
	for _, r := range in.Facts.Errors {
		if c, ok := cycles[r.Instance]; ok && (c.Outcome != outcomePassed || c.ExpectedRefusal) {
			continue
		}
		if inFault(r.Time) {
			continue
		}
		key := r.VM + ": " + r.Message
		unexplained[key] = append(unexplained[key], r)
	}
	keys := make([]string, 0, len(unexplained))
	for k := range unexplained {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		records := unexplained[k]
		flag(fmt.Sprintf("%d unexplained error record(s), first at %s: %s", len(records), records[0].Time.Format(time.TimeOnly), k), false, records[0].Instance, records[0].Time)
	}
	if in.TOFU {
		byAgent := map[string][]time.Time{}
		for _, a := range in.Facts.Attested {
			byAgent[a.AgentID] = append(byAgent[a.AgentID], a.Time)
		}
		for agent, times := range byAgent {
			sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
			for i := 1; i < len(times); i++ {
				evicted := false
				for _, e := range in.Evictions[agent] {
					if e.After(times[i-1]) && e.Before(times[i]) {
						evicted = true
					}
				}
				if !evicted {
					flag(fmt.Sprintf("%s attested again at %s without an eviction (TOFU must refuse it)", agent, times[i].Format(time.TimeOnly)), true, "", times[i])
				}
			}
		}
	}
	if in.CounterDelta != nil {
		n := int64(0)
		for _, t := range in.Facts.Tokens {
			if t.VM == "issuer-a" {
				n++
			}
		}
		if *in.CounterDelta != n {
			flag(fmt.Sprintf("issuer-a's openstack_spire_tokens_issued_total grew by %d, its token_issued records are %d", *in.CounterDelta, n), false, "", time.Time{})
		}
	}
	return failures
}

// --- Classification -----------------------------------------------------------------

// AttestEvidence is what tells why an agent did not attest in time.
type AttestEvidence struct {
	GuestReachable   bool
	AgentInstalled   bool
	TokensIssued     int
	IssuerProblems   int
	PluginRejections int
}

// classifyAttest classes a missed node attestation: node when anything of
// the attestation chain ran (the agent, the issuer, the plugin), infra when
// the guest never got that far (no network, no agent installed).
func classifyAttest(e AttestEvidence) Class {
	if e.PluginRejections > 0 || e.IssuerProblems > 0 || e.TokensIssued > 0 {
		return ClassNode
	}
	if e.GuestReachable && e.AgentInstalled {
		return ClassNode
	}
	return ClassInfra
}

// classifyBoot classes an instance that went to ERROR, from Nova's fault.
func classifyBoot(fault string) Class {
	if strings.Contains(fault, "No valid host") || strings.Contains(fault, "NoValidHost") {
		return ClassCapacity
	}
	return ClassInfra
}

// --- Verdict ------------------------------------------------------------------------

// verdict is the run's exit status and its one-line explanation: 1 when a
// failure counts against it, 2 when only the infra rate was exceeded, 3 when
// the teardown failed, 0 otherwise.
func verdict(cycles []CycleResult, failures []Failure, maxInfraRate float64, teardownFailed bool) (int, string) {
	counted := 0
	infraCycles := map[string]bool{}
	for _, f := range failures {
		if f.Class.counts() {
			counted++
		}
		if f.Class == ClassInfra && f.Cycle != "" {
			infraCycles[f.Cycle] = true
		}
	}
	if counted > 0 {
		return 1, fmt.Sprintf("FAIL: %d failure(s) count against the verdict", counted)
	}
	started := 0
	for _, c := range cycles {
		if c.Outcome != outcomeAborted {
			started++
		}
	}
	if started > 0 {
		if rate := float64(len(infraCycles)) / float64(started); rate > maxInfraRate {
			return 2, fmt.Sprintf("FAIL: infra failures in %.1f%% of the cycles, above %.1f%%", rate*100, maxInfraRate*100)
		}
	}
	if teardownFailed {
		return 3, "FAIL: the teardown did not complete"
	}
	return 0, "PASS"
}
