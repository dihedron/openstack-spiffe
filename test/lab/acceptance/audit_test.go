//go:build lab

package acceptance

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// syslogEntry is a journald entry received through the syslog socket.
type syslogEntry struct {
	Identifier string         `json:"SYSLOG_IDENTIFIER"`
	Facility   string         `json:"SYSLOG_FACILITY"`
	Priority   string         `json:"PRIORITY"`
	Message    string         `json:"MESSAGE"`
	record     map[string]any // MESSAGE, decoded
}

// syslogAudit returns the audit records an issuer sent to syslog since a
// journalctl time specification, as journald recorded them.
func (l *lab) syslogAudit(t *testing.T, vm, since string) []syslogEntry {
	t.Helper()
	out := l.must(t, vm, "sudo journalctl _TRANSPORT=syslog SYSLOG_IDENTIFIER=openstack-spire-issuer --no-pager -o json --since "+quote(since))
	var entries []syslogEntry
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var e syslogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal entry %s: %v", line, err)
		}
		if err := json.Unmarshal([]byte(e.Message), &e.record); err != nil {
			t.Errorf("syslog MESSAGE is not a JSON object (journald did not parse the header?): %q", e.Message)
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

var jtiOf = regexp.MustCompile(`audit=token_issued .*\bjti=(\S+)`)

// checkSyslogAudit checks, for the tokens issuer-a issued to a guest since a
// time, that each has exactly one syslog entry, parsed by journald, with the
// authpriv facility, the info severity and the token's jti; and that the
// tokens were requested by the dedicated vendordata user.
func (l *lab) checkSyslogAudit(t *testing.T, g guest, since string) {
	t.Helper()
	var jtis []string
	for _, m := range jtiOf.FindAllStringSubmatch(l.issuerLog(t, "issuer-a", since, "_TRANSPORT=stdout -o cat"), -1) {
		if strings.Contains(m[0], "instance_id="+g.id) {
			jtis = append(jtis, m[1])
		}
	}
	if len(jtis) == 0 {
		t.Fatalf("issuer-a's log has no token_issued record for %s", g.id)
	}
	entries := l.syslogAudit(t, "issuer-a", since)
	for _, jti := range jtis {
		var found []syslogEntry
		for _, e := range entries {
			if e.record["audit"] == "token_issued" && e.record["jti"] == jti {
				found = append(found, e)
			}
		}
		if len(found) != 1 {
			t.Errorf("jti %s: %d syslog entries, want exactly 1", jti, len(found))
			continue
		}
		e := found[0]
		if e.Facility != "10" || e.Priority != "6" || e.record["instance_id"] != g.id || e.record["time"] == nil {
			t.Errorf("jti %s: facility %s, priority %s, record %v; want authpriv (10), info (6), the instance and the time", jti, e.Facility, e.Priority, e.record)
		}
		// S-3: Nova calls as the dedicated user
		if e.record["user_id"] != l.env.OpenStack.VendordataUserID {
			t.Errorf("jti %s: requested by %v, not by nova-vendordata (%s)", jti, e.record["user_id"], l.env.OpenStack.VendordataUserID)
		}
	}
	t.Logf("%d tokens for %s, each with its syslog entry", len(jtis), g.id)
}

// TestSyslogAudit is AUD-1: under the packaged unit, every token issued for
// a guest reaches journald through /dev/log as one parsed audit entry, and
// the active key's lifecycle is there too.
func TestSyslogAudit(t *testing.T) {
	l := theLab
	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	g := l.bootGuest(t, "ubuntu", "demo")
	l.waitAttested(t, l.agentID(g, l.env.OpenStack.ProjectID), "", attestTimeout)
	l.checkSyslogAudit(t, g, since)

	events := map[string]bool{}
	for _, e := range l.syslogAudit(t, "issuer-a", "-2days") {
		if e.record["audit"] == "key_lifecycle" {
			events[e.record["event"].(string)] = true
		}
	}
	for _, event := range []string{"generated", "published", "active"} {
		if !events[event] {
			t.Errorf("no key_lifecycle %s entry in issuer-a's syslog", event)
		}
	}
}

// TestLogLevelOff is AUD-2: with OPENSTACK_SPIRE_ISSUER_LOG_LEVEL=off, the
// syslog audit trail is still complete, and the unit's own output still
// carries the audit records but no ordinary record.
func TestLogLevelOff(t *testing.T) {
	l := theLab
	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	l.editIssuerFile(t, "issuer-a", "/etc/openstack-spire-issuer/signer.env", func(env string) string {
		return env + "OPENSTACK_SPIRE_ISSUER_LOG_LEVEL=off\n"
	})
	g := l.bootGuest(t, "ubuntu", "demo")
	l.waitAttested(t, l.agentID(g, l.env.OpenStack.ProjectID), "", attestTimeout)
	l.checkSyslogAudit(t, g, since)

	// the output of the process started with the level off (not the
	// previous one's shutdown, logged at the default level)
	pid := strings.TrimSpace(l.must(t, "issuer-a", "systemctl show -p MainPID --value openstack-spire-issuer"))
	output := l.issuerLog(t, "issuer-a", since, "_TRANSPORT=stdout _PID="+pid+" -o cat")
	if !strings.Contains(output, "audit=token_issued") {
		t.Errorf("the unit's output (PID %s) has no audit record", pid)
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line != "" && !strings.Contains(line, " audit=") {
			t.Errorf("an ordinary record despite the level off: %s", line)
			break
		}
	}
}
