//go:build lab

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func journalLine(fields map[string]string) []byte {
	parts := []string{}
	for k, v := range fields {
		parts = append(parts, fmt.Sprintf("%q:%q", k, v))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

func at(d time.Duration) string { return fmt.Sprint(t0.Add(d).UnixMicro()) }

func TestParseEntry(t *testing.T) {
	e, err := parseEntry("issuer-a", journalLine(map[string]string{
		"__REALTIME_TIMESTAMP": at(time.Second), "__CURSOR": "c1", "_SYSTEMD_UNIT": "openstack-spire-issuer.service",
		"SYSLOG_IDENTIFIER": "openstack-spire-issuer", "_TRANSPORT": "syslog", "PRIORITY": "6",
		"MESSAGE": `{"audit":"token_issued","jti":"j1","instance_id":"i1","kid":"k1"}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Time.Equal(t0.Add(time.Second)) || e.Cursor != "c1" || e.Transport != "syslog" || e.Priority != 6 || e.VM != "issuer-a" {
		t.Errorf("entry %+v", e)
	}
	// journald writes a message that is not valid UTF-8 as an array of bytes
	e, err = parseEntry("spire", []byte(`{"__REALTIME_TIMESTAMP":"1","MESSAGE":[104,105]}`))
	if err != nil || e.Message != "hi" {
		t.Errorf("byte-array message: %q, %v", e.Message, err)
	}
}

func TestLedger(t *testing.T) {
	l := newLedger()
	add := func(vm string, fields map[string]string) {
		e, err := parseEntry(vm, journalLine(fields))
		if err != nil {
			t.Fatal(err)
		}
		l.Add(e)
	}
	add("issuer-a", map[string]string{"__REALTIME_TIMESTAMP": at(0), "SYSLOG_IDENTIFIER": "openstack-spire-issuer", "_TRANSPORT": "syslog",
		"MESSAGE": `{"audit":"token_issued","jti":"j1","instance_id":"i1","kid":"k1"}`})
	add("issuer-a", map[string]string{"__REALTIME_TIMESTAMP": at(time.Second), "_SYSTEMD_UNIT": "openstack-spire-issuer.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time=2026-10-17T12:00:01Z level=ERROR msg="nova lookup failed" instance_id=i2 error="timeout"`})
	// the same record on the issuer's stdout is not a second token
	add("issuer-a", map[string]string{"__REALTIME_TIMESTAMP": at(time.Second), "_SYSTEMD_UNIT": "openstack-spire-issuer.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time=2026-10-17T12:00:01Z level=INFO msg="token issued" audit=token_issued jti=j1 instance_id=i1`})
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(2 * time.Second), "SYSLOG_IDENTIFIER": "openstack-server-plugin", "_TRANSPORT": "syslog",
		"MESSAGE": `{"audit":"agent_attested","jti":"j1","instance_id":"i1","spiffe_id":"spiffe://td/spire/agent/openstack_iid/p/i1","kid":"k1"}`})
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(3 * time.Second), "SYSLOG_IDENTIFIER": "openstack-server-plugin", "_TRANSPORT": "syslog",
		"MESSAGE": `{"audit":"reattest_alert","jti":"j3","previous_jti":"j1","instance_id":"i1"}`})
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(4 * time.Second), "_SYSTEMD_UNIT": "spire-server.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time="2026-10-17T12:00:04Z" level=warning msg="attestation rejected" error="token already used" external=true instance_id=i1 plugin_name=openstack_iid plugin_type=NodeAttestor subsystem_name=catalog`})
	// SPIRE's own record of the same rejection, a moment later: one rejection
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(4*time.Second + 100*time.Millisecond), "_SYSTEMD_UNIT": "spire-server.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time="2026-10-17T12:00:04Z" level=error msg="Failed to attest" error="rpc error: code = PermissionDenied desc = attestation rejected: token already used; a fresh token is needed" node_attestor_type=openstack_iid`})
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(5 * time.Second), "_SYSTEMD_UNIT": "spire-server.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time="2026-10-17T12:00:05Z" level=warning msg="attestation rejected" error="token issued before this server started" external=true instance_id=i4 plugin_name=openstack_iid`})
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(6 * time.Second), "_SYSTEMD_UNIT": "spire-server.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time="2026-10-17T12:00:06Z" level=warning msg="attestation rejected" error="verifying token: unknown kid" external=true instance_id=i5 plugin_name=openstack_iid`})
	// SPIRE Server's own errors unrelated to the plugin do not count
	add("spire", map[string]string{"__REALTIME_TIMESTAMP": at(7 * time.Second), "_SYSTEMD_UNIT": "spire-server.service", "_TRANSPORT": "stdout",
		"MESSAGE": `time="2026-10-17T12:00:07Z" level=error msg="Could not prune" subsystem_name=ca_manager`})

	f := l.Facts()
	if len(f.Tokens) != 1 || f.Tokens[0].JTI != "j1" || f.Tokens[0].VM != "issuer-a" {
		t.Errorf("tokens %+v", f.Tokens)
	}
	if len(f.Attested) != 1 || f.Attested[0].AgentID != "spiffe://td/spire/agent/openstack_iid/p/i1" {
		t.Errorf("attested %+v", f.Attested)
	}
	if len(f.Alerts) != 1 || f.Alerts[0].Instance != "i1" || f.Alerts[0].PrevJTI != "j1" {
		t.Errorf("alerts %+v", f.Alerts)
	}
	kinds := map[string]int{}
	for _, r := range f.Rejections {
		kinds[r.Instance+"/"+r.Kind]++
	}
	if kinds["i1/"+rejectAlreadyUsed] != 1 || kinds["i4/"+rejectBeforeStart] != 1 || kinds["i5/"+rejectOther] != 1 || len(f.Rejections) != 3 {
		t.Errorf("rejections %+v", f.Rejections)
	}
	if len(f.UnknownKID) != 1 || f.UnknownKID[0].Instance != "i5" {
		t.Errorf("unknown kid %+v", f.UnknownKID)
	}
	if len(f.Errors) != 1 || f.Errors[0].Instance != "i2" || f.Errors[0].VM != "issuer-a" {
		t.Errorf("errors %+v", f.Errors)
	}
	if got := l.IssuerProblems("i2"); got != 1 {
		t.Errorf("issuer problems of i2: %d", got)
	}
	if got := l.TokensFor("i1"); got != 1 {
		t.Errorf("tokens of i1: %d", got)
	}
}

func cycle(id string, kind Kind, instance, outcome string) CycleResult {
	return CycleResult{ID: id, Kind: kind, InstanceID: instance, Outcome: outcome}
}

func TestInvariantsClean(t *testing.T) {
	f := Facts{
		Tokens:   []Token{{JTI: "j1", Instance: "i1", VM: "issuer-a"}, {JTI: "j2", Instance: "i2", VM: "issuer-a"}},
		Attested: []Attested{{JTI: "j1", Instance: "i1", AgentID: "a1"}, {JTI: "j2", Instance: "i2", AgentID: "a2"}},
	}
	in := InvariantInputs{Facts: f, Cycles: []CycleResult{cycle("c1", KindCreate, "i1", outcomePassed), cycle("c2", KindRestart, "i2", outcomePassed)}}
	if failures := checkInvariants(in); len(failures) != 0 {
		t.Errorf("failures on the clean case: %+v", failures)
	}
}

func TestInvariantsFlag(t *testing.T) {
	base := func() InvariantInputs {
		return InvariantInputs{
			Facts: Facts{
				Tokens:   []Token{{JTI: "j1", Instance: "i1", VM: "issuer-a"}},
				Attested: []Attested{{JTI: "j1", Instance: "i1", AgentID: "a1", Time: t0}},
			},
			Cycles: []CycleResult{cycle("c1", KindCreate, "i1", outcomePassed), cycle("c2", KindRestart, "i2", outcomePassed)},
		}
	}
	for name, tc := range map[string]struct {
		edit     func(*InvariantInputs)
		want     string
		security bool
	}{
		"attestation without token": {func(in *InvariantInputs) {
			in.Facts.Attested = append(in.Facts.Attested, Attested{JTI: "jx", Instance: "i2", AgentID: "a2"})
		}, "no token_issued", false},
		"jti attested twice": {func(in *InvariantInputs) {
			in.Facts.Attested = append(in.Facts.Attested, Attested{JTI: "j1", Instance: "i1", AgentID: "a1"})
		}, "attested 2 times", true},
		"alert on a create cycle": {func(in *InvariantInputs) {
			in.Facts.Alerts = []Alert{{Instance: "i1", JTI: "j2", PrevJTI: "j1"}}
		}, "reattest_alert", false},
		"alert on a restart cycle whose SVID did not expire": {func(in *InvariantInputs) {
			in.Facts.Alerts = []Alert{{Instance: "i2"}}
		}, "reattest_alert", false},
		"unknown kid": {func(in *InvariantInputs) {
			in.Facts.UnknownKID = []ErrorRecord{{VM: "spire", Message: "unknown kid", Instance: "i9"}}
		}, "unknown kid", false},
		"unexplained error": {func(in *InvariantInputs) {
			in.Facts.Errors = []ErrorRecord{{VM: "issuer-a", Message: "keystone timeout", Time: t0}}
		}, "keystone timeout", false},
		"tofu re-attestation without eviction": {func(in *InvariantInputs) {
			in.TOFU = true
			in.Facts.Tokens = append(in.Facts.Tokens, Token{JTI: "j2", Instance: "i1"})
			in.Facts.Attested = append(in.Facts.Attested, Attested{JTI: "j2", Instance: "i1", AgentID: "a1", Time: t0.Add(time.Minute)})
		}, "without an eviction", true},
		"counter mismatch": {func(in *InvariantInputs) {
			delta := int64(5)
			in.CounterDelta = &delta
		}, "tokens_issued_total", false},
	} {
		t.Run(name, func(t *testing.T) {
			in := base()
			tc.edit(&in)
			failures := checkInvariants(in)
			if len(failures) != 1 {
				t.Fatalf("%d failures, want 1: %+v", len(failures), failures)
			}
			f := failures[0]
			if f.Class != ClassInvariant || !strings.Contains(f.Reason, tc.want) || f.Security != tc.security {
				t.Errorf("failure %+v, want an invariant failure mentioning %q (security %v)", f, tc.want, tc.security)
			}
		})
	}
}

func TestInvariantsExplained(t *testing.T) {
	in := InvariantInputs{
		Facts: Facts{
			Errors: []ErrorRecord{
				{VM: "issuer-a", Message: "nova lookup failed", Instance: "i1", Time: t0},      // a failed cycle's
				{VM: "issuer-a", Message: "peer fetch failed", Time: t0.Add(10 * time.Minute)}, // inside a fault
			},
			Alerts: []Alert{{Instance: "i2"}},
		},
		Cycles: []CycleResult{
			cycle("c1", KindCreate, "i1", outcomeFailed),
			{ID: "c2", Kind: KindRestart, InstanceID: "i2", Outcome: outcomePassed, SVIDExpiredWhileStopped: true},
		},
		Faults: []FaultWindow{{Fault: "restart issuer-b", Start: t0.Add(9 * time.Minute), End: t0.Add(12 * time.Minute)}},
	}
	// the TOFU re-attestation is fine after an eviction
	in.TOFU = true
	in.Facts.Tokens = []Token{{JTI: "j1"}, {JTI: "j2"}}
	in.Facts.Attested = []Attested{{JTI: "j1", AgentID: "a1", Time: t0}, {JTI: "j2", AgentID: "a1", Time: t0.Add(time.Hour)}}
	in.Evictions = map[string][]time.Time{"a1": {t0.Add(30 * time.Minute)}}
	if failures := checkInvariants(in); len(failures) != 1 || !strings.Contains(failures[0].Reason, "reattest_alert") {
		// with TOFU, even an expired SVID must not re-attest: the alert is flagged
		t.Errorf("failures %+v, want only the TOFU restart alert", failures)
	}
	in.TOFU = false
	if failures := checkInvariants(in); len(failures) != 0 {
		t.Errorf("explained records flagged: %+v", failures)
	}
}

func TestClassify(t *testing.T) {
	for name, tc := range map[string]struct {
		e    AttestEvidence
		want Class
	}{
		"plugin rejected":             {AttestEvidence{GuestReachable: true, AgentInstalled: true, PluginRejections: 2}, ClassNode},
		"issuer refused":              {AttestEvidence{IssuerProblems: 1}, ClassNode},
		"token issued, never used":    {AttestEvidence{TokensIssued: 1}, ClassNode},
		"agent running, no token":     {AttestEvidence{GuestReachable: true, AgentInstalled: true}, ClassNode},
		"guest unreachable":           {AttestEvidence{}, ClassInfra},
		"agent never installed":       {AttestEvidence{GuestReachable: true}, ClassInfra},
		"unreachable but plugin said": {AttestEvidence{PluginRejections: 1}, ClassNode},
	} {
		t.Run(name, func(t *testing.T) {
			if got := classifyAttest(tc.e); got != tc.want {
				t.Errorf("classifyAttest(%+v) = %s, want %s", tc.e, got, tc.want)
			}
		})
	}
	if classifyBoot("No valid host was found. There are not enough hosts available.") != ClassCapacity {
		t.Error("NoValidHost is not capacity")
	}
	if classifyBoot("Build of instance aborted: volume error") != ClassInfra {
		t.Error("another fault is not infra")
	}
}

func TestVerdict(t *testing.T) {
	passed := []CycleResult{cycle("c1", KindCreate, "i1", outcomePassed), cycle("c2", KindCreate, "i2", outcomePassed)}
	for name, tc := range map[string]struct {
		cycles   []CycleResult
		failures []Failure
		teardown bool
		want     int
	}{
		"clean":                    {passed, nil, false, 0},
		"harness only":             {passed, []Failure{{Class: ClassHarness}}, false, 0},
		"capacity only":            {passed, []Failure{{Class: ClassCapacity}}, false, 0},
		"node":                     {passed, []Failure{{Class: ClassNode, Cycle: "c1"}}, false, 1},
		"workload":                 {passed, []Failure{{Class: ClassWorkload, Cycle: "c1"}}, false, 1},
		"invariant":                {passed, []Failure{{Class: ClassInvariant}}, false, 1},
		"infra above the rate":     {passed, []Failure{{Class: ClassInfra, Cycle: "c1"}}, false, 2},
		"node wins over infra":     {passed, []Failure{{Class: ClassInfra, Cycle: "c1"}, {Class: ClassNode, Cycle: "c2"}}, false, 1},
		"teardown":                 {passed, nil, true, 3},
		"failure wins on teardown": {passed, []Failure{{Class: ClassNode}}, true, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if got, _ := verdict(tc.cycles, tc.failures, 0.05, tc.teardown); got != tc.want {
				t.Errorf("verdict = %d, want %d", got, tc.want)
			}
		})
	}
	// 1 infra failure in 40 cycles is 2.5%, under 5%
	many := make([]CycleResult, 40)
	for i := range many {
		many[i] = cycle(fmt.Sprint("c", i), KindCreate, "", outcomePassed)
	}
	if got, _ := verdict(many, []Failure{{Class: ClassInfra, Cycle: "c3"}}, 0.05, false); got != 0 {
		t.Errorf("verdict = %d for an infra rate under the threshold", got)
	}
}

func TestNovaProblem(t *testing.T) {
	// as nova-api-metadata logs a failed dynamic vendordata call (the lab,
	// Oct 17): the level is the first word, the journald priority is info
	warning := "WARNING nova.api.metadata.vendordata_dynamic [\x1b[01;36mNone req-84f8 \x1b[00;36mNone None] \x1b[01;35m[instance: b18fd058-0517-4698-9385-481ea1c252e1] Error from dynamic vendordata service openstack_iid at https://issuer-a.lab:8443/attest: Unable to establish connection"
	l := newLedger()
	l.Add(Entry{VM: "devstack", Unit: "devstack@n-api-meta.service", Priority: 6, Message: warning, Time: t0})
	l.Add(Entry{VM: "devstack", Unit: "devstack@n-api-meta.service", Priority: 6, Time: t0,
		Message: "DEBUG nova.api.metadata.handler [None req-7d23] Metadata request headers: vendordata"})
	l.Add(Entry{VM: "devstack", Unit: "devstack@n-api-meta.service", Priority: 6, Time: t0,
		Message: "[pid: 92594|app: 0] 10.250.0.10 () GET /openstack/latest/vendor_data2.json => generated 35 bytes (HTTP/1.1 200)"})
	f := l.Facts()
	if len(f.NovaProblems) != 1 || len(f.NovaProblems[0].Instances) != 1 || f.NovaProblems[0].Instances[0] != "b18fd058-0517-4698-9385-481ea1c252e1" {
		t.Errorf("nova problems %+v, want the one warning with its instance", f.NovaProblems)
	}
}
