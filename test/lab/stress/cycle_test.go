//go:build lab

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLab is a lab whose instances boot, attest and serve SVIDs after short
// delays, unless told otherwise.
type fakeLab struct {
	mu        sync.Mutex
	n         int
	servers   map[string]*fakeServer
	agents    map[string]AgentInfo
	evicted   []string
	bootFault string // instances go to ERROR with this fault
	noAttest  bool   // agents never attest
	outsider  bool   // the outsider gets an SVID
	reachable bool
	onStart   func(id string) // called when an instance starts again
	delay     time.Duration
}

type fakeServer struct {
	Server
	since   time.Time // of the current transition
	target  string    // the status it reaches after delay
	deleted bool
}

const fakeProject, fakeTD = "p", "openstack.lab"

func newFakeLab() *fakeLab {
	return &fakeLab{servers: map[string]*fakeServer{}, agents: map[string]AgentInfo{}, reachable: true, delay: 20 * time.Millisecond}
}

func (f *fakeLab) agentID(id string) string {
	return fmt.Sprintf("spiffe://%s/spire/agent/openstack_iid/%s/%s", fakeTD, fakeProject, id)
}

func (f *fakeLab) CreateServer(ctx context.Context, name, distro string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("i%d", f.n)
	target := "ACTIVE"
	if f.bootFault != "" {
		target = "ERROR"
	}
	f.servers[id] = &fakeServer{Server: Server{ID: id, Name: name, Status: "BUILD", Address: "10.0.0.9"}, since: time.Now(), target: target}
	return id, nil
}

func (f *fakeLab) ServerAction(ctx context.Context, id, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok {
		return errors.New("no such server")
	}
	s.since = time.Now()
	switch action {
	case "stop":
		s.target = "SHUTOFF"
	case "start":
		s.target = "ACTIVE"
		if f.onStart != nil {
			f.onStart(id)
		}
	case "delete":
		s.deleted = true
	}
	return nil
}

func (f *fakeLab) ServerFault(ctx context.Context, id string) (string, error) {
	return f.bootFault, nil
}

func (f *fakeLab) ListServers(ctx context.Context) ([]Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Server
	for id, s := range f.servers {
		if time.Since(s.since) > f.delay {
			if s.deleted {
				delete(f.servers, id)
				continue
			}
			s.Status = s.target
			if s.Status == "ACTIVE" && !f.noAttest {
				if _, ok := f.agents[f.agentID(id)]; !ok {
					f.agents[f.agentID(id)] = AgentInfo{ID: f.agentID(id), Serial: "1", ExpiresAt: time.Now().Add(time.Hour),
						Selectors: []string{"openstack_iid:project_id:" + fakeProject, "openstack_iid:instance_id:" + id}}
				}
			}
		}
		out = append(out, s.Server)
	}
	return out, nil
}

func (f *fakeLab) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AgentInfo
	for _, a := range f.agents {
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeLab) EvictAgent(ctx context.Context, agentID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.agents, agentID)
	f.evicted = append(f.evicted, agentID)
	return nil
}

func (f *fakeLab) CheckWorkload(ctx context.Context, s Server, distro string) WorkloadCheck {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.reachable {
		return WorkloadCheck{Error: "connection timed out"}
	}
	c := WorkloadCheck{Reachable: true, WorkloadID: "spiffe://" + fakeTD + "/stress/workload", Verified: true, OutsiderErr: "no identity issued"}
	if f.outsider {
		c.OutsiderID = "spiffe://" + fakeTD + "/stress/workload"
	}
	return c
}

func (f *fakeLab) GuestState(ctx context.Context, s Server, distro string) GuestState {
	return GuestState{Reachable: f.reachable, AgentInstalled: true, AgentActive: true, Output: "agent journal"}
}

func (f *fakeLab) ConsoleLog(ctx context.Context, id string) (string, error) { return "console", nil }
func (f *fakeLab) AgentShow(ctx context.Context, id string) (string, error)  { return "agent", nil }
func (f *fakeLab) Stream(ctx context.Context, vm, command string) (io.ReadCloser, error) {
	return nil, errors.New("no journals")
}

func (f *fakeLab) alive() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.servers)
}

type fakeRun struct {
	runner *Runner
	lab    *fakeLab
	stop   context.CancelFunc
}

func newFakeRun(t *testing.T, lab *fakeLab, edit func(*RunOptions)) *fakeRun {
	t.Helper()
	cfg := testConfig(t, func(o *RunOptions) {
		o.Bound = "boot=1s,attest=300ms,svid=300ms,stop=1s,start=1s,back=500ms,delete=1s"
		o.Hold, o.KeepFailed = "0s", 0
		if edit != nil {
			edit(o)
		}
	})
	rec, err := newRecorder(t.TempDir(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rec.Close)
	faults := &Faults{}
	obs := newObserver(lab, faults, 10*time.Millisecond, rec.log, rec.Harness)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go obs.Run(ctx)
	ledger := newLedger()
	return &fakeRun{lab: lab, stop: cancel, runner: &Runner{
		cfg: cfg, lab: lab, obs: obs, ledger: ledger, faults: faults, journals: newJournals(lab, t.TempDir(), ledger, time.Now(), rec.log),
		rec: rec, log: rec.log, runID: "test", projectID: fakeProject, trustDomain: fakeTD, agentTTL: time.Hour,
		pollEvery: 10 * time.Millisecond, evictions: map[string][]time.Time{},
	}}
}

func TestCreateCyclePasses(t *testing.T) {
	lab := newFakeLab()
	f := newFakeRun(t, lab, nil)
	res := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindCreate, Distro: "ubuntu"})
	if res.Outcome != outcomePassed || res.Failure != nil {
		t.Fatalf("cycle %s: %+v", res.Outcome, res.Failure)
	}
	var steps []string
	for _, s := range res.Steps {
		steps = append(steps, s.Step)
	}
	if got := strings.Join(steps, ","); got != "boot,attest,svid,svid,delete" {
		t.Errorf("steps %s", got)
	}
	if lab.alive() != 0 || len(lab.evicted) != 1 || lab.evicted[0] != res.AgentID {
		t.Errorf("instance left (%d) or agent not evicted (%v)", lab.alive(), lab.evicted)
	}
	if !strings.HasPrefix(res.Name, "stress-test-c0001-ubuntu") {
		t.Errorf("name %s", res.Name)
	}
}

func TestCycleFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		edit     func(*fakeLab)
		class    Class
		step     string
		security bool
	}{
		"not attested, agent running": {func(l *fakeLab) { l.noAttest = true }, ClassNode, StepAttest, false},
		"not attested, unreachable":   {func(l *fakeLab) { l.noAttest, l.reachable = true, false }, ClassInfra, StepAttest, false},
		"outsider gets an SVID":       {func(l *fakeLab) { l.outsider = true }, ClassWorkload, StepSVID, true},
		"no valid host":               {func(l *fakeLab) { l.bootFault = "No valid host was found." }, ClassCapacity, StepBoot, false},
		"boot fault":                  {func(l *fakeLab) { l.bootFault = "Build of instance aborted" }, ClassInfra, StepBoot, false},
	} {
		t.Run(name, func(t *testing.T) {
			lab := newFakeLab()
			tc.edit(lab)
			f := newFakeRun(t, lab, nil)
			res := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindCreate, Distro: "rhel"})
			if res.Outcome != outcomeFailed || res.Failure == nil {
				t.Fatalf("outcome %s, want failed", res.Outcome)
			}
			if res.Failure.Class != tc.class || res.Failure.Step != tc.step || res.Failure.Security != tc.security {
				t.Errorf("failure %+v, want class %s at %s (security %v)", res.Failure, tc.class, tc.step, tc.security)
			}
			if res.Failure.Evidence == "" {
				t.Error("no evidence directory")
			}
			if lab.alive() != 0 {
				t.Error("the failed instance was not deleted (keep-failed 0)")
			}
			if got := f.runner.rec.Failures(); len(got) != 1 {
				t.Errorf("%d failures recorded, want 1", len(got))
			}
		})
	}
}

func TestFailedInstanceKept(t *testing.T) {
	lab := newFakeLab()
	lab.noAttest = true
	f := newFakeRun(t, lab, func(o *RunOptions) { o.KeepFailed = 1 })
	first := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindCreate, Distro: "ubuntu"})
	second := f.runner.Cycle(context.Background(), "c0002", Plan{Kind: KindCreate, Distro: "ubuntu"})
	if !first.Kept || second.Kept || lab.alive() != 1 {
		t.Errorf("kept %v and %v, %d alive: want only the first kept", first.Kept, second.Kept, lab.alive())
	}
}

func TestRestartCycle(t *testing.T) {
	lab := newFakeLab()
	f := newFakeRun(t, lab, nil)
	res := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindRestart, Distro: "ubuntu"})
	if res.Outcome != outcomePassed {
		t.Fatalf("cycle %s: %+v", res.Outcome, res.Failure)
	}
	var steps []string
	for _, s := range res.Steps {
		steps = append(steps, s.Step)
	}
	if got := strings.Join(steps, ","); got != "boot,attest,svid,stop,start,back,delete" {
		t.Errorf("steps %s", got)
	}
	if res.Reattested {
		t.Error("re-attested with a valid SVID")
	}
}

func TestRestartCycleAttestingAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		tofu     bool
		security bool
	}{"default": {false, false}, "tofu": {true, true}} {
		t.Run(name, func(t *testing.T) {
			lab := newFakeLab()
			f := newFakeRun(t, lab, func(o *RunOptions) { o.TOFU = tc.tofu })
			// the agent attests again when its instance starts, its SVID valid
			lab.onStart = func(id string) {
				f.runner.ledger.Add(Entry{Transport: "syslog", Ident: "openstack-server-plugin", Time: time.Now(),
					Message: fmt.Sprintf(`{"audit":"agent_attested","jti":"j2","instance_id":%q}`, id)})
			}
			res := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindRestart, Distro: "ubuntu"})
			if res.Failure == nil || res.Failure.Class != ClassNode || res.Failure.Step != StepBack || res.Failure.Security != tc.security {
				t.Errorf("failure %+v, want a node failure at back (security %v)", res.Failure, tc.security)
			}
		})
	}
}

func TestAbortedCycle(t *testing.T) {
	lab := newFakeLab()
	lab.noAttest = true
	f := newFakeRun(t, lab, func(o *RunOptions) { o.Bound = "attest=1h" })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	res := f.runner.Cycle(ctx, "c0001", Plan{Kind: KindCreate, Distro: "ubuntu"})
	if res.Outcome != outcomeAborted || res.Failure != nil {
		t.Errorf("outcome %s, failure %+v; want aborted without a failure", res.Outcome, res.Failure)
	}
	if lab.alive() != 0 {
		t.Error("the aborted cycle's instance was not deleted")
	}
}

func TestCapacityFailureNotKept(t *testing.T) {
	lab := newFakeLab()
	lab.bootFault = "No valid host was found."
	f := newFakeRun(t, lab, func(o *RunOptions) { o.KeepFailed = 3 })
	res := f.runner.Cycle(context.Background(), "c0001", Plan{Kind: KindCreate, Distro: "rhel"})
	if res.Kept || lab.alive() != 0 {
		t.Errorf("a capacity failure was kept (kept %v, %d alive)", res.Kept, lab.alive())
	}
}

func TestRejectionsAfterASpireRestart(t *testing.T) {
	lab := newFakeLab()
	f := newFakeRun(t, lab, nil)
	restart := time.Now()
	f.runner.faults.windows = []FaultWindow{{Fault: faultRestartSpire, Start: restart, Healthy: restart.Add(3 * time.Second), End: restart.Add(time.Minute)}}
	c := &cycleState{res: &CycleResult{InstanceID: "i1"}, start: restart.Add(-time.Minute)}
	reject := func(at time.Time, kind string) {
		f.runner.ledger.mu.Lock()
		f.runner.ledger.facts.Rejections = append(f.runner.ledger.facts.Rejections, Rejection{Instance: "i1", Kind: kind, Time: at})
		f.runner.ledger.mu.Unlock()
	}
	// the startup watermark refuses every attempt for clock_skew_tolerance
	for i := range 6 {
		reject(restart.Add(time.Duration(5+5*i)*time.Second), rejectBeforeStart)
	}
	if err := f.runner.checkRejections(c); err != nil {
		t.Errorf("rejections of the startup watermark within the restart flagged: %v", err)
	}
	// outside a restart, the same rejections count: the cycle spans one
	// restart, so two are allowed (spec, chaos)
	reject(restart.Add(-30*time.Second), rejectBeforeStart)
	reject(restart.Add(-20*time.Second), rejectAlreadyUsed)
	if err := f.runner.checkRejections(c); err != nil {
		t.Errorf("two transient rejections outside the restart, two allowed, flagged: %v", err)
	}
	reject(restart.Add(-10*time.Second), rejectAlreadyUsed)
	if err := f.runner.checkRejections(c); err == nil {
		t.Error("three transient rejections outside the restart, two allowed, not flagged")
	}
}
