//go:build lab

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dihedron/openstack-spiffe/test/lab/labkit"
)

// Exit statuses (spec, records and report).
const (
	exitPass     = 0
	exitFail     = 1
	exitInfra    = 2
	exitLabSetup = 3
)

const (
	drainTimeout   = 15 * time.Minute
	startSpacing   = 10 * time.Second
	sampleEvery    = time.Minute
	readinessEvery = 30 * time.Second
	pollInterval   = 5 * time.Second
	selfTestLength = 25 * time.Minute
	selfTestAttest = 2 * time.Minute
)

// run is "stress run": the whole lifecycle; it returns the exit status.
func run(o RunOptions, durationSet, attestBoundSet bool) int {
	cfg, err := o.Validate(rand.Uint64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitLabSetup
	}
	if cfg.SelfTest {
		if !durationSet {
			cfg.Duration = selfTestLength
		}
		if !attestBoundSet {
			cfg.Bounds[StepAttest] = selfTestAttest
		}
	}
	kit, err := labkit.Load(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitLabSetup
	}
	started := time.Now().UTC()
	runID := strings.ToLower(started.Format("0102-150405"))
	if cfg.Out == "" {
		cfg.Out = filepath.Join(cfg.StateDir, "stress", started.Format("20060102T150405Z"))
	}
	rec, err := newRecorder(cfg.Out, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitLabSetup
	}
	defer rec.Close()
	r := &stressRun{cfg: cfg, kit: kit, lab: &kitLab{kit: kit}, rec: rec, log: rec.log, runID: runID, started: started}
	return r.lifecycle()
}

type stressRun struct {
	cfg     *Config
	kit     *labkit.Lab
	lab     *kitLab
	rec     *Recorder
	log     *slog.Logger
	runID   string
	started time.Time
	info    map[string]any

	faults   *Faults
	ledger   *Ledger
	journals *Journals
	obs      *Observer
	runner   *Runner
	setup    *Setup
	pending  *Pending

	target   atomic.Int32
	active   atomic.Int32
	issuerA  atomic.Bool  // issuer-a restarted during the run: its counter restarted
	held     atomic.Int32 // instances outside the cycles (the self-test's TOFU guest)
	samples  []Sample
	sampleMu sync.Mutex
	selfTest *selfTest
}

func (r *stressRun) repoDir() string {
	if r.cfg.LabDir != "" {
		return filepath.Join(r.cfg.LabDir, "..", "..")
	}
	return "."
}

func (r *stressRun) commit() string {
	out, err := exec.Command("git", "-C", r.repoDir(), "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	commit := strings.TrimSpace(string(out))
	if exec.Command("git", "-C", r.repoDir(), "diff", "--quiet", "HEAD").Run() != nil {
		commit += "+changes"
	}
	return commit
}

func (r *stressRun) writeRunInfo() {
	if err := r.rec.WriteJSON("run.json", r.info); err != nil {
		r.log.Error("writing run.json", "error", err)
	}
}

func (r *stressRun) lifecycle() int {
	r.info = map[string]any{
		"run_id": r.runID, "started": r.started.Format(time.RFC3339), "seed": r.cfg.Seed,
		"commit": r.commit(), "options": strings.Join(os.Args[1:], " "), "config": r.cfg.RunOptions,
		"bounds": r.cfg.Bounds, "versions": r.kit.Env.Versions, "dir": r.cfg.Out,
	}
	r.writeRunInfo()
	r.log.Info("stress run", "run_id", r.runID, "dir", r.cfg.Out, "seed", r.cfg.Seed, "duration", r.cfg.Duration.String())

	// 1. prepare the lab
	if err := r.prepare(); err != nil {
		r.log.Error("preparing the lab", "error", err)
		return exitLabSetup
	}
	kit, err := labkit.Load(r.cfg.StateDir) // deploy updates env.json
	if err != nil {
		r.log.Error("reading the lab", "error", err)
		return exitLabSetup
	}
	r.kit, r.lab = kit, &kitLab{kit: kit}
	r.info["versions"], r.info["deployed"] = kit.Env.Versions, kit.Env.Deployed
	r.writeRunInfo()

	root := context.Background()
	r.setup = &Setup{cfg: r.cfg, kit: r.kit, lab: r.lab, log: r.log}

	// 2. check the lab
	if err := r.setup.Check(root); err != nil {
		r.log.Error("the lab is not ready for a run", "error", err)
		return exitLabSetup
	}

	// signals: the first drains, the second aborts
	startCtx, stopStarting := context.WithTimeout(root, r.cfg.Duration)
	defer stopStarting()
	runCtx, abort := context.WithCancel(root)
	defer abort()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		r.log.Warn("signal: draining (again to abort)")
		stopStarting()
		<-signals
		r.log.Warn("signal: aborting the running cycles")
		abort()
	}()

	// 3. set up
	r.pending = &Pending{RunID: r.runID}
	r.faults = &Faults{}
	maxRunning := r.cfg.MaxParallel
	if !r.cfg.Auto {
		maxRunning = r.cfg.Fixed
	}
	setUp := r.faults.begin(faultSetUp, false, time.Now())
	err = r.setup.Up(root, r.pending, maxRunning+r.cfg.KeepFailed+2)
	r.faults.healed(setUp, time.Now(), err)
	if err != nil {
		r.log.Error("setting up the run", "error", err)
		if derr := r.setup.Down(root, r.pending); derr != nil {
			r.log.Error("undoing the set-up", "error", derr)
		}
		return exitLabSetup
	}
	r.info["changes"] = r.pending
	r.writeRunInfo()
	counterStart, counterErr := r.lab.TokensIssued(root)

	// followers: journals, the observer, samples, readiness, faults
	r.ledger = newLedger()
	followCtx, stopFollowing := context.WithCancel(root)
	defer stopFollowing()
	var followers sync.WaitGroup
	r.journals = newJournals(r.lab, filepath.Join(r.cfg.Out, "journals"), r.ledger, time.Now().Add(-5*time.Second), r.log)
	followers.Add(1)
	go func() {
		defer followers.Done()
		if err := r.journals.Run(followCtx); err != nil {
			r.rec.Harness("following the journals: " + err.Error())
		}
	}()
	r.obs = newObserver(r.lab, r.faults, pollInterval, r.log, r.rec.Harness)
	followers.Add(1)
	go func() { defer followers.Done(); r.obs.Run(followCtx) }()
	agentTTL := r.cfg.AgentTTL
	if agentTTL == 0 {
		agentTTL = time.Hour // SPIRE Server's default
	}
	r.runner = &Runner{cfg: r.cfg, lab: r.lab, obs: r.obs, ledger: r.ledger, faults: r.faults, journals: r.journals, rec: r.rec,
		log: r.log, runID: r.runID, projectID: r.kit.Env.OpenStack.ProjectID, trustDomain: r.kit.Env.Spire.TrustDomain,
		agentTTL: agentTTL, pollEvery: pollInterval, evictions: map[string][]time.Time{}}
	if _, err := r.obs.Wait(runCtx, time.Now(), 2*time.Minute, time.Now(), func(Snapshot) bool { return true }); err != nil {
		r.rec.Harness("the observer got no snapshot within 2 minutes: " + err.Error())
	}
	r.updateTarget(root, true)
	followers.Add(2)
	go func() { defer followers.Done(); r.sampleLoop(followCtx) }()
	go func() { defer followers.Done(); r.readinessLoop(followCtx) }()
	var injectors sync.WaitGroup
	if r.cfg.Chaos {
		injectors.Add(1)
		go func() { defer injectors.Done(); r.chaos(startCtx, root) }()
	}
	if r.cfg.SelfTest {
		r.selfTest = &selfTest{r: r}
		injectors.Add(1)
		go func() { defer injectors.Done(); r.selfTest.inject(startCtx, root) }()
	}

	// 4. run
	runStart := time.Now()
	r.info["run_started"] = runStart.Format(time.RFC3339)
	var cycles sync.WaitGroup
	chooser := newChooser(r.cfg)
	adm := &admission{spacing: startSpacing}
	n := 0
	ticker := time.NewTicker(time.Second)
schedule:
	for {
		select {
		case <-startCtx.Done():
			break schedule
		case now := <-ticker.C:
			if r.cfg.Cycles > 0 && n >= r.cfg.Cycles {
				break schedule
			}
			if !adm.admit(int(r.active.Load()), int(r.target.Load()), now) {
				continue
			}
			n++
			id, plan := fmt.Sprintf("c%04d", n), chooser.next()
			r.active.Add(1)
			cycles.Add(1)
			go func() {
				defer cycles.Done()
				defer r.active.Add(-1)
				res := r.runner.Cycle(runCtx, id, plan)
				r.rec.Cycle(res)
				if res.Failure != nil && res.Failure.Class == ClassCapacity && r.cfg.Auto {
					r.target.Store(max(r.target.Load()-1, 1))
				}
			}()
		}
	}
	ticker.Stop()
	stopStarting()

	// 5. drain
	r.log.Info("draining: no new cycles", "started", n, "running", r.active.Load())
	drained := make(chan struct{})
	go func() { cycles.Wait(); injectors.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainTimeout):
		r.log.Warn("the drain timed out: aborting the running cycles")
		abort()
		<-drained
	}
	runEnd := time.Now()
	r.info["run_ended"] = runEnd.Format(time.RFC3339)

	// 6. tear down: the run's instances, then the run-wide checks on the
	// journals (stopped before the restore restarts services), then the
	// changes
	teardownFailed := false
	kept := map[string]bool{}
	var keptNames []string
	for _, c := range r.rec.Cycles() {
		if c.Kept {
			kept[c.InstanceID] = true
			keptNames = append(keptNames, c.Name)
		}
	}
	if err := r.deleteRunInstances(root, kept); err != nil {
		r.log.Error("deleting the run's instances", "error", err)
		teardownFailed = true
	}
	if err := r.setup.recordKept(keptNames); err != nil {
		r.log.Error("recording the kept instances", "error", err)
	}
	// let the journals catch up with the last records
	time.Sleep(10 * time.Second)
	stopFollowing()
	followers.Wait()

	var delta *int64
	if counterEnd, err := r.lab.TokensIssued(root); err == nil && counterErr == nil && !r.issuerA.Load() {
		d := counterEnd - counterStart
		delta = &d
	}
	facts := r.ledger.Facts()
	for _, f := range checkInvariants(InvariantInputs{Facts: facts, Cycles: r.rec.Cycles(), Faults: r.faults.Windows(),
		Evictions: r.runner.Evictions(), TOFU: r.cfg.TOFU, CounterDelta: delta}) {
		r.rec.Failure(f)
	}
	if err := r.setup.Down(root, r.pending); err != nil {
		r.log.Error("undoing the run's changes", "error", err)
		teardownFailed = true
	}
	r.info["ended"] = time.Now().UTC().Format(time.RFC3339)
	r.writeRunInfo()

	var st *SelfTestResult
	if r.selfTest != nil {
		st = r.selfTest.evaluate(r.rec.Cycles(), r.rec.Failures(), facts, r.faults.Windows())
	}
	r.sampleMu.Lock()
	samples := append([]Sample(nil), r.samples...)
	r.sampleMu.Unlock()
	report := buildReport(ReportInputs{Run: r.info, Cycles: r.rec.Cycles(), Failures: r.rec.Failures(), Bounds: r.cfg.Bounds,
		MaxInfraRate: r.cfg.MaxInfraRate, TeardownFailed: teardownFailed, Samples: samples, Serials: r.obs.SerialChanges(),
		Faults: r.faults.Windows(), SelfTest: st})
	if err := r.rec.WriteJSON("report.json", report); err != nil {
		r.log.Error("writing the report", "error", err)
	}
	text := report.Text()
	if err := os.WriteFile(filepath.Join(r.cfg.Out, "report.txt"), []byte(text), 0o644); err != nil {
		r.log.Error("writing the report", "error", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "\n%s\nRecords: %s\n", text, r.cfg.Out)
	return report.Status
}

// prepare runs lab.sh reset and deploy, unless skipped.
func (r *stressRun) prepare() error {
	log, err := os.Create(filepath.Join(r.cfg.Out, "prepare.log"))
	if err != nil {
		return fmt.Errorf("creating prepare.log: %w", err)
	}
	defer func() { _ = log.Close() }()
	for _, step := range []struct {
		command string
		skip    bool
	}{{"reset", r.cfg.NoReset}, {"deploy", r.cfg.NoDeploy}} {
		if step.skip {
			r.log.Info("skipped", "command", "lab.sh "+step.command)
			continue
		}
		r.log.Info("preparing the lab", "command", "lab.sh "+step.command)
		cmd := exec.Command(filepath.Join(r.cfg.LabDir, "lab.sh"), step.command)
		cmd.Env = append(os.Environ(), "LAB_ASSUME_YES=1")
		cmd.Stdout = io.MultiWriter(log, os.Stderr)
		cmd.Stderr = cmd.Stdout
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("lab.sh %s: %w (see prepare.log)", step.command, err)
		}
	}
	return nil
}

// deleteRunInstances deletes what is left of the run's instances (aborted
// cycles), keeping the kept failures, and evicts their agents.
func (r *stressRun) deleteRunInstances(ctx context.Context, kept map[string]bool) error {
	servers, err := r.lab.ListServers(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range servers {
		if !strings.HasPrefix(s.Name, stressPrefix+r.runID+"-") || kept[s.ID] {
			continue
		}
		r.log.Warn("deleting a run instance left behind", "name", s.Name)
		if _, err := r.lab.demo(ctx, "server", "delete", "--wait", s.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.lab.EvictAgent(ctx, r.runner.agentID(s.ID)); err != nil && !strings.Contains(err.Error(), "NotFound") && !strings.Contains(err.Error(), "not found") {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// --- Parallelism and samples -------------------------------------------------------------

// keptCount is the number of instances that hold capacity outside the
// cycles: the failed instances kept so far, and the self-test's TOFU guest.
func (r *stressRun) keptCount() int {
	n := int(r.held.Load())
	for _, c := range r.rec.Cycles() {
		if c.Kept {
			n++
		}
	}
	return n
}

// running is the run's instances that cycles hold: not those in ERROR,
// which Placement does not count, nor kept failures, whose capacity is
// already out of Placement's free slots and is not the cycles' to use.
func (r *stressRun) running() int {
	kept := map[string]bool{}
	for _, c := range r.rec.Cycles() {
		if c.Kept {
			kept[c.InstanceID] = true
		}
	}
	n := 0
	for _, s := range r.obs.Snapshot().Servers {
		if strings.HasPrefix(s.Name, stressPrefix+r.runID+"-") && !strings.HasSuffix(s.Name, tofuGuestSuffix) && s.Status != "ERROR" && !kept[s.ID] {
			n++
		}
	}
	return n
}

func (r *stressRun) updateTarget(ctx context.Context, first bool) Sample {
	s := Sample{Time: time.Now(), Running: r.running(), Active: int(r.active.Load()), HostAvailMiB: hostMemAvailMiB(), HostLoad: hostLoad()}
	var err error
	var total int
	s.PlacementFree, total, s.DevstackAvailMiB, err = r.lab.Capacity(ctx, labGuest)
	if err != nil {
		r.log.Warn("probing the capacity", "error", err)
	}
	if !r.cfg.Auto {
		r.target.Store(int32(r.cfg.Fixed))
	} else {
		desired, pressure := capacityTarget(Capacity{Max: r.cfg.MaxParallel, Running: s.Running, PlacementFree: s.PlacementFree,
			PlacementTotal: total, Kept: r.keptCount(),
			DevstackAvailMiB: s.DevstackAvailMiB, FlavorRAMMiB: labGuest.RAMMiB, HostAvailMiB: s.HostAvailMiB, HostLoad: s.HostLoad, HostCPUs: runtime.NumCPU()})
		next := nextTarget(int(r.target.Load()), desired, pressure, first)
		if int32(next) != r.target.Load() || first {
			r.log.Info("parallelism target", "target", next, "capacity", desired, "host_pressure", pressure,
				"placement_free", s.PlacementFree, "devstack_mem_available_mib", s.DevstackAvailMiB)
		}
		r.target.Store(int32(next))
	}
	s.Target = int(r.target.Load())
	return s
}

func (r *stressRun) sampleLoop(ctx context.Context) {
	ticker := time.NewTicker(sampleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s := r.updateTarget(ctx, false)
		s.RSS = map[string]int64{}
		for vm, names := range map[string][]string{
			"issuer-a": {"openstack-spire-issuer"}, "issuer-b": {"openstack-spire-issuer"},
			"spire": {"spire-server", "openstack-server-plugin"},
		} {
			rss, err := r.lab.RSS(ctx, vm, names...)
			if err != nil {
				r.log.Warn("sampling the memory", "vm", vm, "error", err)
				continue
			}
			for name, kb := range rss {
				s.RSS[vm+"/"+name] = kb
			}
		}
		r.rec.Sample(s)
		r.sampleMu.Lock()
		r.samples = append(r.samples, s)
		r.sampleMu.Unlock()
	}
}

// faultVM is the VM a fault takes down, whose readiness it explains.
var faultVM = map[string]string{faultRestartIssuerB: "issuer-b", faultStopIssuerA: "issuer-a"}

func (r *stressRun) readinessLoop(ctx context.Context) {
	ready := map[string]bool{"issuer-a": true, "issuer-b": true}
	ticker := time.NewTicker(readinessEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, vm := range []string{"issuer-a", "issuer-b"} {
			probed := time.Now()
			err := r.kit.IssuerReady(ctx, vm)
			if ctx.Err() != nil {
				return
			}
			// a fault that began while the probe ran explains it too
			now := time.Now()
			explained := false
			for _, w := range r.faults.Windows() {
				if faultVM[w.Fault] == vm && (w.contains(probed) || w.contains(now)) {
					explained = true
				}
			}
			switch {
			case err != nil && ready[vm] && !explained:
				r.rec.Failure(Failure{Time: now, Class: ClassInvariant, Reason: fmt.Sprintf("%s is not ready: %v", vm, err)})
				ready[vm] = false
			case err != nil && !explained:
			case err != nil:
				ready[vm] = false
			default:
				if !ready[vm] {
					r.log.Info("ready again", "vm", vm)
				}
				ready[vm] = true
			}
		}
	}
}

// --- Chaos -----------------------------------------------------------------------------

// chaos injects the chaos faults on schedule, until the run stops starting
// cycles (spec, chaos).
func (r *stressRun) chaos(startCtx, root context.Context) {
	start := time.Now()
	schedule := chaosSchedule(r.cfg.Seed, r.cfg.Duration)
	r.log.Info("chaos schedule", "faults", fmt.Sprint(schedule))
	for _, f := range schedule {
		if err := sleep(startCtx, time.Until(start.Add(f.At))); err != nil {
			return
		}
		switch f.Fault {
		case faultRestartIssuerB:
			r.restartIssuerB(root)
		case faultRestartSpire:
			r.restartSpire(root, faultRestartSpire)
		}
	}
}

func (r *stressRun) restartIssuerB(ctx context.Context) {
	before, err := r.mergedKIDs(ctx)
	if err != nil {
		r.rec.Harness("reading issuer-a's merged JWK Set before restarting issuer-b: " + err.Error())
	}
	r.log.Warn("fault", "fault", faultRestartIssuerB)
	i := r.faults.begin(faultRestartIssuerB, false, time.Now())
	if _, err := r.kit.Run(ctx, "issuer-b", "sudo systemctl restart openstack-spire-issuer", nil); err != nil {
		r.faults.healed(i, time.Now(), err)
		r.rec.Harness("restarting issuer-b: " + err.Error())
		return
	}
	// issuer-a keeps serving issuer-b's keys while its peer is down
	if during, err := r.mergedKIDs(ctx); err == nil {
		for _, kid := range before {
			if strings.Contains(kid, "issuer-b") && !strings.Contains(strings.Join(during, " "), kid) {
				r.rec.Failure(Failure{Time: time.Now(), Class: ClassInvariant, Reason: fmt.Sprintf("issuer-a stopped serving issuer-b's key %s while issuer-b restarted", kid)})
			}
		}
	}
	err = r.kit.WaitIssuerReady(ctx, "issuer-b", 5*time.Minute)
	r.faults.healed(i, time.Now(), err)
	if err != nil {
		r.rec.Failure(Failure{Time: time.Now(), Class: ClassInvariant, Reason: "issuer-b not ready again after its restart: " + err.Error()})
	}
}

func (r *stressRun) restartSpire(ctx context.Context, fault string) {
	r.log.Warn("fault", "fault", fault)
	i := r.faults.begin(fault, false, time.Now())
	err := r.kit.RestartSpire(ctx, 3*time.Minute)
	r.faults.healed(i, time.Now(), err)
	if err != nil {
		r.rec.Failure(Failure{Time: time.Now(), Class: ClassInvariant, Reason: "SPIRE Server not healthy again after its restart: " + err.Error()})
	}
}

// mergedKIDs is the kids of issuer-a's merged JWK Set.
func (r *stressRun) mergedKIDs(ctx context.Context) ([]string, error) {
	out, err := r.kit.Run(ctx, "devstack", "curl -sSf -m 10 --cacert /etc/nova/lab-ca.pem https://issuer-a.lab:8443/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	var kids []string
	for _, m := range kidPattern.FindAllStringSubmatch(out, -1) {
		kids = append(kids, m[1])
	}
	return kids, nil
}
