//go:build lab

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Server is a Nova instance, as the observer sees it.
type Server struct {
	ID, Name, Status, Address string
}

// AgentInfo is an attested agent, as SPIRE Server lists it.
type AgentInfo struct {
	ID          string
	Serial      string
	ExpiresAt   time.Time
	Selectors   []string
	CanReattest bool
}

// Snapshot is the observer's latest view of the run's instances and of
// SPIRE Server's agents.
type Snapshot struct {
	ServersAt time.Time
	AgentsAt  time.Time
	Servers   map[string]Server    // by instance ID
	Agents    map[string]AgentInfo // by SPIFFE ID
}

// SerialChange is an agent's SVID replaced: renewed, or re-attested.
type SerialChange struct {
	AgentID  string
	Old, New string
	Time     time.Time
}

// errTimeout is a step that missed its bound.
var errTimeout = errors.New("bound exceeded")

// Observer polls Nova's server list and SPIRE Server's agent list for the
// whole run, so that the cycles never poll on their own (spec, parallelism).
type Observer struct {
	lab      Lister
	faults   *Faults
	interval time.Duration
	log      *slog.Logger
	harness  func(reason string) // records a harness failure

	mu      sync.Mutex
	snap    Snapshot
	changed chan struct{}
	serials []SerialChange
}

// Lister is what the observer polls.
type Lister interface {
	ListServers(ctx context.Context) ([]Server, error)
	ListAgents(ctx context.Context) ([]AgentInfo, error)
}

func newObserver(lab Lister, faults *Faults, interval time.Duration, log *slog.Logger, harness func(string)) *Observer {
	return &Observer{lab: lab, faults: faults, interval: interval, log: log, harness: harness,
		snap: Snapshot{Servers: map[string]Server{}, Agents: map[string]AgentInfo{}}, changed: make(chan struct{})}
}

// consecutiveFailuresReported is how many polls in a row may fail before
// it is a harness failure (one minute at 5 seconds).
const consecutiveFailuresReported = 12

// Run polls until ctx ends.
func (o *Observer) Run(ctx context.Context) {
	var serverFailures, agentFailures int
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		var wg sync.WaitGroup
		var servers []Server
		var agents []AgentInfo
		var serverErr, agentErr error
		wg.Add(2)
		go func() { defer wg.Done(); servers, serverErr = o.lab.ListServers(ctx) }()
		go func() { defer wg.Done(); agents, agentErr = o.lab.ListAgents(ctx) }()
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		o.update(now, servers, serverErr, agents, agentErr)
		serverFailures = o.count("Nova's server list", serverErr, serverFailures)
		agentFailures = o.count("SPIRE Server's agent list", agentErr, agentFailures)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (o *Observer) count(what string, err error, failures int) int {
	if err == nil {
		return 0
	}
	failures++
	o.log.Warn("poll failed", "what", what, "error", err, "consecutive", failures)
	if failures == consecutiveFailuresReported {
		o.harness(fmt.Sprintf("%s failed %d times in a row: %v", what, failures, err))
	}
	return failures
}

func (o *Observer) update(now time.Time, servers []Server, serverErr error, agents []AgentInfo, agentErr error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	snap := Snapshot{ServersAt: o.snap.ServersAt, AgentsAt: o.snap.AgentsAt, Servers: o.snap.Servers, Agents: o.snap.Agents}
	if serverErr == nil {
		snap.ServersAt = now
		snap.Servers = make(map[string]Server, len(servers))
		for _, s := range servers {
			snap.Servers[s.ID] = s
		}
	}
	if agentErr == nil {
		snap.AgentsAt = now
		snap.Agents = make(map[string]AgentInfo, len(agents))
		for _, a := range agents {
			snap.Agents[a.ID] = a
			if old, ok := o.snap.Agents[a.ID]; ok && old.Serial != a.Serial {
				o.serials = append(o.serials, SerialChange{AgentID: a.ID, Old: old.Serial, New: a.Serial, Time: now})
				o.log.Info("agent SVID replaced", "agent_id", a.ID, "old_serial", old.Serial, "new_serial", a.Serial)
			}
		}
	}
	o.snap = snap
	close(o.changed)
	o.changed = make(chan struct{})
}

// Snapshot is the latest snapshot.
func (o *Observer) Snapshot() Snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.snap
}

// SerialChanges is every agent SVID replacement seen so far.
func (o *Observer) SerialChanges() []SerialChange {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]SerialChange(nil), o.serials...)
}

// Wait waits, from start, until pred holds on a snapshot taken after
// notBefore, for at most bound, extended by the faults during the wait.
func (o *Observer) Wait(ctx context.Context, start time.Time, bound time.Duration, notBefore time.Time, pred func(Snapshot) bool) (Snapshot, error) {
	deadline := start.Add(bound)
	for {
		o.mu.Lock()
		snap, changed := o.snap, o.changed
		o.mu.Unlock()
		fresh := snap.ServersAt.After(notBefore) && snap.AgentsAt.After(notBefore)
		if fresh && pred(snap) {
			return snap, nil
		}
		now := time.Now()
		if d := o.faults.extend(start, deadline, now); now.After(d) {
			return snap, errTimeout
		}
		select {
		case <-ctx.Done():
			return snap, ctx.Err()
		case <-changed:
		case <-time.After(o.interval):
		}
	}
}
