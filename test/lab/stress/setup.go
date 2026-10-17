//go:build lab

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/test/lab/labkit"
)

// Pending is what a run changed on the lab and has not undone yet; it is
// saved after every change, so that the teardown, the next run's check or
// "lab.sh stress --cleanup" can undo it (spec, lifecycle).
type Pending struct {
	RunID   string            `json:"run_id"`
	Quotas  map[string]int64  `json:"quotas,omitempty"` // the original values
	Files   []FileChange      `json:"files,omitempty"`
	Entries []string          `json:"entries,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
}

// FileChange is a configuration file replaced for the run.
type FileChange struct {
	VM       string `json:"vm"`
	Path     string `json:"path"`
	Original string `json:"original"`
	Service  string `json:"service"` // "issuer" or "spire": what to restart
}

func pendingPath(stateDir string) string { return filepath.Join(stateDir, "stress", "pending.json") }

func loadPending(stateDir string) (*Pending, error) {
	data, err := os.ReadFile(pendingPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the pending changes: %w", err)
	}
	var p Pending
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", pendingPath(stateDir), err)
	}
	return &p, nil
}

func (p *Pending) save(stateDir string) error {
	if err := os.MkdirAll(filepath.Dir(pendingPath(stateDir)), 0o755); err != nil {
		return fmt.Errorf("creating the stress state directory: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(pendingPath(stateDir), data, 0o600); err != nil {
		return fmt.Errorf("saving the pending changes: %w", err)
	}
	return nil
}

// Setup prepares and restores the lab around a run.
type Setup struct {
	cfg *Config
	kit *labkit.Lab
	lab *kitLab
	log *slog.Logger
}

const (
	nodeEntryPath     = "/stress/node"
	workloadEntryPath = "/stress/workload"
	workloadUID       = 2000 // deploy.sh, STRESS_WORKLOAD_UID
)

// --- Check (step 2) and cleanup ------------------------------------------------------

// Check checks that the lab is healthy, after undoing what an interrupted
// run left behind.
func (s *Setup) Check(ctx context.Context) error {
	if err := s.Recover(ctx, false); err != nil {
		return err
	}
	var errs []error
	for _, vm := range []string{"issuer-a", "issuer-b"} {
		if err := s.kit.IssuerReady(ctx, vm); err != nil {
			errs = append(errs, fmt.Errorf("%s is not ready: %w", vm, err))
		}
	}
	if err := s.kit.SpireHealthy(ctx); err != nil {
		errs = append(errs, fmt.Errorf("SPIRE Server is not healthy: %w", err))
	}
	out, err := s.lab.admin(ctx, "compute", "service", "list", "--service", "nova-compute", "-f", "value", "-c", "State")
	if err != nil || strings.TrimSpace(out) != "up" {
		errs = append(errs, fmt.Errorf("the compute service of Nova is not up (%q): %v", strings.TrimSpace(out), err))
	}
	return errors.Join(errs...)
}

// Recover undoes a previous run's pending changes and deletes its
// instances; kept failures go too when all.
func (s *Setup) Recover(ctx context.Context, all bool) error {
	p, err := loadPending(s.kit.StateDir)
	if err != nil {
		return err
	}
	if p != nil {
		s.log.Warn("undoing the changes of an earlier run", "run_id", p.RunID)
		if err := s.restore(ctx, p); err != nil {
			return fmt.Errorf("undoing the changes of run %s: %w", p.RunID, err)
		}
	}
	servers, err := s.lab.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("listing the stress instances: %w", err)
	}
	for _, srv := range servers {
		if !all && s.isKept(srv.Name) {
			continue
		}
		s.log.Warn("deleting a stress instance left behind", "name", srv.Name, "instance_id", srv.ID)
		if _, err := s.lab.demo(ctx, "server", "delete", "--wait", srv.ID); err != nil {
			return fmt.Errorf("deleting %s: %w", srv.Name, err)
		}
	}
	// the agents of stress instances that no longer exist
	alive := map[string]bool{}
	for _, srv := range servers {
		if !all && s.isKept(srv.Name) {
			alive[srv.ID] = true
		}
	}
	agents, err := s.lab.ListAgents(ctx)
	if err != nil {
		return fmt.Errorf("listing the agents: %w", err)
	}
	prefix := fmt.Sprintf("spiffe://%s/spire/agent/openstack_iid/%s/", s.kit.Env.Spire.TrustDomain, s.kit.Env.OpenStack.ProjectID)
	for _, a := range agents {
		instance, ok := strings.CutPrefix(a.ID, prefix)
		if !ok || alive[instance] {
			continue
		}
		s.log.Warn("evicting the agent of a deleted instance", "agent_id", a.ID)
		if err := s.lab.EvictAgent(ctx, a.ID); err != nil {
			return fmt.Errorf("evicting %s: %w", a.ID, err)
		}
	}
	for _, path := range []string{workloadEntryPath, nodeEntryPath} {
		ids, err := s.lab.EntryIDs(ctx, "spiffe://"+s.kit.Env.Spire.TrustDomain+path)
		if err != nil {
			return fmt.Errorf("listing the stress entries: %w", err)
		}
		for _, id := range ids {
			if err := s.lab.DeleteEntry(ctx, id); err != nil {
				return fmt.Errorf("deleting the entry %s: %w", id, err)
			}
		}
	}
	return nil
}

// kept instances are listed in the kept file of the stress state directory.
func keptPath(stateDir string) string { return filepath.Join(stateDir, "stress", "kept") }

func (s *Setup) isKept(name string) bool {
	data, err := os.ReadFile(keptPath(s.kit.StateDir))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}

func (s *Setup) recordKept(names []string) error {
	if len(names) == 0 {
		return nil
	}
	f, err := os.OpenFile(keptPath(s.kit.StateDir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("recording the kept instances: %w", err)
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(strings.Join(names, "\n") + "\n")
	return err
}

// --- Set up (step 3) and tear down (step 6) --------------------------------------------

// Up makes the run's changes, saving each in p as it goes.
func (s *Setup) Up(ctx context.Context, p *Pending, quotaInstances int) error {
	if err := s.raiseQuotas(ctx, p, quotaInstances); err != nil {
		return err
	}
	td := s.kit.Env.Spire.TrustDomain
	node, err := s.lab.CreateEntry(ctx, fmt.Sprintf("-node -spiffeID spiffe://%s%s -selector openstack_iid:project_id:%s", td, nodeEntryPath, s.kit.Env.OpenStack.ProjectID))
	if err != nil {
		return fmt.Errorf("creating the node alias: %w", err)
	}
	p.Entries = append(p.Entries, node)
	if err := p.save(s.kit.StateDir); err != nil {
		return err
	}
	if err := s.createWorkloadEntry(ctx, p); err != nil {
		return err
	}
	if s.cfg.Rotation > 0 {
		for _, vm := range []string{"issuer-a", "issuer-b"} {
			if err := s.editFile(ctx, p, vm, labkit.IssuerConfig, "issuer", func(c string) string {
				return c + fmt.Sprintf("key_store:\n  rotation_interval: %q\n", s.cfg.Rotation.String())
			}); err != nil {
				return err
			}
		}
		for _, vm := range []string{"issuer-a", "issuer-b"} {
			if err := s.kit.RestartIssuer(ctx, vm); err != nil {
				return fmt.Errorf("restarting %s with rotation_interval %v: %w", vm, s.cfg.Rotation, err)
			}
		}
	}
	if s.cfg.AgentTTL > 0 || s.cfg.TOFU {
		if err := s.editFile(ctx, p, "spire", labkit.SpireServerConfig, "spire", func(c string) string {
			return editSpireConfig(c, s.cfg.AgentTTL, s.cfg.TOFU)
		}); err != nil {
			return err
		}
		if err := s.kit.RestartSpire(ctx, 2*time.Minute); err != nil {
			return fmt.Errorf("restarting SPIRE Server with the run's configuration: %w", err)
		}
	}
	return nil
}

func (s *Setup) createWorkloadEntry(ctx context.Context, p *Pending) error {
	td := s.kit.Env.Spire.TrustDomain
	id, err := s.lab.CreateEntry(ctx, fmt.Sprintf("-parentID spiffe://%s%s -spiffeID spiffe://%s%s -selector unix:uid:%d", td, nodeEntryPath, td, workloadEntryPath, workloadUID))
	if err != nil {
		return fmt.Errorf("creating the workload entry: %w", err)
	}
	p.Entries = append(p.Entries, id)
	if p.Extra == nil {
		p.Extra = map[string]string{}
	}
	p.Extra["workload_entry"] = id
	return p.save(s.kit.StateDir)
}

// removeWorkloadEntry deletes the workload entry (the self-test's fault).
func (s *Setup) removeWorkloadEntry(ctx context.Context, p *Pending) error {
	id := p.Extra["workload_entry"]
	if err := s.lab.DeleteEntry(ctx, id); err != nil {
		return err
	}
	for i, e := range p.Entries {
		if e == id {
			p.Entries = append(p.Entries[:i], p.Entries[i+1:]...)
			break
		}
	}
	delete(p.Extra, "workload_entry")
	return p.save(s.kit.StateDir)
}

// editSpireConfig sets agent_ttl in the server block and the server
// plugin's reattest.
func editSpireConfig(config string, agentTTL time.Duration, tofu bool) string {
	if agentTTL > 0 {
		config = strings.Replace(config, "server {\n", fmt.Sprintf("server {\n  agent_ttl    = %q\n", agentTTL.String()), 1)
	}
	if tofu {
		config = regexp.MustCompile(`(?m)^(\s*)jwks_url`).ReplaceAllString(config, "${1}reattest            = false\n${1}jwks_url")
	}
	return config
}

func (s *Setup) editFile(ctx context.Context, p *Pending, vm, path, service string, edit func(string) string) error {
	original, err := s.kit.ReadFile(ctx, vm, path)
	if err != nil {
		return fmt.Errorf("reading %s on %s: %w", path, vm, err)
	}
	p.Files = append(p.Files, FileChange{VM: vm, Path: path, Original: original, Service: service})
	if err := p.save(s.kit.StateDir); err != nil {
		return err
	}
	if err := s.kit.WriteFile(ctx, vm, path, edit(original)); err != nil {
		return fmt.Errorf("writing %s on %s: %w", path, vm, err)
	}
	return nil
}

func (s *Setup) raiseQuotas(ctx context.Context, p *Pending, instances int) error {
	out, err := s.lab.admin(ctx, "quota", "show", "demo", "-f", "json")
	if err != nil {
		return fmt.Errorf("reading the demo project's quotas: %w", err)
	}
	current, err := parseQuotas(out)
	if err != nil {
		return err
	}
	want := map[string]int64{"instances": int64(instances), "cores": int64(instances) * labGuest.VCPUs, "ram": int64(instances) * labGuest.RAMMiB}
	args := []string{"quota", "set"}
	p.Quotas = map[string]int64{}
	for _, name := range []string{"instances", "cores", "ram"} {
		if v, ok := current[name]; ok && v >= 0 && v < want[name] {
			p.Quotas[name] = v
			args = append(args, "--"+name, strconv.FormatInt(want[name], 10))
		}
	}
	if len(p.Quotas) == 0 {
		return nil
	}
	if err := p.save(s.kit.StateDir); err != nil {
		return err
	}
	if _, err := s.lab.admin(ctx, append(args, "demo")...); err != nil {
		return fmt.Errorf("raising the demo project's quotas: %w", err)
	}
	return nil
}

// parseQuotas parses "openstack quota show -f json", as a list of
// Resource/Limit rows or as an object; an unlimited quota is -1.
func parseQuotas(out string) (map[string]int64, error) {
	quotas := map[string]int64{}
	var rows []struct {
		Resource string `json:"Resource"`
		Limit    *int64 `json:"Limit"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err == nil {
		for _, r := range rows {
			if r.Limit == nil {
				quotas[r.Resource] = -1
			} else {
				quotas[r.Resource] = *r.Limit
			}
		}
		return quotas, nil
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(out), &object); err != nil {
		return nil, fmt.Errorf("parsing the quotas: %w", err)
	}
	for k, v := range object {
		if f, ok := v.(float64); ok {
			quotas[k] = int64(f)
		}
	}
	return quotas, nil
}

// Down undoes the run's changes.
func (s *Setup) Down(ctx context.Context, p *Pending) error {
	return s.restore(ctx, p)
}

func (s *Setup) restore(ctx context.Context, p *Pending) error {
	var errs []error
	for _, id := range p.Entries {
		if err := s.lab.DeleteEntry(ctx, id); err != nil && !strings.Contains(err.Error(), "NotFound") && !strings.Contains(err.Error(), "not found") {
			errs = append(errs, fmt.Errorf("deleting the entry %s: %w", id, err))
		}
	}
	restart := map[string]string{}
	for i := len(p.Files) - 1; i >= 0; i-- {
		f := p.Files[i]
		if err := s.kit.WriteFile(ctx, f.VM, f.Path, f.Original); err != nil {
			errs = append(errs, fmt.Errorf("restoring %s on %s: %w", f.Path, f.VM, err))
			continue
		}
		restart[f.VM] = f.Service
	}
	for vm, service := range restart {
		var err error
		if service == "spire" {
			err = s.kit.RestartSpire(ctx, 2*time.Minute)
		} else {
			err = s.kit.RestartIssuer(ctx, vm)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restarting %s with its configuration restored: %w", vm, err))
		}
	}
	if len(p.Quotas) > 0 {
		args := []string{"quota", "set"}
		for name, v := range p.Quotas {
			args = append(args, "--"+name, strconv.FormatInt(v, 10))
		}
		if _, err := s.lab.admin(ctx, append(args, "demo")...); err != nil {
			errs = append(errs, fmt.Errorf("restoring the demo project's quotas: %w", err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := os.Remove(pendingPath(s.kit.StateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing the pending changes: %w", err)
	}
	return nil
}
