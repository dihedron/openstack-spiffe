//go:build lab

// Package acceptance holds the lab's acceptance tests: they run against a
// lab built by "lab.sh up" and "lab.sh deploy", through "lab.sh test" (see
// .specs/openstack-spire-test-environment.md). They reach the lab through
// labkit, shared with the stress test, which needs nothing but the standard
// library.
//
// The tests run one after another: some restart or reconfigure the issuers.
// Each boots the guests it needs and removes them, and restores what it
// changes.
package acceptance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/test/lab/labkit"
)

// lab is the lab under test, with the testing.T helpers of the tests.
type lab struct {
	kit      *labkit.Lab
	stateDir string
	env      *labkit.Env
}

var theLab *lab

func TestMain(m *testing.M) {
	dir := os.Getenv("LAB_STATE_DIR")
	if dir == "" {
		dir = filepath.Join("..", ".state")
	}
	kit, err := labkit.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	theLab = &lab{kit: kit, stateDir: dir, env: &kit.Env}
	os.Exit(m.Run())
}

// long reports whether the long scenarios run (lab.sh test -long).
func long() bool { return os.Getenv("LAB_LONG") != "" }

// --- SSH ----------------------------------------------------------------------

// run runs a shell command on a VM and returns its standard output; standard
// input is stdin, if not nil.
func (l *lab) run(vm, command string, stdin []byte) (string, error) {
	return l.kit.Run(context.Background(), vm, command, stdin)
}

// must runs a command on a VM, failing the test on error.
func (l *lab) must(t *testing.T, vm, command string) string {
	t.Helper()
	out, err := l.run(vm, command, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// quote quotes a string for a POSIX shell.
func quote(s string) string { return labkit.Quote(s) }

// --- OpenStack ----------------------------------------------------------------

// openstack runs the openstack CLI on devstack as user in project (both
// DevStack users, e.g. demo/demo or admin/admin), and returns its output.
func (l *lab) openstack(user, project string, args ...string) (string, error) {
	return l.kit.OpenStack(context.Background(), user, project, args...)
}

// --- Guests -------------------------------------------------------------------

// guest is a Nova instance under test.
type guest struct {
	name, id, project, distro string
}

func (g guest) kit() labkit.Guest {
	return labkit.Guest{Name: g.name, ID: g.id, Project: g.project, Distro: g.distro}
}

// bootGuest boots a guest of distro (ubuntu or rhel) in project (demo or
// alt_demo) with the cloud-init configuration "lab.sh deploy" wrote, and
// deletes it when the test ends.
func (l *lab) bootGuest(t *testing.T, distro, project string) guest {
	t.Helper()
	name := fmt.Sprintf("lab-%s-%s-%d", strings.ToLower(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(t.Name(), "-")), distro, time.Now().Unix()%100000)
	if len(name) > 60 {
		name = name[len(name)-60:]
	}
	k, err := l.kit.CreateGuest(context.Background(), name, distro, project, true)
	if err != nil {
		t.Fatal(err)
	}
	g := guest{name: k.Name, id: k.ID, project: k.Project, distro: k.Distro}
	t.Cleanup(func() {
		if err := l.kit.DeleteGuest(context.Background(), k, true); err != nil {
			t.Log(err)
		}
	})
	t.Logf("booted %s (%s, %s, %s)", g.name, g.id, distro, project)
	return g
}

// guestRun runs a shell command in a guest, over SSH from the devstack VM's
// OVN metadata namespace, which sits on the guests' private network.
func (l *lab) guestRun(t *testing.T, g guest, command string) string {
	t.Helper()
	out, err := l.kit.GuestRun(context.Background(), g.kit(), "", command)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// --- SPIRE --------------------------------------------------------------------

func (l *lab) spireServer(args string) (string, error) {
	return l.kit.SpireServer(context.Background(), args)
}

// agentID is the SPIFFE ID the server plugin gives a guest's agent.
func (l *lab) agentID(g guest, projectID string) string {
	return l.kit.AgentID(projectID, g.id)
}

// agent is an attested agent, as "spire-server agent show" describes it.
type agent struct {
	serial    string
	selectors []string
}

// attestedAgent returns the agent with the given SPIFFE ID, if attested.
func (l *lab) attestedAgent(id string) (agent, bool) {
	a, ok := l.kit.AttestedAgent(context.Background(), id)
	return agent{serial: a.Serial, selectors: a.Selectors}, ok
}

// waitAttested waits until the agent with the given SPIFFE ID is attested,
// with a serial other than notSerial (its previous SVID, if any).
func (l *lab) waitAttested(t *testing.T, id, notSerial string, timeout time.Duration) agent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if a, ok := l.attestedAgent(id); ok && a.serial != notSerial {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not attested within %v\nSPIRE Server's openstack_iid records:\n%s", id, timeout, l.spireLog("-5min", ""))
		}
		time.Sleep(5 * time.Second)
	}
}

// spireLog returns SPIRE Server's journal since a journalctl time
// specification, filtered by an extended regular expression if not empty.
func (l *lab) spireLog(since, pattern string) string {
	return l.kit.SpireLog(context.Background(), since, pattern)
}

// --- Issuers ------------------------------------------------------------------

// issuerLog returns an issuer's journal since a journalctl time
// specification, with extra journalctl arguments (e.g. field matches).
func (l *lab) issuerLog(t *testing.T, vm, since, extra string) string {
	t.Helper()
	out, err := l.kit.IssuerLog(context.Background(), vm, since, extra)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// waitIssuerReady waits for an issuer's /readiness, from the devstack VM
// (where Nova calls from).
func (l *lab) waitIssuerReady(t *testing.T, vm string) {
	t.Helper()
	if err := l.kit.WaitIssuerReady(context.Background(), vm, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
}

// restartIssuer restarts an issuer and waits until it is ready again (its
// first key is published ahead of use: about 2 minutes).
func (l *lab) restartIssuer(t *testing.T, vm string) {
	t.Helper()
	if err := l.kit.RestartIssuer(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
}

// editIssuerFile replaces a file of an issuer's configuration with the
// result of edit, restarts the issuer, and restores the original (and
// restarts it again) when the test ends.
func (l *lab) editIssuerFile(t *testing.T, vm, path string, edit func(string) string) {
	t.Helper()
	ctx := context.Background()
	original, err := l.kit.ReadFile(ctx, vm, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.kit.WriteFile(ctx, vm, path, edit(original)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.kit.WriteFile(ctx, vm, path, original); err != nil {
			t.Errorf("restoring %s on %s: %v", path, vm, err)
			return
		}
		l.restartIssuer(t, vm)
	})
	l.restartIssuer(t, vm)
}
