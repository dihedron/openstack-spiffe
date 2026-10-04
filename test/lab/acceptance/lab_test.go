//go:build lab

// Package acceptance holds the lab's acceptance tests: they run against a
// lab built by "lab.sh up" and "lab.sh deploy", through "lab.sh test" (see
// .specs/openstack-spire-test-environment.md). They reach the VMs with the
// system's ssh client and OpenStack with the openstack CLI on the devstack
// VM, so they need nothing but the standard library.
//
// The tests run one after another: some restart or reconfigure the issuers.
// Each boots the guests it needs and removes them, and restores what it
// changes.
package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// lab describes the lab under test, from env.json.
type lab struct {
	stateDir string
	env      struct {
		Versions struct {
			Spire string `json:"spire"`
		} `json:"versions"`
		SSH struct {
			User string `json:"user"`
			Key  string `json:"key"`
		} `json:"ssh"`
		VMs map[string]struct {
			IP string `json:"ip"`
		} `json:"vms"`
		OpenStack struct {
			VendordataUserID string            `json:"vendordata_user_id"`
			ProjectID        string            `json:"project_id"`
			Flavor           string            `json:"flavor"`
			Keypair          string            `json:"keypair"`
			Images           map[string]string `json:"images"`
		} `json:"openstack"`
		Spire struct {
			TrustDomain string `json:"trust_domain"`
		} `json:"spire"`
		Images map[string]struct {
			Distro string `json:"distro"`
		} `json:"images"`
	}
}

var theLab *lab

func TestMain(m *testing.M) {
	dir := os.Getenv("LAB_STATE_DIR")
	if dir == "" {
		dir = filepath.Join("..", ".state")
	}
	l := &lab{stateDir: dir}
	data, err := os.ReadFile(filepath.Join(dir, "env.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "no lab: %v (run lab.sh up and lab.sh deploy)\n", err)
		os.Exit(2)
	}
	if err := json.Unmarshal(data, &l.env); err != nil {
		fmt.Fprintf(os.Stderr, "reading env.json: %v\n", err)
		os.Exit(2)
	}
	if l.env.Spire.TrustDomain == "" {
		fmt.Fprintln(os.Stderr, "the lab is not deployed: run lab.sh deploy")
		os.Exit(2)
	}
	theLab = l
	os.Exit(m.Run())
}

// long reports whether the long scenarios run (lab.sh test -long).
func long() bool { return os.Getenv("LAB_LONG") != "" }

// --- SSH ----------------------------------------------------------------------

func (l *lab) sshArgs() []string {
	return []string{
		"-i", l.env.SSH.Key,
		"-o", "UserKnownHostsFile=" + filepath.Join(l.stateDir, "known_hosts"),
		"-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
	}
}

// run runs a shell command on a VM and returns its standard output; standard
// input is stdin, if not nil.
func (l *lab) run(vm, command string, stdin []byte) (string, error) {
	vmEnv, ok := l.env.VMs[vm]
	if !ok {
		return "", fmt.Errorf("no VM %q", vm)
	}
	cmd := exec.Command("ssh", append(l.sshArgs(), l.env.SSH.User+"@"+vmEnv.IP, command)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s on %s: %w: %s", firstLine(command), vm, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
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

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 80 {
		line = line[:80] + "..."
	}
	return line
}

// quote quotes a string for a POSIX shell.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// --- OpenStack ----------------------------------------------------------------

// openstack runs the openstack CLI on devstack as user in project (both
// DevStack users, e.g. demo/demo or admin/admin), and returns its output.
func (l *lab) openstack(user, project string, args ...string) (string, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quote(a)
	}
	script := "set +u; source /opt/stack/devstack/openrc " + user + " " + project + " >/dev/null 2>&1; set -u; openstack " + strings.Join(quoted, " ")
	return l.run("devstack", "cd /opt/stack && sudo -u stack bash -c "+quote(script), nil)
}

// --- Guests -------------------------------------------------------------------

// guest is a Nova instance under test.
type guest struct {
	name, id, project, distro string
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
	userData, err := os.ReadFile(filepath.Join(l.stateDir, "guest", distro+".yaml"))
	if err != nil {
		t.Fatalf("no guest configuration (run lab.sh deploy): %v", err)
	}
	remote := "/tmp/" + name + ".yaml"
	if _, err := l.run("devstack", "cat > "+remote+" && chmod 644 "+remote, userData); err != nil {
		t.Fatal(err)
	}
	args := []string{"server", "create", "--image", l.env.OpenStack.Images[distro],
		"--flavor", l.env.OpenStack.Flavor, "--network", "private", "--user-data", remote}
	if project == "demo" {
		// key pairs belong to a user: the lab's belongs to demo
		args = append(args, "--key-name", l.env.OpenStack.Keypair)
	}
	id, err := l.openstack(project, project, append(args, "--wait", "-f", "value", "-c", "id", name)...)
	if err != nil {
		t.Fatalf("booting %s: %v", name, err)
	}
	g := guest{name: name, id: strings.TrimSpace(id), project: project, distro: distro}
	t.Cleanup(func() {
		if _, err := l.openstack(project, project, "server", "delete", "--wait", g.id); err != nil {
			t.Logf("deleting %s: %v", g.name, err)
		}
		if _, err := l.run("devstack", "rm -f "+remote, nil); err != nil {
			t.Logf("removing %s: %v", remote, err)
		}
	})
	t.Logf("booted %s (%s, %s, %s)", g.name, g.id, distro, project)
	return g
}

// guestRun runs a shell command in a guest, over SSH from the devstack VM's
// OVN metadata namespace, which sits on the guests' private network.
func (l *lab) guestRun(t *testing.T, g guest, command string) string {
	t.Helper()
	address, err := l.openstack(g.project, g.project, "server", "show", "-f", "json", "-c", "addresses", g.id)
	if err != nil {
		t.Fatal(err)
	}
	ip := regexp.MustCompile(`\b10\.0\.0\.\d+\b`).FindString(address)
	if ip == "" {
		t.Fatalf("no private address for %s in %s", g.name, address)
	}
	// the cloud images' default users
	user := map[string]string{"ubuntu": "ubuntu", "alma": "almalinux", "rocky": "rocky"}[l.env.Images[g.distro].Distro]
	key, err := os.ReadFile(l.env.SSH.Key)
	if err != nil {
		t.Fatal(err)
	}
	script := `set -e
key=$(mktemp); trap 'rm -f "$key"' EXIT; cat > "$key"; chmod 600 "$key"
ns=$(ip netns list | awk '/^ovnmeta-/ { print $1; exit }')
sudo ip netns exec "$ns" ssh -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR -o ConnectTimeout=20 ` + user + `@` + ip + ` ` + quote(command)
	out, err := l.run("devstack", script, key)
	if err != nil {
		t.Fatalf("in %s: %v", g.name, err)
	}
	return out
}

// --- SPIRE --------------------------------------------------------------------

func (l *lab) spireServer(args string) (string, error) {
	return l.run("spire", "sudo -u spire /opt/spire/bin/spire-server "+args+" -socketPath /var/lib/spire/server/api.sock", nil)
}

// agentID is the SPIFFE ID the server plugin gives a guest's agent.
func (l *lab) agentID(g guest, projectID string) string {
	return fmt.Sprintf("spiffe://%s/spire/agent/openstack_iid/%s/%s", l.env.Spire.TrustDomain, projectID, g.id)
}

// agent is an attested agent, as "spire-server agent show" describes it.
type agent struct {
	serial    string
	selectors []string
}

// attestedAgent returns the agent with the given SPIFFE ID, if attested.
func (l *lab) attestedAgent(id string) (agent, bool) {
	out, err := l.spireServer("agent show -spiffeID " + quote(id))
	if err != nil {
		return agent{}, false
	}
	var a agent
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Serial number":
			a.serial = strings.TrimSpace(value)
		case "Selectors":
			a.selectors = append(a.selectors, strings.TrimSpace(value))
		}
	}
	return a, a.serial != ""
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
	command := "sudo journalctl -u spire-server --no-pager -o cat --since " + quote(since)
	if pattern != "" {
		command += " | grep -E " + quote(pattern) + " || true"
	}
	out, _ := l.run("spire", command, nil)
	return out
}

// --- Issuers ------------------------------------------------------------------

// issuerLog returns an issuer's journal since a journalctl time
// specification, with extra journalctl arguments (e.g. field matches).
func (l *lab) issuerLog(t *testing.T, vm, since, extra string) string {
	t.Helper()
	return l.must(t, vm, "sudo journalctl -u openstack-spire-issuer --no-pager --since "+quote(since)+" "+extra)
}

// waitIssuerReady waits for an issuer's /readiness, from the devstack VM
// (where Nova calls from).
func (l *lab) waitIssuerReady(t *testing.T, vm string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if _, err := l.run("devstack", "curl -sf --cacert /etc/nova/lab-ca.pem https://"+vm+".lab:8443/readiness", nil); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready within 5 minutes", vm)
		}
		time.Sleep(10 * time.Second)
	}
}

// restartIssuer restarts an issuer and waits until it is ready again (its
// first key is published ahead of use: about 2 minutes).
func (l *lab) restartIssuer(t *testing.T, vm string) {
	t.Helper()
	l.must(t, vm, "sudo systemctl restart openstack-spire-issuer")
	l.waitIssuerReady(t, vm)
}

// editIssuerFile replaces a file of an issuer's configuration with the
// result of edit, restarts the issuer, and restores the original (and
// restarts it again) when the test ends.
func (l *lab) editIssuerFile(t *testing.T, vm, path string, edit func(string) string) {
	t.Helper()
	original := l.must(t, vm, "sudo cat "+path)
	write := func(content string) error {
		_, err := l.run(vm, "sudo tee "+path+" >/dev/null", []byte(content))
		return err
	}
	if err := write(edit(original)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := write(original); err != nil {
			t.Errorf("restoring %s on %s: %v", path, vm, err)
			return
		}
		l.restartIssuer(t, vm)
	})
	l.restartIssuer(t, vm)
}
