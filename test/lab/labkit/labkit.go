//go:build lab

// Package labkit reaches the lab built by "lab.sh up" and "lab.sh deploy"
// (see .specs/openstack-spire-test-environment.md): its VMs over the system's
// ssh client, OpenStack with the openstack CLI on the devstack VM, SPIRE
// Server with its CLI on the spire VM. The acceptance tests and the stress
// test (.specs/openstack-spire-stress-test.md) share it; it needs nothing but
// the standard library.
package labkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Env is the lab's env.json, as far as the tests use it.
type Env struct {
	Versions map[string]string `json:"versions"`
	SSH      struct {
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
	Deployed struct {
		Commit string `json:"commit"`
		At     string `json:"at"`
	} `json:"deployed"`
}

// Lab is a lab, described by the env.json in its state directory.
type Lab struct {
	StateDir string
	Env      Env

	// sessions bounds the concurrent multiplexed SSH sessions per VM, below
	// sshd's MaxSessions (10 by default).
	mu       sync.Mutex
	sessions map[string]chan struct{}
}

// maxSessions is the number of concurrent commands run on one VM over its
// shared SSH connection.
const maxSessions = 8

// ErrNotDeployed is returned by Load for a lab that was never deployed.
var ErrNotDeployed = errors.New("the lab is not deployed: run lab.sh deploy")

// Load reads the lab's env.json from its state directory.
func Load(stateDir string) (*Lab, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "env.json"))
	if err != nil {
		return nil, fmt.Errorf("no lab (run lab.sh up and lab.sh deploy): %w", err)
	}
	l := &Lab{StateDir: stateDir, sessions: map[string]chan struct{}{}}
	if err := json.Unmarshal(data, &l.Env); err != nil {
		return nil, fmt.Errorf("reading env.json: %w", err)
	}
	if l.Env.Spire.TrustDomain == "" {
		return nil, ErrNotDeployed
	}
	return l, nil
}

// --- SSH ----------------------------------------------------------------------

func (l *Lab) sshArgs(multiplex bool) []string {
	args := []string{
		"-i", l.Env.SSH.Key,
		"-o", "UserKnownHostsFile=" + filepath.Join(l.StateDir, "known_hosts"),
		"-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
	}
	if multiplex {
		// %C hashes the connection's parameters: short enough for a socket path
		args = append(args, "-o", "ControlMaster=auto", "-o", "ControlPersist=120",
			"-o", "ControlPath="+filepath.Join(runtimeDir(), "labkit-%C"))
	} else {
		args = append(args, "-o", "ControlPath=none")
	}
	return args
}

func runtimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return os.TempDir()
}

func (l *Lab) address(vm string) (string, error) {
	v, ok := l.Env.VMs[vm]
	if !ok {
		return "", fmt.Errorf("no VM %q", vm)
	}
	return l.Env.SSH.User + "@" + v.IP, nil
}

func (l *Lab) session(vm string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[vm]
	if !ok {
		s = make(chan struct{}, maxSessions)
		l.sessions[vm] = s
	}
	return s
}

// Run runs a shell command on a VM and returns its standard output; standard
// input is stdin, if not nil.
func (l *Lab) Run(ctx context.Context, vm, command string, stdin []byte) (string, error) {
	address, err := l.address(vm)
	if err != nil {
		return "", err
	}
	session := l.session(vm)
	select {
	case session <- struct{}{}:
		defer func() { <-session }()
	case <-ctx.Done():
		return "", fmt.Errorf("%s on %s: %w", FirstLine(command), vm, ctx.Err())
	}
	cmd := exec.CommandContext(ctx, "ssh", append(l.sshArgs(true), address, command)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s on %s: %w: %s", FirstLine(command), vm, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Stream runs a long-running command on a VM, over a connection of its own,
// and returns its standard output; closing it, or ending ctx, stops the
// command.
func (l *Lab) Stream(ctx context.Context, vm, command string) (io.ReadCloser, error) {
	address, err := l.address(vm)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "ssh", append(l.sshArgs(false), address, command)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("streaming %s on %s: %w", FirstLine(command), vm, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("streaming %s on %s: %w", FirstLine(command), vm, err)
	}
	return &stream{ReadCloser: stdout, cmd: cmd}, nil
}

type stream struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (s *stream) Close() error {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.ReadCloser.Close()
	_ = s.cmd.Wait()
	return nil
}

// FirstLine is the first line of a command, shortened, for error messages.
func FirstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 80 {
		line = line[:80] + "..."
	}
	return line
}

// Quote quotes a string for a POSIX shell.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ReadFile returns a file of a VM, read as root.
func (l *Lab) ReadFile(ctx context.Context, vm, path string) (string, error) {
	return l.Run(ctx, vm, "sudo cat "+Quote(path), nil)
}

// WriteFile replaces the content of a file of a VM, keeping its owner and
// mode.
func (l *Lab) WriteFile(ctx context.Context, vm, path, content string) error {
	_, err := l.Run(ctx, vm, "sudo tee "+Quote(path)+" >/dev/null", []byte(content))
	return err
}

// --- OpenStack ----------------------------------------------------------------

// OpenStack runs the openstack CLI on devstack as user in project (both
// DevStack users, e.g. demo/demo or admin/admin), and returns its output.
func (l *Lab) OpenStack(ctx context.Context, user, project string, args ...string) (string, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = Quote(a)
	}
	script := "set +u; source /opt/stack/devstack/openrc " + user + " " + project + " >/dev/null 2>&1; set -u; openstack " + strings.Join(quoted, " ")
	return l.Run(ctx, "devstack", "cd /opt/stack && sudo -u stack bash -c "+Quote(script), nil)
}
