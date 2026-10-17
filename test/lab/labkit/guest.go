//go:build lab

package labkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Guest is a Nova instance under test.
type Guest struct {
	Name, ID, Project, Distro string
}

// GuestImageUser is the default user of a guest image's distro.
var GuestImageUser = map[string]string{"ubuntu": "ubuntu", "alma": "almalinux", "rocky": "rocky"}

// CreateGuest boots a guest of distro (ubuntu or rhel) in project (demo or
// alt_demo) with the cloud-init configuration "lab.sh deploy" wrote. With
// wait, it returns once the instance is ACTIVE (or failed); otherwise once
// Nova accepted the request.
func (l *Lab) CreateGuest(ctx context.Context, name, distro, project string, wait bool) (Guest, error) {
	userData, err := os.ReadFile(filepath.Join(l.StateDir, "guest", distro+".yaml"))
	if err != nil {
		return Guest{}, fmt.Errorf("no guest configuration (run lab.sh deploy): %w", err)
	}
	remote := "/tmp/" + name + ".yaml"
	if _, err := l.Run(ctx, "devstack", "cat > "+remote+" && chmod 644 "+remote, userData); err != nil {
		return Guest{}, fmt.Errorf("copying the user data of %s: %w", name, err)
	}
	// Nova reads the user data at the request: the copy can go right after
	defer func() { _, _ = l.Run(context.WithoutCancel(ctx), "devstack", "rm -f "+remote, nil) }()
	args := []string{"server", "create", "--image", l.Env.OpenStack.Images[distro],
		"--flavor", l.Env.OpenStack.Flavor, "--network", "private", "--user-data", remote}
	if project == "demo" {
		// key pairs belong to a user: the lab's belongs to demo
		args = append(args, "--key-name", l.Env.OpenStack.Keypair)
	}
	if wait {
		args = append(args, "--wait")
	}
	id, err := l.OpenStack(ctx, project, project, append(args, "-f", "value", "-c", "id", name)...)
	if err != nil {
		return Guest{}, fmt.Errorf("booting %s: %w", name, err)
	}
	return Guest{Name: name, ID: strings.TrimSpace(id), Project: project, Distro: distro}, nil
}

// DeleteGuest deletes a guest, waiting for it to be gone if wait.
func (l *Lab) DeleteGuest(ctx context.Context, g Guest, wait bool) error {
	args := []string{"server", "delete"}
	if wait {
		args = append(args, "--wait")
	}
	if _, err := l.OpenStack(ctx, g.Project, g.Project, append(args, g.ID)...); err != nil {
		return fmt.Errorf("deleting %s: %w", g.Name, err)
	}
	return nil
}

var privateAddress = regexp.MustCompile(`\b10\.0\.0\.\d+\b`)

// PrivateAddress extracts a guest's address on DevStack's private network
// from Nova's description of its addresses.
func PrivateAddress(addresses string) string { return privateAddress.FindString(addresses) }

// GuestAddress is a guest's address on DevStack's private network.
func (l *Lab) GuestAddress(ctx context.Context, g Guest) (string, error) {
	out, err := l.OpenStack(ctx, g.Project, g.Project, "server", "show", "-f", "json", "-c", "addresses", g.ID)
	if err != nil {
		return "", err
	}
	ip := PrivateAddress(out)
	if ip == "" {
		return "", fmt.Errorf("no private address for %s in %s", g.Name, out)
	}
	return ip, nil
}

// GuestRun runs a shell command in a guest at address ip (GuestAddress when
// empty), over SSH from the devstack VM's OVN metadata namespace, which sits
// on the guests' private network.
func (l *Lab) GuestRun(ctx context.Context, g Guest, ip, command string) (string, error) {
	if ip == "" {
		var err error
		if ip, err = l.GuestAddress(ctx, g); err != nil {
			return "", err
		}
	}
	user := GuestImageUser[l.Env.Images[g.Distro].Distro]
	key, err := os.ReadFile(l.Env.SSH.Key)
	if err != nil {
		return "", fmt.Errorf("reading the lab's SSH key: %w", err)
	}
	script := `set -e
key=$(mktemp); trap 'rm -f "$key"' EXIT; cat > "$key"; chmod 600 "$key"
ns=$(ip netns list | awk '/^ovnmeta-/ { print $1; exit }')
sudo ip netns exec "$ns" ssh -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR -o ConnectTimeout=20 -o BatchMode=yes ` + user + `@` + ip + ` ` + Quote(command)
	out, err := l.Run(ctx, "devstack", script, key)
	if err != nil {
		return out, fmt.Errorf("in %s: %w", g.Name, err)
	}
	return out, nil
}

// ConsoleLog is the tail of a guest's console log.
func (l *Lab) ConsoleLog(ctx context.Context, g Guest) (string, error) {
	return l.OpenStack(ctx, g.Project, g.Project, "console", "log", "show", "--lines", "300", g.ID)
}
