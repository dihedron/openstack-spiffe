//go:build lab

package labkit

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SpireServerConfig is SPIRE Server's configuration file on the spire VM.
const SpireServerConfig = "/etc/spire/server.conf"

// SpireServer runs the spire-server CLI on the spire VM.
func (l *Lab) SpireServer(ctx context.Context, args string) (string, error) {
	return l.Run(ctx, "spire", "sudo -u spire /opt/spire/bin/spire-server "+args+" -socketPath /var/lib/spire/server/api.sock", nil)
}

// AgentID is the SPIFFE ID the server plugin gives an instance's agent.
func (l *Lab) AgentID(projectID, instanceID string) string {
	return fmt.Sprintf("spiffe://%s/spire/agent/openstack_iid/%s/%s", l.Env.Spire.TrustDomain, projectID, instanceID)
}

// Agent is an attested agent, as "spire-server agent show" describes it.
type Agent struct {
	Serial    string
	Selectors []string
}

// AttestedAgent returns the agent with the given SPIFFE ID, if attested.
func (l *Lab) AttestedAgent(ctx context.Context, id string) (Agent, bool) {
	out, err := l.SpireServer(ctx, "agent show -spiffeID "+Quote(id))
	if err != nil {
		return Agent{}, false
	}
	return ParseAgentShow(out)
}

// ParseAgentShow parses the output of "spire-server agent show".
func ParseAgentShow(out string) (Agent, bool) {
	var a Agent
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Serial number":
			a.Serial = strings.TrimSpace(value)
		case "Selectors":
			a.Selectors = append(a.Selectors, strings.TrimSpace(value))
		}
	}
	return a, a.Serial != ""
}

// SpireLog returns SPIRE Server's journal since a journalctl time
// specification, filtered by an extended regular expression if not empty.
func (l *Lab) SpireLog(ctx context.Context, since, pattern string) string {
	command := "sudo journalctl -u spire-server --no-pager -o cat --since " + Quote(since)
	if pattern != "" {
		command += " | grep -E " + Quote(pattern) + " || true"
	}
	out, _ := l.Run(ctx, "spire", command, nil)
	return out
}

// SpireHealthy reports whether SPIRE Server passes its health check.
func (l *Lab) SpireHealthy(ctx context.Context) error {
	_, err := l.SpireServer(ctx, "healthcheck")
	return err
}

// RestartSpire restarts SPIRE Server and waits for its health check.
func (l *Lab) RestartSpire(ctx context.Context, timeout time.Duration) error {
	if _, err := l.Run(ctx, "spire", "sudo systemctl restart spire-server", nil); err != nil {
		return err
	}
	return poll(ctx, timeout, 3*time.Second, "SPIRE Server healthy", func() error { return l.SpireHealthy(ctx) })
}

// --- Issuers ------------------------------------------------------------------

// IssuerConfig is the signer configuration file on the issuer VMs.
const IssuerConfig = "/etc/openstack-spire-issuer/signer.yaml"

// IssuerLog returns an issuer's journal since a journalctl time
// specification, with extra journalctl arguments (e.g. field matches).
func (l *Lab) IssuerLog(ctx context.Context, vm, since, extra string) (string, error) {
	return l.Run(ctx, vm, "sudo journalctl -u openstack-spire-issuer --no-pager --since "+Quote(since)+" "+extra, nil)
}

// IssuerReady checks an issuer's /readiness, from the devstack VM (where
// Nova calls from).
func (l *Lab) IssuerReady(ctx context.Context, vm string) error {
	_, err := l.Run(ctx, "devstack", "curl -sSf -m 10 --cacert /etc/nova/lab-ca.pem https://"+vm+".lab:8443/readiness", nil)
	return err
}

// WaitIssuerReady waits for an issuer's /readiness.
func (l *Lab) WaitIssuerReady(ctx context.Context, vm string, timeout time.Duration) error {
	return poll(ctx, timeout, 10*time.Second, vm+" ready", func() error { return l.IssuerReady(ctx, vm) })
}

// RestartIssuer restarts an issuer and waits until it is ready again (its
// first key is published ahead of use: about 2 minutes).
func (l *Lab) RestartIssuer(ctx context.Context, vm string) error {
	if _, err := l.Run(ctx, vm, "sudo systemctl restart openstack-spire-issuer", nil); err != nil {
		return err
	}
	return l.WaitIssuerReady(ctx, vm, 5*time.Minute)
}

// poll calls check every interval until it succeeds, timeout passes or ctx
// ends.
func poll(ctx context.Context, timeout, interval time.Duration, what string, check func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := check()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not %s within %v: %w", what, timeout, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", what, ctx.Err())
		case <-time.After(interval):
		}
	}
}
