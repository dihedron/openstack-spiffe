//go:build lab

package acceptance

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// issuerMetrics scrapes issuer-a's Prometheus endpoint, which listens on
// loopback only.
func (l *lab) issuerMetrics(t *testing.T) string {
	t.Helper()
	return l.must(t, "issuer-a", "curl -sf http://127.0.0.1:9464/metrics")
}

// series returns the sum of a Prometheus metric's series whose labels
// include every given one (name, value pairs).
func series(body, metric string, labels ...string) float64 {
	var total float64
	for _, line := range strings.Split(body, "\n") {
		name, rest, ok := strings.Cut(line, "{")
		if !ok || name != metric {
			continue
		}
		match := true
		for i := 0; i+1 < len(labels); i += 2 {
			match = match && strings.Contains(rest, labels[i]+`="`+labels[i+1]+`"`)
		}
		fields := strings.Fields(line)
		var v float64
		if _, err := fmt.Sscan(fields[len(fields)-1], &v); match && err == nil {
			total += v
		}
	}
	return total
}

// metricsInstance is a well-formed instance ID Nova does not know, distinct
// from the network tests' (the per-instance limit allows one call per 5s).
const metricsInstance = "5d1e8c2a-7b3f-4e6a-9c0d-1f2e3a4b5c6d"

// TestPrometheusMetrics is MET-1: issuer-a's metrics, scraped on loopback,
// count the tokens issued for a guest exactly as its audit records do, per
// project, and count refusals under their reasons; the metrics port is not
// reachable from another host.
func TestPrometheusMetrics(t *testing.T) {
	l := theLab
	project := l.env.OpenStack.ProjectID
	before := l.issuerMetrics(t)
	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"

	g := l.bootGuest(t, "ubuntu", "demo")
	l.waitAttested(t, l.agentID(g, project), "", attestTimeout)

	// refused at the guard: spire is not an allowed source
	if code := strings.TrimSpace(l.must(t, "spire", "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/spire/lab-ca.pem -X POST https://issuer-a.lab:8443/attest")); code != "403" {
		t.Errorf("/attest from spire: HTTP %s, want 403", code)
	}
	// refused at verification: Nova does not know the instance
	body := `{"project-id":"` + project + `","instance-id":"` + metricsInstance + `","hostname":"x","metadata":{}}`
	curl := `sudo curl -s -o /dev/null -w '%{http_code}' --cacert /etc/nova/lab-ca.pem --cert /etc/nova/lab-nova-vendordata.pem --key /etc/nova/lab-nova-vendordata.key` +
		` -H 'Content-Type: application/json' -H 'X-Auth-Token: ` + l.vendordataToken(t) + `' -d ` + quote(body) + ` https://issuer-a.lab:8443/attest`
	if code := strings.TrimSpace(l.must(t, "devstack", curl)); code != "403" {
		t.Errorf("/attest for an unknown instance: HTTP %s, want 403", code)
	}

	after := l.issuerMetrics(t)
	issued := strings.Count(l.issuerLog(t, "issuer-a", since, "_TRANSPORT=stdout -o cat"), "audit=token_issued")
	const tokens = "openstack_spire_tokens_issued_total"
	if delta := series(after, tokens, "project_id", project) - series(before, tokens, "project_id", project); delta != float64(issued) || issued == 0 {
		t.Errorf("%s for the demo project rose by %v, and %d token_issued records were written", tokens, delta, issued)
	}
	const requests = "openstack_spire_attest_requests_total"
	for _, reason := range []string{"source_not_allowed", "instance_not_allowed"} {
		if delta := series(after, requests, "reason", reason) - series(before, requests, "reason", reason); delta < 1 {
			t.Errorf("%s{reason=%q} did not rise", requests, reason)
		}
	}
	if series(after, requests, "reason", "unspecified") != 0 {
		t.Error("a refusal counted without a reason")
	}
	for _, metric := range []string{"openstack_spire_keys", "openstack_spire_readiness_check", "openstack_spire_jwks_fetches_total"} {
		if !strings.Contains(after, metric+"{") {
			t.Errorf("no %s", metric)
		}
	}

	// loopback only (I-8)
	if out, err := l.run("devstack", "curl -s -m 5 http://issuer-a.lab:9464/metrics", nil); err == nil {
		t.Errorf("the metrics port answered another host: %.200s", out)
	}
	t.Logf("%d tokens issued, counted for project %s", issued, project)
}

// TestOTLPMetrics is MET-2: issuer-b pushes its metrics over OTLP/HTTP and
// TLS to the OpenTelemetry Collector on spire, which receives them, with
// issuer-b's identity, within two export intervals.
func TestOTLPMetrics(t *testing.T) {
	l := theLab
	since := strings.TrimSpace(l.must(t, "spire", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	// a refused call, so that issuer-b has an /attest series to push
	if code := strings.TrimSpace(l.must(t, "spire", "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/spire/lab-ca.pem -X POST https://issuer-b.lab:8443/attest")); code != "403" {
		t.Errorf("/attest from spire: HTTP %s, want 403", code)
	}
	deadline := time.Now().Add(30 * time.Second) // two 10s intervals, with margin
	for {
		out := l.must(t, "spire", "sudo journalctl -u otelcol --no-pager -o cat --since "+quote(since))
		if strings.Contains(out, "openstack_spire.attest.requests") && strings.Contains(out, "service.instance.id: Str(issuer-b)") &&
			strings.Contains(out, "source_not_allowed") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collector did not receive issuer-b's /attest metrics within 30s:\n%.3000s", out)
		}
		time.Sleep(3 * time.Second)
	}
}
