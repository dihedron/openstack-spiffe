//go:build lab

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/test/lab/labkit"
)

// kitLab is the lab, through labkit.
type kitLab struct {
	kit *labkit.Lab
}

const (
	stressPrefix  = "stress-"
	guestSocket   = "/run/spire/agent/public/api.sock"
	agentBinary   = "/opt/spire/bin/spire-agent"
	issuerMetrics = "http://127.0.0.1:9464/metrics"
)

func (l *kitLab) demo(ctx context.Context, args ...string) (string, error) {
	return l.kit.OpenStack(ctx, "demo", "demo", args...)
}

func (l *kitLab) admin(ctx context.Context, args ...string) (string, error) {
	return l.kit.OpenStack(ctx, "admin", "admin", args...)
}

func (l *kitLab) Stream(ctx context.Context, vm, command string) (io.ReadCloser, error) {
	return l.kit.Stream(ctx, vm, command)
}

// --- Nova -----------------------------------------------------------------------

func (l *kitLab) CreateServer(ctx context.Context, name, distro string) (string, error) {
	g, err := l.kit.CreateGuest(ctx, name, distro, "demo", false)
	return g.ID, err
}

func (l *kitLab) ServerAction(ctx context.Context, id, action string) error {
	_, err := l.demo(ctx, "server", action, id)
	return err
}

func (l *kitLab) ServerFault(ctx context.Context, id string) (string, error) {
	out, err := l.demo(ctx, "server", "show", "-f", "json", "-c", "fault", id)
	if err != nil {
		return "", err
	}
	var s struct {
		Fault json.RawMessage `json:"fault"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return strings.TrimSpace(out), nil
	}
	var fault struct {
		Message string `json:"message"`
		Details string `json:"details"`
	}
	if json.Unmarshal(s.Fault, &fault) == nil && fault.Message != "" {
		return fault.Message, nil
	}
	return string(s.Fault), nil
}

// ListServers lists every stress instance, of this run or a previous one.
func (l *kitLab) ListServers(ctx context.Context) ([]Server, error) {
	out, err := l.demo(ctx, "server", "list", "--name", "^"+stressPrefix, "-f", "json", "-c", "ID", "-c", "Name", "-c", "Status", "-c", "Networks")
	if err != nil {
		return nil, err
	}
	return parseServers(out)
}

func parseServers(out string) ([]Server, error) {
	var rows []struct {
		ID       string          `json:"ID"`
		Name     string          `json:"Name"`
		Status   string          `json:"Status"`
		Networks json.RawMessage `json:"Networks"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("parsing the server list: %w", err)
	}
	servers := make([]Server, len(rows))
	for i, r := range rows {
		servers[i] = Server{ID: r.ID, Name: r.Name, Status: r.Status, Address: labkit.PrivateAddress(string(r.Networks))}
	}
	return servers, nil
}

// --- SPIRE ----------------------------------------------------------------------

func (l *kitLab) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	out, err := l.kit.SpireServer(ctx, "agent list -output json")
	if err != nil {
		return nil, err
	}
	return parseAgents(out)
}

func parseAgents(out string) ([]AgentInfo, error) {
	var list struct {
		Agents []struct {
			ID struct {
				Path        string `json:"path"`
				TrustDomain string `json:"trust_domain"`
			} `json:"id"`
			Selectors []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"selectors"`
			ExpiresAt   string `json:"x509svid_expires_at"`
			Serial      string `json:"x509svid_serial_number"`
			CanReattest bool   `json:"can_reattest"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("parsing the agent list: %w", err)
	}
	agents := make([]AgentInfo, len(list.Agents))
	for i, a := range list.Agents {
		info := AgentInfo{ID: "spiffe://" + a.ID.TrustDomain + a.ID.Path, Serial: a.Serial, CanReattest: a.CanReattest}
		if sec, err := strconv.ParseInt(a.ExpiresAt, 10, 64); err == nil {
			info.ExpiresAt = time.Unix(sec, 0)
		}
		for _, s := range a.Selectors {
			info.Selectors = append(info.Selectors, s.Type+":"+s.Value)
		}
		agents[i] = info
	}
	return agents, nil
}

func (l *kitLab) EvictAgent(ctx context.Context, agentID string) error {
	_, err := l.kit.SpireServer(ctx, "agent evict -spiffeID "+labkit.Quote(agentID))
	return err
}

func (l *kitLab) AgentShow(ctx context.Context, agentID string) (string, error) {
	return l.kit.SpireServer(ctx, "agent show -spiffeID "+labkit.Quote(agentID))
}

// CreateEntry creates a registration entry and returns its ID.
func (l *kitLab) CreateEntry(ctx context.Context, args string) (string, error) {
	out, err := l.kit.SpireServer(ctx, "entry create "+args+" -output json")
	if err != nil {
		return "", err
	}
	var r struct {
		Results []struct {
			Entry struct {
				ID string `json:"id"`
			} `json:"entry"`
			Status struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Results) != 1 {
		return "", fmt.Errorf("parsing the created entry: %q", out)
	}
	if r.Results[0].Status.Code != 0 {
		return "", fmt.Errorf("creating the entry: %s", r.Results[0].Status.Message)
	}
	return r.Results[0].Entry.ID, nil
}

// EntryIDs is the IDs of the entries with a SPIFFE ID.
func (l *kitLab) EntryIDs(ctx context.Context, spiffeID string) ([]string, error) {
	out, err := l.kit.SpireServer(ctx, "entry show -spiffeID "+labkit.Quote(spiffeID)+" -output json")
	if err != nil {
		return nil, err
	}
	var r struct {
		Entries []struct {
			ID string `json:"id"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return nil, fmt.Errorf("parsing the entries: %w", err)
	}
	ids := make([]string, len(r.Entries))
	for i, e := range r.Entries {
		ids[i] = e.ID
	}
	return ids, nil
}

func (l *kitLab) DeleteEntry(ctx context.Context, id string) error {
	_, err := l.kit.SpireServer(ctx, "entry delete -entryID "+labkit.Quote(id))
	return err
}

// --- Guests -----------------------------------------------------------------------

func (l *kitLab) guest(s Server, distro string) labkit.Guest {
	return labkit.Guest{Name: s.Name, ID: s.ID, Project: "demo", Distro: distro}
}

// workloadScript fetches the workload user's SVID and checks its chain, then
// the outsider's, which must be refused.
const workloadScript = `S=` + guestSocket + ` A=` + agentBinary + `
fetch() { out=$(sudo -u "$1" "$A" api fetch x509 -socketPath "$S" -timeout 5s ${2:+-write "$2"} 2>&1); rc=$?; }
oneline() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-300; }
spiffe_id() { printf '%s\n' "$1" | sed -n 's/^SPIFFE ID:[[:space:]]*//p' | head -n1; }
d=$(sudo -u workload mktemp -d)
fetch workload "$d"
if [ $rc -eq 0 ]; then
	echo "W_ID=$(spiffe_id "$out")"
	if sudo -u workload openssl verify -CAfile "$d/bundle.0.pem" -untrusted "$d/svid.0.pem" "$d/svid.0.pem" >/dev/null 2>&1; then echo W_VERIFY=OK; else echo W_VERIFY=FAIL; fi
else
	echo "W_ERR=$(oneline "$out")"
fi
sudo rm -rf "$d"
fetch outsider ""
if [ $rc -eq 0 ]; then echo "O_ID=$(spiffe_id "$out")"; else echo "O_ERR=$(oneline "$out")"; fi
echo CHECK_DONE`

func (l *kitLab) CheckWorkload(ctx context.Context, s Server, distro string) WorkloadCheck {
	out, err := l.kit.GuestRun(ctx, l.guest(s, distro), s.Address, workloadScript)
	return parseWorkloadCheck(out, err)
}

func parseWorkloadCheck(out string, err error) WorkloadCheck {
	c := WorkloadCheck{}
	if !strings.Contains(out, "CHECK_DONE") {
		c.Error = strings.TrimSpace(out)
		if err != nil {
			c.Error = err.Error()
		}
		return c
	}
	c.Reachable = true
	for _, line := range strings.Split(out, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "W_ID":
			c.WorkloadID = value
		case "W_VERIFY":
			c.Verified = value == "OK"
		case "W_ERR":
			c.WorkloadErr = value
		case "O_ID":
			c.OutsiderID = value
		case "O_ERR":
			c.OutsiderErr = value
		}
	}
	return c
}

const guestStateScript = `test -x ` + agentBinary + ` && echo AGENT_INSTALLED=yes
echo AGENT_ACTIVE=$(systemctl is-active spire-agent)
echo '--- spire-agent journal'; sudo journalctl -u spire-agent -n 200 --no-pager
echo '--- cloud-init output'; sudo tail -n 100 /var/log/cloud-init-output.log`

func (l *kitLab) GuestState(ctx context.Context, s Server, distro string) GuestState {
	if s.Address == "" {
		return GuestState{Output: "no address"}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := l.kit.GuestRun(ctx, l.guest(s, distro), s.Address, guestStateScript)
	st := GuestState{Output: out}
	if err != nil && !strings.Contains(out, "AGENT_ACTIVE=") {
		st.Output = out + "\n" + err.Error()
		return st
	}
	st.Reachable = true
	st.AgentInstalled = strings.Contains(out, "AGENT_INSTALLED=yes")
	st.AgentActive = strings.Contains(out, "AGENT_ACTIVE=active")
	return st
}

func (l *kitLab) ConsoleLog(ctx context.Context, id string) (string, error) {
	return l.kit.ConsoleLog(ctx, labkit.Guest{ID: id, Project: "demo"})
}

// WipeAgent makes a guest's agent lose its state and attest again (the
// self-test's TOFU step, as E2E-2 does).
func (l *kitLab) WipeAgent(ctx context.Context, s Server, distro string) error {
	_, err := l.kit.GuestRun(ctx, l.guest(s, distro), s.Address, "sudo systemctl stop spire-agent && sudo rm -rf /var/lib/spire/agent/* && sudo systemctl start spire-agent")
	return err
}

// --- Capacity and samples -----------------------------------------------------------

// placementScript prints the compute host's inventories and usages from the
// Placement API (no osc-placement plugin needed).
const placementScript = `set -e
cd /opt/stack
sudo -u stack bash -c '
set +u; source /opt/stack/devstack/openrc admin admin >/dev/null 2>&1; set -u
token=$(openstack token issue -f value -c id)
url=$(openstack endpoint list --service placement --interface public -f value -c URL | head -n1)
h=(-sS -m 20 -H "X-Auth-Token: $token" -H "OpenStack-API-Version: placement 1.10")
[ -n "${OS_CACERT:-}" ] && h+=(--cacert "$OS_CACERT")
rp=$(curl "${h[@]}" "$url/resource_providers" | python3 -c "import json,sys; print(json.load(sys.stdin)[\"resource_providers\"][0][\"uuid\"])")
echo "INVENTORIES=$(curl "${h[@]}" "$url/resource_providers/$rp/inventories")"
echo "USAGES=$(curl "${h[@]}" "$url/resource_providers/$rp/usages")"
'
grep MemAvailable /proc/meminfo`

// Capacity probes what the parallelism target needs from the lab; values
// it cannot get are -1.
func (l *kitLab) Capacity(ctx context.Context, flavor Flavor) (placementFree, placementTotal int, devstackAvailMiB int64, err error) {
	out, err := l.kit.Run(ctx, "devstack", placementScript, nil)
	placementFree, placementTotal, devstackAvailMiB = -1, -1, -1
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "MemAvailable:"):
			if kb, perr := strconv.ParseInt(strings.Fields(line)[1], 10, 64); perr == nil {
				devstackAvailMiB = kb / 1024
			}
		case strings.HasPrefix(line, "INVENTORIES="):
			inventories := strings.TrimPrefix(line, "INVENTORIES=")
			for _, l2 := range strings.Split(out, "\n") {
				if usages, ok := strings.CutPrefix(l2, "USAGES="); ok {
					placementFree, placementTotal = placementSlots(inventories, usages, flavor)
				}
			}
		}
	}
	return placementFree, placementTotal, devstackAvailMiB, err
}

// Flavor is the guests' flavor.
type Flavor struct {
	VCPUs  int64
	RAMMiB int64
	DiskGB int64
}

var labGuest = Flavor{VCPUs: 2, RAMMiB: 2048, DiskGB: 20} // devstack.sh, devstack_guest_access

// placementSlots is how many more instances of a flavor the inventories
// can allocate, given the usages, and how many they hold in all.
func placementSlots(inventoriesJSON, usagesJSON string, f Flavor) (free, total int) {
	var inv struct {
		Inventories map[string]struct {
			Total           int64   `json:"total"`
			Reserved        int64   `json:"reserved"`
			AllocationRatio float64 `json:"allocation_ratio"`
		} `json:"inventories"`
	}
	var use struct {
		Usages map[string]int64 `json:"usages"`
	}
	if json.Unmarshal([]byte(inventoriesJSON), &inv) != nil || json.Unmarshal([]byte(usagesJSON), &use) != nil {
		return -1, -1
	}
	free, total = -1, -1
	for class, need := range map[string]int64{"VCPU": f.VCPUs, "MEMORY_MB": f.RAMMiB, "DISK_GB": f.DiskGB} {
		i, ok := inv.Inventories[class]
		if !ok || need <= 0 {
			continue
		}
		capacity := int64(float64(i.Total-i.Reserved) * i.AllocationRatio)
		if n := int(max(capacity-use.Usages[class], 0) / need); free < 0 || n < free {
			free = n
		}
		if n := int(capacity / need); total < 0 || n < total {
			total = n
		}
	}
	return free, total
}

// RSS is the resident memory, in KiB, of the processes named on a VM.
func (l *kitLab) RSS(ctx context.Context, vm string, names ...string) (map[string]int64, error) {
	out, err := l.kit.Run(ctx, vm, "for n in "+strings.Join(names, " ")+"; do echo \"$n $(ps -C $n -o rss= | awk '{ s += $1 } END { print s+0 }')\"; done", nil)
	if err != nil {
		return nil, err
	}
	rss := map[string]int64{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if name, value, ok := strings.Cut(line, " "); ok {
			if kb, err := strconv.ParseInt(value, 10, 64); err == nil {
				rss[name] = kb
			}
		}
	}
	return rss, nil
}

// TokensIssued is issuer-a's openstack_spire_tokens_issued_total, summed
// over its series (0 before the first token).
func (l *kitLab) TokensIssued(ctx context.Context) (int64, error) {
	out, err := l.kit.Run(ctx, "issuer-a", "curl -sSf -m 10 "+issuerMetrics, nil)
	if err != nil {
		return 0, err
	}
	var total float64
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "openstack_spire_tokens_issued_total") {
			continue
		}
		fields := strings.Fields(line)
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			total += v
		}
	}
	return int64(total), nil
}

// hostMemAvailMiB and hostLoad read the lab host's own state.
func hostMemAvailMiB() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			if kb, err := strconv.ParseInt(strings.Fields(line)[1], 10, 64); err == nil {
				return kb / 1024
			}
		}
	}
	return -1
}

func hostLoad() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	return v
}
