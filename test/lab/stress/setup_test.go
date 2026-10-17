//go:build lab

package main

import (
	"strings"
	"testing"
	"time"
)

const spireConfig = `server {
  bind_address = "0.0.0.0"
  log_level    = "INFO"
}

plugins {
  NodeAttestor "openstack_iid" {
    plugin_data {
      # the peered replicas' merged JWK Set (the lab has no load balancer)
      jwks_url            = "https://issuer-a.lab:8443/.well-known/jwks.json"
      allowed_project_ids = ["p"]
    }
  }
}
`

func TestEditSpireConfig(t *testing.T) {
	got := editSpireConfig(spireConfig, 15*time.Minute, true)
	if !strings.Contains(got, "server {\n  agent_ttl    = \"15m0s\"\n  bind_address") {
		t.Errorf("no agent_ttl in the server block:\n%s", got)
	}
	if !strings.Contains(got, "      reattest            = false\n      jwks_url") {
		t.Errorf("no reattest in the plugin's data:\n%s", got)
	}
	if editSpireConfig(spireConfig, 0, false) != spireConfig {
		t.Error("changed without agent_ttl or tofu")
	}
}

func TestParseQuotas(t *testing.T) {
	q, err := parseQuotas(`[{"Resource": "cores", "Limit": 20}, {"Resource": "instances", "Limit": 10}, {"Resource": "fixed_ips", "Limit": null}]`)
	if err != nil || q["cores"] != 20 || q["instances"] != 10 || q["fixed_ips"] != -1 {
		t.Errorf("quotas %v, %v", q, err)
	}
	q, err = parseQuotas(`{"cores": 20, "instances": 10, "ram": 51200, "project": "demo"}`)
	if err != nil || q["ram"] != 51200 {
		t.Errorf("quotas %v, %v", q, err)
	}
}

func TestPlacementSlots(t *testing.T) {
	inv := `{"inventories": {"VCPU": {"total": 8, "reserved": 0, "allocation_ratio": 4.0}, "MEMORY_MB": {"total": 24031, "reserved": 512, "allocation_ratio": 1.0}, "DISK_GB": {"total": 95, "reserved": 0, "allocation_ratio": 1.0}}}`
	use := `{"usages": {"VCPU": 2, "MEMORY_MB": 2048, "DISK_GB": 20}}`
	// disk: (95-20)/20 = 3; memory: (23519-2048)/2048 = 10; vcpu: (32-2)/2 = 15
	if free, total := placementSlots(inv, use, labGuest); free != 3 || total != 4 {
		t.Errorf("placementSlots = %d free, %d in all; want 3 and 4 (disk)", free, total)
	}
	if free, total := placementSlots("not json", use, labGuest); free != -1 || total != -1 {
		t.Errorf("placementSlots = %d, %d on bad input, want -1", free, total)
	}
}

func TestParseAgentsAndServers(t *testing.T) {
	agents, err := parseAgents(`{"agents":[{"can_reattest":true,"id":{"path":"/spire/agent/openstack_iid/p/i","trust_domain":"openstack.lab"},"selectors":[{"type":"openstack_iid","value":"project_id:p"}],"x509svid_expires_at":"1792216261","x509svid_serial_number":"995"}],"next_page_token":""}`)
	if err != nil || len(agents) != 1 {
		t.Fatalf("agents %v, %v", agents, err)
	}
	a := agents[0]
	if a.ID != "spiffe://openstack.lab/spire/agent/openstack_iid/p/i" || a.Serial != "995" || a.ExpiresAt.Unix() != 1792216261 || a.Selectors[0] != "openstack_iid:project_id:p" || !a.CanReattest {
		t.Errorf("agent %+v", a)
	}
	servers, err := parseServers(`[{"ID": "i", "Name": "stress-x", "Status": "ACTIVE", "Networks": {"private": ["fdf4::1", "10.0.0.36"]}}]`)
	if err != nil || len(servers) != 1 || servers[0].Address != "10.0.0.36" || servers[0].Status != "ACTIVE" {
		t.Errorf("servers %+v, %v", servers, err)
	}
}

func TestParseWorkloadCheck(t *testing.T) {
	c := parseWorkloadCheck("W_ID=spiffe://openstack.lab/stress/workload\nW_VERIFY=OK\nO_ERR=rpc error: code = PermissionDenied desc = no identity issued\nCHECK_DONE\n", nil)
	if !c.Reachable || c.WorkloadID != "spiffe://openstack.lab/stress/workload" || !c.Verified || c.OutsiderID != "" || c.OutsiderErr == "" {
		t.Errorf("check %+v", c)
	}
	c = parseWorkloadCheck("", errTimeout)
	if c.Reachable || c.Error == "" {
		t.Errorf("unreachable check %+v", c)
	}
}
