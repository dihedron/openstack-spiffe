package openstackiid

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAgentStore is SPIRE Server's AgentStore host service, knowing the
// agents in attested.
type fakeAgentStore struct {
	agentstorev1.UnimplementedAgentStoreServer

	mu       sync.Mutex
	attested map[string]bool
	err      error
	asked    []string
}

func newFakeAgentStore() *fakeAgentStore { return &fakeAgentStore{attested: map[string]bool{}} }

func (f *fakeAgentStore) GetAgentInfo(_ context.Context, req *agentstorev1.GetAgentInfoRequest) (*agentstorev1.GetAgentInfoResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, req.GetAgentId())
	if f.err != nil {
		return nil, f.err
	}
	if !f.attested[req.GetAgentId()] {
		return nil, status.Errorf(codes.NotFound, "no attested agent %s", req.GetAgentId())
	}
	return &agentstorev1.GetAgentInfoResponse{Info: &agentstorev1.AgentInfo{AgentId: req.GetAgentId()}}, nil
}

func (f *fakeAgentStore) set(agentID string, attested bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attested[agentID] = attested
}

func (f *fakeAgentStore) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

const testAgentID = "spiffe://example.org/spire/agent/openstack_iid/" + testProjectID + "/" + testInstanceID

// TOFU (S-4, E-4): with reattest = false, an attested agent is refused
// until evicted, and the refused token stays unused.
func TestTOFURefusesAnAttestedAgent(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	logs := captureLogs(t)
	h.mustConfigure(t, "reattest = false\n")
	h.store.set(testAgentID, true)
	token := sign(t, es, nil, validClaims())
	_, err := h.attest(t, token)
	wantCode(t, err, codes.PermissionDenied, "agent "+testAgentID+" is already attested and reattest is false: evict it to attest again")
	if out := logs.String(); !strings.Contains(out, "audit=reattest_refused") || !strings.Contains(out, "jti="+validClaims()["jti"].(string)) ||
		!strings.Contains(out, "instance_id="+testInstanceID) || !strings.Contains(out, "level=WARN") {
		t.Errorf("no reattest_refused warning with the instance and the jti:\n%s", out)
	}
	if got := h.store.questions(); len(got) != 1 || got[0] != testAgentID {
		t.Errorf("the AgentStore was asked about %v, want the agent's ID once", got)
	}
	// once evicted, the agent attests with the same token: the refusal did
	// not burn its jti
	h.store.set(testAgentID, false)
	attrs, err := h.attest(t, token)
	if err != nil {
		t.Fatalf("the evicted agent is refused: %v", err)
	}
	if attrs.CanReattest {
		t.Error("CanReattest with reattest = false")
	}
}

func TestTOFUFirstAttestation(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "reattest = false\n")
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatalf("a first attestation refused: %v", err)
	}
	if got := h.store.questions(); len(got) != 1 {
		t.Errorf("the AgentStore was asked %d times, want once", len(got))
	}
}

// any other answer of the host service fails closed
func TestTOFUHostServiceError(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "reattest = false\n")
	h.store.err = status.Error(codes.Internal, "datastore unavailable")
	token := sign(t, es, nil, validClaims())
	_, err := h.attest(t, token)
	wantCode(t, err, codes.Unavailable, "checking whether the agent is attested")
	// the failure did not burn the jti either
	h.store.err = nil
	if _, err := h.attest(t, token); err != nil {
		t.Fatalf("refused once the host service is back: %v", err)
	}
}

// the store is asked only about verified tokens, and only in TOFU mode
func TestTOFUAskedOnlyWhenNeeded(t *testing.T) {
	_, es, other := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "reattest = false\n")
	if _, err := h.attest(t, sign(t, other, nil, validClaims())); err == nil {
		t.Fatal("a token of an unknown key accepted")
	}
	if got := h.store.questions(); len(got) != 0 {
		t.Errorf("the AgentStore was asked about an unverified token: %v", got)
	}
	h.mustConfigure(t, "")
	h.store.set(testAgentID, true)
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatalf("re-attestation refused with reattest = true: %v", err)
	}
	if got := h.store.questions(); len(got) != 0 {
		t.Errorf("the AgentStore was asked with reattest = true: %v", got)
	}
}

func TestTOFUNeedsTheHostService(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serveWith(t, nil, es)
	err := h.configure(t, "example.org", h.baseConfig()+"reattest = false\n")
	if err == nil || !strings.Contains(err.Error(), "AgentStore") || !strings.Contains(err.Error(), "reattest") {
		t.Fatalf("Configure = %v, want an error naming reattest and the AgentStore host service", err)
	}
	h.mustConfigure(t, "")
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatalf("reattest = true needs no host service: %v", err)
	}
}

func TestTOFURefusalToSyslog(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	socket := listenSyslog(t)
	h.mustConfigure(t, fmt.Sprintf("reattest = false\naudit_syslog {\n  enabled = true\n  socket = %q\n}\n", socket.path))
	h.store.set(testAgentID, true)
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err == nil {
		t.Fatal("an attested agent accepted")
	}
	pri, record, ok := socket.receive(t, 2*time.Second)
	// authpriv (10) * 8 + warning (4)
	if !ok || pri != "<84>" || record["audit"] != "reattest_refused" || record["jti"] != validClaims()["jti"] || record["instance_id"] != testInstanceID {
		t.Fatalf("datagram %s %v (%v), want <84> reattest_refused with the jti and the instance", pri, record, ok)
	}
}
