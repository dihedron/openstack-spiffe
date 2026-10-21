package openstackiid

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	// wait, if set, runs before each answer, outside the lock
	wait func()
}

func newFakeAgentStore() *fakeAgentStore { return &fakeAgentStore{attested: map[string]bool{}} }

func (f *fakeAgentStore) GetAgentInfo(_ context.Context, req *agentstorev1.GetAgentInfoRequest) (*agentstorev1.GetAgentInfoResponse, error) {
	f.mu.Lock()
	f.asked = append(f.asked, req.GetAgentId())
	wait := f.wait
	f.mu.Unlock()
	if wait != nil {
		wait()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
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

// two attestations of one agent with different tokens, both checked before
// SPIRE Server records either: exactly one wins, the other is refused like
// an attested agent, without reaching the AgentStore
func TestTOFUConcurrentAttestations(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	logs := captureLogs(t)
	h.mustConfigure(t, "reattest = false\n")
	// hold each answer until both attempts asked, or long enough for the
	// second to have been refused without asking
	h.store.wait = func() {
		for range 50 {
			if len(h.store.questions()) >= 2 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		token := sign(t, es, nil, with(validClaims(), map[string]any{"jti": fmt.Sprintf("concurrent-%d", i)}))
		wg.Go(func() { _, errs[i] = h.attest(t, token) })
	}
	wg.Wait()
	refused := slices.IndexFunc(errs, func(err error) bool { return err != nil })
	if refused < 0 || errs[1-refused] != nil {
		t.Fatalf("attestations = %v, want exactly one success", errs)
	}
	wantCode(t, errs[refused], codes.PermissionDenied, "agent "+testAgentID+" is already attested and reattest is false")
	if !strings.Contains(logs.String(), "audit=reattest_refused") {
		t.Errorf("no reattest_refused record:\n%s", logs)
	}
	if got := h.store.questions(); len(got) != 1 {
		t.Errorf("the AgentStore was asked %d times, want once", len(got))
	}
}

// the reservation outlives a quick eviction, until the end of the token's
// acceptance window
func TestTOFUReservationExpires(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "reattest = false\n")
	claims := validClaims()
	if _, err := h.attest(t, sign(t, es, nil, claims)); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	// the store does not know the agent yet (or it was evicted): the
	// reservation still refuses a second presenter
	h.clock.Advance(time.Minute)
	fresh := func(jti string) string {
		iat := h.clock.Now().Add(-time.Second).Unix()
		return sign(t, es, nil, with(validClaims(), map[string]any{"jti": jti, "iat": iat, "nbf": iat, "exp": iat + 300}))
	}
	_, err := h.attest(t, fresh("second"))
	wantCode(t, err, codes.PermissionDenied, "already attested")
	// at exp + skew the reservation ends
	end := time.Unix(claims["exp"].(int64), 0).Add(30 * time.Second)
	h.clock.Advance(end.Sub(h.clock.Now()))
	if _, err := h.attest(t, fresh("third")); err != nil {
		t.Fatalf("refused once the reservation expired: %v", err)
	}
}

// a refusal by the replay cache releases the reservation
func TestTOFUReservationReleasedOnReplayRefusal(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.plugin.replay = newReplayCache(maxReplayEntries, testNow.Add(-15*time.Second))
	h.mustConfigure(t, "reattest = false\n")
	// minted within the tolerance after the start: the watermark refuses it
	_, err := h.attest(t, sign(t, es, nil, validClaims()))
	wantCode(t, err, codes.PermissionDenied, "before this server started")
	fresh := testNow.Add(20 * time.Second).Unix()
	if _, err := h.attest(t, sign(t, es, nil, with(validClaims(), map[string]any{"jti": "fresh", "iat": fresh, "nbf": fresh, "exp": fresh + 300}))); err != nil {
		t.Fatalf("refused after a replay refusal: %v", err)
	}
}

// full reservations fail closed
func TestTOFUReservationsFull(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.plugin.reservations = newExpiringSet(1)
	h.mustConfigure(t, "reattest = false\n")
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatal(err)
	}
	other := "0b6f2c1e-6d5a-4c3b-9a8f-7e6d5c4b3a29"
	_, err := h.attest(t, sign(t, es, nil, with(validClaims(), map[string]any{"jti": "other", "sub": other, "instance_id": other})))
	wantCode(t, err, codes.Unavailable, "reservations full")
}

func TestExpiringSet(t *testing.T) {
	s := newExpiringSet(1)
	if added, err := s.add("a", testNow.Add(time.Minute), testNow); !added || err != nil {
		t.Fatalf("add a = %v, %v", added, err)
	}
	if added, err := s.add("a", testNow.Add(time.Minute), testNow); added || err != nil {
		t.Fatalf("add a again = %v, %v, want present", added, err)
	}
	if _, err := s.add("b", testNow.Add(time.Minute), testNow); !errors.Is(err, errSetFull) {
		t.Fatalf("add b = %v, want errSetFull", err)
	}
	s.remove("a")
	if added, err := s.add("b", testNow.Add(time.Minute), testNow); !added || err != nil {
		t.Fatalf("add b after removing a = %v, %v", added, err)
	}
	// an expired key makes room, and is absent again
	later := testNow.Add(time.Minute)
	if added, err := s.add("b", later.Add(time.Minute), later); !added || err != nil {
		t.Fatalf("add expired b = %v, %v", added, err)
	}
}
