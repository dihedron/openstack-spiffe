package integration

import (
	"bytes"
	"encoding/json/v2"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/metadata/requestid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of the
// replicas' goroutines and the test's reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// auditRecords returns the audit records of the given kind logged so far.
func (b *syncBuffer) auditRecords(t *testing.T, kind string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	logs := b.buf.String()
	b.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(logs) {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		if r[syslog.AuditKey] == kind {
			out = append(out, r)
		}
	}
	return out
}

// TestAuditTrail checks the issuer's audit records (R-1, R-3) on running
// replicas: the token_issued record of a token carries its jti and kid, and
// the key_lifecycle records tie that kid to the replica and to the key
// material published in the JWKS.
func TestAuditTrail(t *testing.T) {
	logs := &syncBuffer{}
	previous := slog.Default()
	// as service start installs it, so that records carry the request ID
	slog.SetDefault(slog.New(requestid.NewLogHandler(slog.NewJSONHandler(logs, nil))))
	t.Cleanup(func() { slog.SetDefault(previous) })

	s := start(t, topologies[0])
	jwt, header, claims := s.mint(t, "signer-a")

	var issued []map[string]any
	for _, r := range logs.auditRecords(t, "token_issued") {
		if r["jti"] == claims.ID {
			issued = append(issued, r)
		}
	}
	if len(issued) != 1 {
		t.Fatalf("%d token_issued records with jti %s, want 1", len(issued), claims.ID)
	}
	if r := issued[0]; r["kid"] != header.KeyID || r["instance_id"] != claims.InstanceID || r["user_id"] == nil || r["request_id"] == nil {
		t.Fatalf("token_issued record %v does not match the token (kid %s, instance %s) or lacks user_id/request_id", r, header.KeyID, claims.InstanceID)
	}

	key, ok := s.keysAt(t, s.signers["signer-a"]+"/jwks/local.json")[header.KeyID]
	if !ok {
		t.Fatalf("kid %s not published by signer-a", header.KeyID)
	}
	thumbprint, err := keystore.Thumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	events := map[string]bool{}
	for _, r := range logs.auditRecords(t, "key_lifecycle") {
		if r["kid"] != header.KeyID {
			continue
		}
		if r["replica_id"] != "signer-a" || r["thumbprint"] != thumbprint {
			t.Fatalf("key_lifecycle record %v, want replica signer-a and thumbprint %s", r, thumbprint)
		}
		events[r["event"].(string)] = true
	}
	for _, event := range []string{"generated", "published", "active"} {
		if !events[event] {
			t.Errorf("no %s record for the signing key %s", event, header.KeyID)
		}
	}

	logs.mu.Lock()
	out := logs.buf.String()
	logs.mu.Unlock()
	if strings.Contains(out, jwt) {
		t.Fatal("the token appears in the logs")
	}
}
