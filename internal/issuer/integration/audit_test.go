package integration

import (
	"bytes"
	"encoding/json/v2"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
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
	// start installs the request ID and syslog handlers around this one
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
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

	// the same records reach syslog (R-1, R-3)
	datagrams := s.syslog.received(t, "token_issued", func(d map[string]any) bool { return d["jti"] == claims.ID })
	if len(datagrams) != 1 || datagrams[0]["kid"] != header.KeyID || datagrams[0]["request_id"] != issued[0]["request_id"] {
		t.Fatalf("token_issued datagrams for jti %s: %v, want exactly one with kid %s and request_id %v", claims.ID, datagrams, header.KeyID, issued[0]["request_id"])
	}
	lifecycle := map[string]bool{}
	for _, d := range s.syslog.received(t, "key_lifecycle", func(d map[string]any) bool { return d["kid"] == header.KeyID }) {
		if d["thumbprint"] == thumbprint {
			lifecycle[d["event"].(string)] = true
		}
	}
	for _, event := range []string{"generated", "published", "active"} {
		if !lifecycle[event] {
			t.Errorf("no %s datagram for the signing key %s", event, header.KeyID)
		}
	}

	logs.mu.Lock()
	out := logs.buf.String()
	logs.mu.Unlock()
	if strings.Contains(out, jwt) {
		t.Fatal("the token appears in the logs")
	}
}

// syslogDaemon stands in for the local syslog daemon: it collects the
// datagrams sent to its socket, so that the socket never fills up.
type syslogDaemon struct {
	path      string
	mu        sync.Mutex
	datagrams []string
}

func newSyslogDaemon(t *testing.T) *syslogDaemon {
	t.Helper()
	d := &syslogDaemon{path: filepath.Join(t.TempDir(), "log")}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: d.path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listening on %s: %v", d.path, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			d.mu.Lock()
			d.datagrams = append(d.datagrams, string(buf[:n]))
			d.mu.Unlock()
		}
	}()
	// registered first, so it runs after the sink has been drained
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return d
}

// received returns the JSON messages of the datagrams of the given audit
// kind that match, waiting briefly for the sink's asynchronous delivery of the
// first one.
func (d *syslogDaemon) received(t *testing.T, kind string, match func(map[string]any) bool) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var out []map[string]any
		d.mu.Lock()
		for _, datagram := range d.datagrams {
			// RFC 3164: <PRI>Mmm dd hh:mm:ss TAG[PID]: MSG, the kind in MSG
			_, text, ok := strings.Cut(datagram, "]: ")
			var msg map[string]any
			if !ok || json.Unmarshal([]byte(text), &msg) != nil {
				d.mu.Unlock()
				t.Fatalf("datagram %q: not RFC 3164 with a JSON MSG", datagram)
			}
			if msg["audit"] != kind {
				continue
			}
			if match(msg) {
				out = append(out, msg)
			}
		}
		d.mu.Unlock()
		if len(out) > 0 || time.Now().After(deadline) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
}
