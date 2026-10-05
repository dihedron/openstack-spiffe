package openstackiid

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
)

// captureLogs sends the default logger's records to a buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestConfigureNewSettingsErrors(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	for name, extra := range map[string]string{
		"tag key with ':'":       "allowed_tag_keys = [\"a:b\"]\n",
		"tag key with a control": "allowed_tag_keys = [\"ro\\u0000le\"]\n",
		"alert window over 1h":   "reattest_alert_window = \"2h\"\n",
		"bad alert window":       "reattest_alert_window = \"soon\"\n",
		"unknown syslog key":     "audit_syslog {\n  enabld = true\n}\n",
		"unknown facility":       "audit_syslog {\n  facility = \"kern\"\n}\n",
		"bad app name":           "audit_syslog {\n  app_name = \"my plugin\"\n}\n",
	} {
		err := h.configure(t, "example.org", h.baseConfig()+extra)
		wantCode(t, err, codes.InvalidArgument, "")
		_ = name
	}
}

func TestConfigureWarnings(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	logs := captureLogs(t)
	// the base configuration pins the JWKS CA
	h.mustConfigure(t, "")
	out := logs.String()
	for _, want := range []string{"allowed_project_ids", "allowed_tag_keys", "audit_syslog"} {
		if !strings.Contains(out, "configuration warning") || !strings.Contains(out, want) {
			t.Errorf("no warning about %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "jwks_ca_cert_path") {
		t.Errorf("a warning about jwks_ca_cert_path although it is set:\n%s", out)
	}

	logs.Reset()
	if err := h.configure(t, "example.org", `jwks_url = "`+h.jwks.url()+`"`); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if !strings.Contains(logs.String(), "jwks_ca_cert_path") {
		t.Errorf("no warning about an unset jwks_ca_cert_path:\n%s", logs)
	}

	logs.Reset()
	socket := listenSyslog(t)
	h.mustConfigure(t, fmt.Sprintf("allowed_project_ids = [%q]\nallowed_tag_keys = [\"role\"]\naudit_syslog {\n  enabled = true\n  socket = %q\n}\n", testProjectID, socket.path))
	if strings.Contains(logs.String(), "configuration warning") {
		t.Errorf("configuration warnings with every setting in place:\n%s", logs)
	}
}

func TestReattestSetting(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "reattest = false\n")
	attrs, err := h.attest(t, sign(t, es, nil, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if attrs.CanReattest {
		t.Error("CanReattest with reattest = false")
	}
}

func TestAllowedTagKeys(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	logs := captureLogs(t)
	h.mustConfigure(t, "allowed_tag_keys = [\"role\"]\n")
	attrs, err := h.attest(t, sign(t, es, nil, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, s := range attrs.SelectorValues {
		if strings.HasPrefix(s, "tag:") {
			tags = append(tags, s)
		}
	}
	if !slices.Equal(tags, []string{"tag:role:web"}) {
		t.Errorf("tag selectors %v, want only tag:role:web", tags)
	}
	if !strings.Contains(logs.String(), "level=DEBUG") || !strings.Contains(logs.String(), "url") {
		t.Errorf("the ignored tag is not logged at debug:\n%s", logs)
	}
}

func TestSuccessRecord(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "")
	logs := captureLogs(t)
	claims := validClaims()
	token := sign(t, es, nil, claims)
	if _, err := h.attest(t, token); err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "agent attested") {
			line = l
		}
	}
	for _, want := range []string{
		"audit=agent_attested", "jti=" + claims["jti"].(string), "kid=" + es.kid,
		fmt.Sprintf("iat=%d", claims["iat"]), fmt.Sprintf("exp=%d", claims["exp"]),
		"project_id=" + testProjectID, "instance_id=" + testInstanceID, "spiffe_id=spiffe://example.org/", "selectors=",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("success record lacks %s: %s", want, line)
		}
	}
	if strings.Contains(logs.String(), strings.Split(token, ".")[2]) {
		t.Error("the token is in the logs")
	}
}

func TestReattestAlert(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	logs := captureLogs(t)
	h.mustConfigure(t, "")
	first, second := validClaims(), with(validClaims(), map[string]any{"jti": "6c2f9b7e-4a11-4c1e-8d0a-5b1f0f3e2f7a"})
	for _, c := range []map[string]any{first, second} {
		if _, err := h.attest(t, sign(t, es, nil, c)); err != nil {
			t.Fatalf("re-attestation refused: %v", err)
		}
	}
	out := logs.String()
	if !strings.Contains(out, "possible token theft: instance re-attested") ||
		!strings.Contains(out, "audit=reattest_alert") ||
		!strings.Contains(out, "jti="+second["jti"].(string)) || !strings.Contains(out, "previous_jti="+first["jti"].(string)) {
		t.Fatalf("no re-attestation alert with both jtis:\n%s", out)
	}

	// window 0: no alert
	h = serve(t, es)
	logs.Reset()
	h.mustConfigure(t, "reattest_alert_window = \"0s\"\n")
	third := with(validClaims(), map[string]any{"jti": "7d3fac8f-5b22-4d2f-9e1b-6c3fac8f3a8b"})
	fourth := with(validClaims(), map[string]any{"jti": "8e40bd90-6c33-4e30-af2c-7d40bd904b9c"})
	for _, c := range []map[string]any{third, fourth} {
		if _, err := h.attest(t, sign(t, es, nil, c)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(logs.String(), "re-attested") {
		t.Errorf("an alert with the window disabled:\n%s", logs)
	}
}

// syslogSocket is a Unix datagram socket standing in for /dev/log.
type syslogSocket struct {
	path string
	conn *net.UnixConn
}

func listenSyslog(t *testing.T) *syslogSocket {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &syslogSocket{path: path, conn: conn}
}

// receive returns the PRI and the JSON record of the next datagram, if one
// arrives within the timeout.
func (s *syslogSocket) receive(t *testing.T, timeout time.Duration) (string, map[string]any, bool) {
	t.Helper()
	if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	n, err := s.conn.Read(buf)
	if err != nil {
		return "", nil, false
	}
	datagram := string(buf[:n])
	pri, _, _ := strings.Cut(datagram, ">")
	_, text, ok := strings.Cut(datagram, "]: ")
	var record map[string]any
	if !ok || json.Unmarshal([]byte(text), &record) != nil {
		t.Fatalf("not RFC 3164 with a JSON record: %q", datagram)
	}
	return pri + ">", record, true
}

func TestAuditSyslog(t *testing.T) {
	_, es, other := testKeys(t)
	h := serve(t, es)
	socket := listenSyslog(t)
	h.mustConfigure(t, fmt.Sprintf("audit_syslog {\n  enabled = true\n  socket = %q\n}\n", socket.path))

	// a rejection never reaches syslog
	if _, err := h.attest(t, sign(t, other, nil, validClaims())); err == nil {
		t.Fatal("a token of an unknown key accepted")
	}
	first, second := validClaims(), with(validClaims(), map[string]any{"jti": "6c2f9b7e-4a11-4c1e-8d0a-5b1f0f3e2f7a"})
	if _, err := h.attest(t, sign(t, es, nil, first)); err != nil {
		t.Fatal(err)
	}
	pri, record, ok := socket.receive(t, 2*time.Second)
	// authpriv (10) * 8 + informational (6)
	if !ok || pri != "<86>" || record["audit"] != "agent_attested" || record["jti"] != first["jti"] {
		t.Fatalf("first datagram %s %v (%v), want <86> agent_attested with the token's jti", pri, record, ok)
	}
	if _, err := h.attest(t, sign(t, es, nil, second)); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for range 2 {
		pri, record, ok := socket.receive(t, 2*time.Second)
		if !ok {
			t.Fatal("a datagram is missing")
		}
		kinds[record["audit"].(string)] = pri
	}
	// authpriv (10) * 8 + warning (4)
	if kinds["agent_attested"] != "<86>" || kinds["reattest_alert"] != "<84>" {
		t.Fatalf("datagrams %v, want agent_attested <86> and reattest_alert <84>", kinds)
	}
	if _, _, ok := socket.receive(t, 300*time.Millisecond); ok {
		t.Error("an unexpected datagram")
	}

	// a new socket in the settings replaces the sink
	moved := listenSyslog(t)
	h.mustConfigure(t, fmt.Sprintf("audit_syslog {\n  enabled = true\n  socket = %q\n}\n", moved.path))
	third := with(validClaims(), map[string]any{"jti": "7d3fac8f-5b22-4d2f-9e1b-6c3fac8f3a8b", "instance_id": "1f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a", "sub": "1f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"})
	if _, err := h.attest(t, sign(t, es, nil, third)); err != nil {
		t.Fatal(err)
	}
	if _, record, ok := moved.receive(t, 2*time.Second); !ok || record["jti"] != third["jti"] {
		t.Fatalf("the new socket got %v (%v)", record, ok)
	}
}

func TestAuditSyslogUnopenableSocket(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	missing := filepath.Join(t.TempDir(), "no-log")
	err := h.configure(t, "example.org", h.baseConfig()+fmt.Sprintf("audit_syslog {\n  enabled = true\n  socket = %q\n}\n", missing))
	wantCode(t, err, codes.InvalidArgument, "")
	if _, statErr := os.Stat(missing); statErr == nil {
		t.Error("the socket path was created")
	}
}
