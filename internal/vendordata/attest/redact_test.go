package attest

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name, body string
		keep       []string
	}{
		{"object", `{"project-id":"p","user-data":"SECRET"}`, []string{`"project-id":"p"`, `"user-data":"[redacted]"`}},
		{"duplicate user-data", `{"user-data":"SECRET","user-data":"SECRET2","hostname":"vm"}`, []string{`"hostname":"vm"`}},
		{"escaped key", `{"user-data":"SECRET"}`, []string{`[redacted]`}},
		{"malformed", `{"project-id":"p","user-data":"SECRET", oops`, []string{`"project-id":"p"`, `[redacted]`}},
		{"no user-data", `not json at all`, []string{`not json at all`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact([]byte(tt.body))
			if strings.Contains(got, "SECRET") {
				t.Fatalf("redact(%s) = %s: user-data leaked", tt.body, got)
			}
			for _, want := range tt.keep {
				if !strings.Contains(got, want) {
					t.Fatalf("redact(%s) = %s, want it to contain %s", tt.body, got, want)
				}
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate([]byte(strings.Repeat("x", maxLoggedPayload))); len(got) != maxLoggedPayload {
		t.Fatalf("payload at the limit changed: %d bytes", len(got))
	}
	got := truncate([]byte(strings.Repeat("x", maxLoggedPayload+1)))
	if !strings.HasSuffix(got, "(truncated)") || strings.Count(got, "x") != maxLoggedPayload {
		t.Fatalf("truncate = %q", got)
	}
}
