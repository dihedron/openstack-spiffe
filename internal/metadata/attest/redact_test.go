package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// escaped spells a JSON member name with its first letter as a \u escape,
// which a parser reads as the plain name.
func escaped(name string) string {
	return `\` + "u00" + hex.EncodeToString([]byte(name[:1])) + name[1:]
}

func TestRedactObjects(t *testing.T) {
	tests := []struct {
		name, body string
		keep       []string
	}{
		{"user-data", `{"project-id":"p","user-data":"SECRET"}`, []string{`"project-id":"p"`, `"user-data":"[redacted]"`}},
		{"duplicate user-data", `{"user-data":"SECRET","user-data":"SECRET2","hostname":"vm"}`, []string{`"hostname":"vm"`}},
		{"escaped user-data", `{"` + escaped("user-data") + `":"SECRET"}`, []string{`"user-data":"[redacted]"`}},
		{"metadata values", `{"metadata":{"db_password":"SECRET","role":"SECRET2","n":1}}`, []string{`"db_password":"[redacted]"`, `"role":"[redacted]"`, `"n":"[redacted]"`}},
		{"escaped metadata", `{"` + escaped("metadata") + `":{"token":"SECRET"}}`, []string{`"token":"[redacted]"`}},
		{"duplicate metadata", `{"metadata":{"a":"SECRET"},"metadata":{"k":"SECRET2"}}`, []string{`"k":"[redacted]"`}},
		{"metadata not an object", `{"metadata":["SECRET"]}`, []string{`"metadata":"[redacted]"`}},
		{"nested metadata", `{"metadata":{"k":{"deep":"SECRET"}}}`, []string{`"k":"[redacted]"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := redact([]byte(tt.body))
			if len(attrs) != 2 || attrs[0] != "payload" {
				t.Fatalf("redact(%s) = %v, want a payload attribute", tt.body, attrs)
			}
			got := attrs[1].(string)
			if strings.Contains(got, "SECRET") {
				t.Fatalf("redact(%s) = %s: secret leaked", tt.body, got)
			}
			for _, want := range tt.keep {
				if !strings.Contains(got, want) {
					t.Fatalf("redact(%s) = %s, want it to contain %s", tt.body, got, want)
				}
			}
		})
	}
}

func TestRedactUnparseable(t *testing.T) {
	for _, body := range []string{
		`{"project-id":"p","user-data":"SECRET", oops`,
		`{"` + escaped("user-data") + `":"SECRET"`,
		`not json at all SECRET`,
		`["SECRET"]`,
		// duplicate members of different types cannot be merged
		`{"metadata":"SECRET","metadata":{"k":"SECRET2"}}`,
		`"SECRET"`,
		"",
	} {
		attrs := redact([]byte(body))
		sum := sha256.Sum256([]byte(body))
		want := []any{"payload_bytes", len(body), "payload_sha256", hex.EncodeToString(sum[:])}
		if len(attrs) != len(want) {
			t.Fatalf("redact(%q) = %v, want %v", body, attrs, want)
		}
		for i := range want {
			if attrs[i] != want[i] {
				t.Fatalf("redact(%q) = %v, want %v", body, attrs, want)
			}
		}
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
