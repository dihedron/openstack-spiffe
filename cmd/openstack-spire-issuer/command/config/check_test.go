package config

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const validSigner = `tls_cert_path: /tls.crt
tls_key_path: /tls.key
replica_id: signer-a
tags:
  allowlist: [role]
keystone:
  allowed_users: [3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60]
audit:
  syslog:
    enabled: true
attest:
  allowed_sources: [10.0.20.0/24]
`

const aggregator = `tls_cert_path: /tls.crt
tls_key_path: /tls.key
replicas: [https://signer-a/jwks]
poll_interval: 60s
fetch_timeout: 10s
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(t *testing.T, cmd *Check, color bool) (int, string, string) {
	t.Helper()
	if cmd.Format == "" {
		cmd.Format = "text"
	}
	cmd.SkipFiles = true
	var stdout, stderr bytes.Buffer
	code := cmd.run(&stdout, &stderr, color)
	return code, stdout.String(), stderr.String()
}

func TestCheckValid(t *testing.T) {
	code, out, _ := run(t, &Check{Signers: []string{writeFile(t, "signer.yaml", validSigner)}}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, output:\n%s", code, out)
	}
	if !strings.Contains(out, "configuration is valid") {
		t.Fatalf("output does not say valid:\n%s", out)
	}
}

func TestCheckErrors(t *testing.T) {
	path := writeFile(t, "signer.yaml", validSigner+"rate_limt_per_instance: \"1/5s\"\ntoken_ttl_seconds: 999\n")
	code, out, _ := run(t, &Check{Signers: []string{path}}, false)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; output:\n%s", code, out)
	}
	for _, want := range []string{
		path,
		"rate_limt_per_instance", `did you mean "rate_limit_per_instance"?`, "unknown-key",
		"token_ttl_seconds", "rule-violation",
		"2 errors",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	// findings are listed in line order
	if strings.Index(out, "rate_limt_per_instance") > strings.Index(out, "token_ttl_seconds") {
		t.Errorf("findings not in line order:\n%s", out)
	}
}

func TestCheckWarningsAndStrict(t *testing.T) {
	doc := strings.Replace(validSigner, "tags:\n  allowlist: [role]\n", "", 1)
	path := writeFile(t, "signer.yaml", doc)

	code, out, _ := run(t, &Check{Signers: []string{path}}, false)
	if code != 0 {
		t.Fatalf("exit code = %d with warnings only; output:\n%s", code, out)
	}
	if !strings.Contains(out, "tags.allowlist") || !strings.Contains(out, "1 warning") {
		t.Fatalf("warning not reported:\n%s", out)
	}

	code, out, _ = run(t, &Check{Signers: []string{path}, Strict: true}, false)
	if code != 1 {
		t.Fatalf("exit code = %d with --strict and warnings, want 1; output:\n%s", code, out)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	code, _, stderr := run(t, &Check{}, false)
	if code != 2 || !strings.Contains(stderr, "--signer") {
		t.Fatalf("no files: code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = run(t, &Check{Signers: []string{filepath.Join(t.TempDir(), "missing.yaml")}}, false)
	if code != 2 || !strings.Contains(stderr, "missing.yaml") {
		t.Fatalf("missing file: code = %d, stderr = %q", code, stderr)
	}
}

func TestCheckCrossFile(t *testing.T) {
	signer := writeFile(t, "signer.yaml", validSigner+"key_store:\n  publish_ahead: 60s\n")
	agg := writeFile(t, "aggregator.yaml", aggregator)
	code, out, _ := run(t, &Check{Signers: []string{signer}, Aggregator: &agg}, false)
	if code != 1 || !strings.Contains(out, "key_store.publish_ahead") || !strings.Contains(out, "inconsistency") {
		t.Fatalf("code = %d, output:\n%s", code, out)
	}
}

type jsonReport struct {
	Files []struct {
		File      string         `json:"file"`
		Type      string         `json:"type"`
		Valid     bool           `json:"valid"`
		Findings  []any          `json:"findings"`
		Effective map[string]any `json:"effective"`
	} `json:"files"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

func TestCheckJSONOutput(t *testing.T) {
	signer := writeFile(t, "signer.yaml", validSigner+"token_ttl_seconds: 999\n")
	agg := writeFile(t, "aggregator.yaml", aggregator)
	code, out, _ := run(t, &Check{Signers: []string{signer}, Aggregator: &agg, Format: "json", PrintEffective: true}, false)
	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	var report jsonReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if report.Errors != 1 || len(report.Files) != 2 {
		t.Fatalf("report = %+v", report)
	}
	if report.Files[0].Type != "signer" || report.Files[0].Valid || len(report.Files[0].Findings) != 1 {
		t.Fatalf("signer entry = %+v", report.Files[0])
	}
	if report.Files[1].Type != "aggregator" || !report.Files[1].Valid {
		t.Fatalf("aggregator entry = %+v", report.Files[1])
	}
	keyStore, _ := report.Files[0].Effective["key_store"].(map[string]any)
	if keyStore["rotation_interval"] != "24h0m0s" {
		t.Fatalf("effective configuration lacks defaults: %v", report.Files[0].Effective)
	}
}

func TestCheckYAMLOutput(t *testing.T) {
	signer := writeFile(t, "signer.yaml", validSigner)
	code, out, _ := run(t, &Check{Signers: []string{signer}, Format: "yaml"}, false)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var report map[string]any
	if err := yaml.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, out)
	}
	if report["errors"] != 0 || report["warnings"] != 0 {
		t.Fatalf("report = %v", report)
	}
}

func TestCheckPrintEffectiveText(t *testing.T) {
	signer := writeFile(t, "signer.yaml", validSigner)
	_, out, _ := run(t, &Check{Signers: []string{signer}, PrintEffective: true}, false)
	for _, want := range []string{"rotation_interval: 24h0m0s", "rate_limit_per_instance: 1/5s", "replica_id: signer-a"} {
		if !strings.Contains(out, want) {
			t.Errorf("effective configuration lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckColor(t *testing.T) {
	path := writeFile(t, "signer.yaml", validSigner+"token_ttl_seconds: 999\n")
	_, colored, _ := run(t, &Check{Signers: []string{path}}, true)
	if !strings.Contains(colored, "\x1b[") {
		t.Errorf("no ANSI colors with color enabled:\n%q", colored)
	}
	_, plain, _ := run(t, &Check{Signers: []string{path}}, false)
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("ANSI colors with color disabled:\n%q", plain)
	}
}

func TestExitError(t *testing.T) {
	var err error = &ExitError{Code: 2, Err: errors.New("boom")}
	var coder interface{ ExitCode() int }
	if !errors.As(err, &coder) || coder.ExitCode() != 2 || err.Error() != "boom" {
		t.Fatalf("ExitError = %v", err)
	}
}

func TestExitErrorAlreadyReported(t *testing.T) {
	err := &ExitError{Code: 1}
	if err.Error() != "" || err.Unwrap() != nil || err.ExitCode() != 1 {
		t.Fatalf("ExitError without cause = %q / %v / %d", err.Error(), err.Unwrap(), err.ExitCode())
	}
}

// failingWriter fails the one write that reaches its limit, and accepts
// every other: an error must not be lost even when later writes succeed.
type failingWriter struct {
	left   int
	failed bool
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if !f.failed && len(p) > f.left {
		f.failed = true
		return f.left, errors.New("disk full")
	}
	f.left -= len(p)
	return len(p), nil
}

func TestCheckReportWriteError(t *testing.T) {
	signer := writeFile(t, "signer.yaml", validSigner)
	for _, format := range []string{"text", "json", "yaml"} {
		for _, left := range []int{0, 10, 100} {
			cmd := &Check{Signers: []string{signer}, Format: format, SkipFiles: true}
			var stderr bytes.Buffer
			if code := cmd.run(&failingWriter{left: left}, &stderr, false); code != exitUsage || !strings.Contains(stderr.String(), "disk full") {
				t.Errorf("%s report failing after %d bytes: exit code %d, stderr %q; want %d and the error", format, left, code, stderr.String(), exitUsage)
			}
		}
	}
}
