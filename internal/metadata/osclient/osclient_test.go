package osclient

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/metadata/openstacktest"
)

func getenv(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

func TestCredentialsFromOpenrc(t *testing.T) {
	env := map[string]string{
		"OS_AUTH_URL":            "https://keystone.example:5000/v3",
		"OS_USERNAME":            "spire-metadata",
		"OS_PASSWORD":            "secret",
		"OS_USER_DOMAIN_NAME":    "Default",
		"OS_PROJECT_NAME":        "service",
		"OS_PROJECT_DOMAIN_NAME": "Default",
		"OS_REGION_NAME":         "RegionOne",
		"OS_INTERFACE":           "internalURL",
	}
	c, err := CredentialsFromEnv(getenv(env))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	if c.Interface != "internal" || c.Region != "RegionOne" {
		t.Fatalf("endpoint preferences %q/%q, want internal/RegionOne", c.Interface, c.Region)
	}
	opts := c.authOptions()
	if opts.Username != "spire-metadata" || opts.DomainName != "Default" || !opts.AllowReauth {
		t.Fatalf("unexpected auth options: %+v", opts)
	}
	if opts.Scope == nil || opts.Scope.ProjectName != "service" || opts.Scope.DomainName != "Default" {
		t.Fatalf("unexpected scope: %+v", opts.Scope)
	}
}

func TestCredentialsDefaults(t *testing.T) {
	c, err := CredentialsFromEnv(getenv(map[string]string{
		"OS_AUTH_URL": "https://keystone.example/v3", "OS_USER_ID": "u", "OS_PASSWORD": "p", "OS_PROJECT_ID": "p1",
	}))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	if c.Interface != "public" {
		t.Fatalf("default interface %q, want public", c.Interface)
	}
	if opts := c.authOptions(); opts.Scope == nil || opts.Scope.ProjectID != "p1" {
		t.Fatalf("unexpected scope: %+v", opts.Scope)
	}
}

func TestCredentialsFromEnvRejects(t *testing.T) {
	valid := map[string]string{
		"OS_AUTH_URL": "https://keystone.example/v3", "OS_USERNAME": "u", "OS_PASSWORD": "secret-value",
		"OS_USER_DOMAIN_NAME": "Default", "OS_PROJECT_NAME": "service", "OS_PROJECT_DOMAIN_NAME": "Default",
	}
	tests := []struct {
		name   string
		change map[string]string
	}{
		{"no auth URL", map[string]string{"OS_AUTH_URL": ""}},
		{"plain http", map[string]string{"OS_AUTH_URL": "http://keystone.example/v3"}},
		{"not a URL", map[string]string{"OS_AUTH_URL": "keystone"}},
		{"no user", map[string]string{"OS_USERNAME": ""}},
		{"no user domain", map[string]string{"OS_USER_DOMAIN_NAME": ""}},
		{"no password", map[string]string{"OS_PASSWORD": ""}},
		{"no project", map[string]string{"OS_PROJECT_NAME": ""}},
		{"no project domain", map[string]string{"OS_PROJECT_DOMAIN_NAME": ""}},
		{"bad interface", map[string]string{"OS_INTERFACE": "private"}},
		{"app credential without secret", map[string]string{"OS_APPLICATION_CREDENTIAL_ID": "ac"}},
		{"app credential by name without user", map[string]string{"OS_APPLICATION_CREDENTIAL_NAME": "ac", "OS_APPLICATION_CREDENTIAL_SECRET": "s", "OS_USERNAME": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := maps.Clone(valid)
			maps.Copy(env, tt.change)
			_, err := CredentialsFromEnv(getenv(env))
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatalf("error leaks the password: %v", err)
			}
		})
	}
}

func TestNewAuthenticatesWithPassword(t *testing.T) {
	ks := openstacktest.New(t)
	creds, err := CredentialsFromEnv(getenv(ks.Env()))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	c, err := New(context.Background(), creds, ks.CAFile(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if ks.Authentications.Load() != 1 {
		t.Fatalf("%d authentications, want 1", ks.Authentications.Load())
	}
	identity, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if want := ks.URL + "/v3/"; identity.Endpoint != want {
		t.Fatalf("identity endpoint %q, want %q", identity.Endpoint, want)
	}
}

func TestComputeFromCatalog(t *testing.T) {
	ks := openstacktest.New(t)
	env := ks.Env()
	env["OS_REGION_NAME"] = openstacktest.Region
	creds, err := CredentialsFromEnv(getenv(env))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	c, err := New(context.Background(), creds, ks.CAFile(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	compute, err := c.Compute()
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if want := ks.URL + "/compute/v2.1/"; compute.Endpoint != want {
		t.Fatalf("compute endpoint %q, want %q", compute.Endpoint, want)
	}
	if compute.Microversion != "2.47" {
		t.Fatalf("microversion %q, want 2.47", compute.Microversion)
	}

	env["OS_REGION_NAME"] = "RegionTwo"
	creds, _ = CredentialsFromEnv(getenv(env))
	c, err = New(context.Background(), creds, ks.CAFile(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Compute(); err == nil {
		t.Fatal("found a compute endpoint in a region without one")
	}
}

func TestNewAuthenticatesWithApplicationCredential(t *testing.T) {
	ks := openstacktest.New(t)
	creds, err := CredentialsFromEnv(getenv(ks.AppCredentialEnv()))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	if _, err := New(context.Background(), creds, ks.CAFile(t)); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewFailures(t *testing.T) {
	ks := openstacktest.New(t)
	creds, err := CredentialsFromEnv(getenv(ks.Env()))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	ctx := context.Background()

	// the fake's self-signed certificate is not in the system roots
	if _, err := New(ctx, creds, ""); err == nil {
		t.Fatal("trusted an unknown certificate authority")
	}
	if _, err := New(ctx, creds, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("accepted a missing CA bundle")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("not a certificate"), 0o600)
	if _, err := New(ctx, creds, empty); err == nil {
		t.Fatal("accepted a CA bundle without certificates")
	}

	wrong := creds
	wrong.Password = "wrong-password"
	_, err = New(ctx, wrong, ks.CAFile(t))
	if err == nil {
		t.Fatal("authenticated with a wrong password")
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("error leaks the password: %v", err)
	}
}

func TestDependencyChecks(t *testing.T) {
	ks := openstacktest.New(t)
	creds, err := CredentialsFromEnv(getenv(ks.Env()))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	c, err := New(context.Background(), creds, ks.CAFile(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := c.CheckIdentity(ctx); err != nil {
		t.Fatalf("CheckIdentity: %v", err)
	}
	if err := c.CheckCompute(ctx); err != nil {
		t.Fatalf("CheckCompute: %v", err)
	}

	// an expired service token is renewed, not reported
	ks.RevokeServiceTokens()
	if err := c.CheckIdentity(ctx); err != nil {
		t.Fatalf("CheckIdentity after service token expiry: %v", err)
	}
	if n := ks.Authentications.Load(); n != 2 {
		t.Fatalf("%d authentications, want 2", n)
	}

	ks.SetDown(true)
	if err := c.CheckIdentity(ctx); err == nil {
		t.Fatal("CheckIdentity passed with Keystone down")
	}
	if err := c.CheckCompute(ctx); err == nil {
		t.Fatal("CheckCompute passed with Nova down")
	}
}

// TestNewFailsWhenKeystoneIsDown: authenticating is part of the service's
// pre-flight checks, so a Keystone outage at startup prevents it.
func TestNewFailsWhenKeystoneIsDown(t *testing.T) {
	ks := openstacktest.New(t)
	creds, err := CredentialsFromEnv(getenv(ks.Env()))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	ks.SetDown(true)
	if _, err := New(context.Background(), creds, ks.CAFile(t)); err == nil || !strings.Contains(err.Error(), "authenticating with Keystone") {
		t.Fatalf("New with Keystone down: %v, want an authentication error", err)
	}

	unreachable := creds
	unreachable.AuthURL = "https://127.0.0.1:1/v3"
	if _, err := New(context.Background(), unreachable, ks.CAFile(t)); err == nil {
		t.Fatal("New succeeded with Keystone unreachable")
	}
}

// TestRefusesTLS12Endpoints: by default, the service connects to OpenStack
// with TLS 1.3 or later only; WithMinTLSVersion lowers the bar to TLS 1.2.
func TestRefusesTLS12Endpoints(t *testing.T) {
	legacy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	legacy.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	legacy.StartTLS()
	t.Cleanup(legacy.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacy.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := CredentialsFromEnv(getenv(map[string]string{
		"OS_AUTH_URL": legacy.URL + "/v3", "OS_USER_ID": "u", "OS_PASSWORD": "p", "OS_PROJECT_ID": "p1",
	}))
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	_, err = New(context.Background(), creds, ca)
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("New against a TLS 1.2-only Keystone: %v, want a protocol version error", err)
	}

	// with TLS 1.2 allowed, the handshake succeeds (authentication then
	// fails, since the legacy server is no Keystone)
	_, err = New(context.Background(), creds, ca, WithMinTLSVersion(tls.VersionTLS12))
	if err == nil || strings.Contains(err.Error(), "protocol version") || strings.Contains(err.Error(), "tls:") {
		t.Fatalf("New with TLS 1.2 allowed: %v, want a non-TLS failure", err)
	}
	if _, err := New(context.Background(), creds, ca, WithMinTLSVersion(tls.VersionTLS11)); err == nil || !strings.Contains(err.Error(), "unsupported minimum TLS version") {
		t.Fatalf("TLS 1.1 minimum: %v, want an unsupported version error", err)
	}
}
