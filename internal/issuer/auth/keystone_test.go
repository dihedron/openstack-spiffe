package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/auth"
	"github.com/dihedron/openstack-spiffe/internal/issuer/openstacktest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/osclient"
)

var (
	novaUser = openstacktest.User{
		ID: "0123456789abcdef0123456789abcdef", Name: "nova", DomainID: "default", DomainName: "Default",
		Roles: []string{"service"},
	}
	aliceUser = openstacktest.User{
		ID: "fedcba9876543210fedcba9876543210", Name: "alice", DomainID: "default", DomainName: "Default",
		Roles: []string{"member"},
	}
)

func newKeystoneValidator(t *testing.T, ks *openstacktest.Server) *auth.KeystoneValidator {
	t.Helper()
	env := ks.Env()
	creds, err := osclient.CredentialsFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	client, err := osclient.New(context.Background(), creds, ks.CAFile(t))
	if err != nil {
		t.Fatalf("osclient.New: %v", err)
	}
	identity, err := client.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	v, err := auth.NewKeystoneValidator(identity)
	if err != nil {
		t.Fatalf("NewKeystoneValidator: %v", err)
	}
	return v
}

func TestKeystoneValidatorReportsIdentity(t *testing.T) {
	ks := openstacktest.New(t)
	v := newKeystoneValidator(t, ks)
	expires := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	token := ks.IssueToken(novaUser, expires)

	id, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.UserID != novaUser.ID || id.UserName != "nova" || id.DomainID != "default" || id.DomainName != "Default" ||
		len(id.Roles) != 1 || id.Roles[0] != "service" || !id.ExpiresAt.Equal(expires) {
		t.Fatalf("unexpected identity: %+v (expires %v)", id, expires)
	}
}

func TestKeystoneValidatorErrors(t *testing.T) {
	ks := openstacktest.New(t)
	v := newKeystoneValidator(t, ks)
	ctx := context.Background()

	if _, err := v.Validate(ctx, "gAAAAABunknown"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("unknown token: %v, want ErrInvalidToken", err)
	}
	expired := ks.IssueToken(novaUser, time.Now().Add(-time.Second))
	if _, err := v.Validate(ctx, expired); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired token: %v, want ErrInvalidToken", err)
	}

	token := ks.IssueToken(novaUser, time.Now().Add(time.Hour))
	ks.SetDown(true)
	_, err := v.Validate(ctx, token)
	if !errors.Is(err, auth.ErrUnavailable) || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("Keystone down: %v, want ErrUnavailable only", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaks the token: %v", err)
	}
	ks.SetDown(false)
	if _, err := v.Validate(ctx, token); err != nil {
		t.Fatalf("Keystone back: %v", err)
	}
}

func TestKeystoneValidatorReauthenticates(t *testing.T) {
	ks := openstacktest.New(t)
	v := newKeystoneValidator(t, ks)
	token := ks.IssueToken(novaUser, time.Now().Add(time.Hour))

	ks.RevokeServiceTokens() // the service's own token expired
	if _, err := v.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate after service token expiry: %v", err)
	}
	if n := ks.Authentications.Load(); n != 2 {
		t.Fatalf("%d authentications, want 2 (initial + re-authentication)", n)
	}
}

// TestMiddlewareAgainstKeystone checks the spec's integration criterion:
// the allowlisted service user carrying the required role is accepted, and
// arbitrary user tokens are rejected.
func TestMiddlewareAgainstKeystone(t *testing.T) {
	ks := openstacktest.New(t)
	a, err := auth.NewAuthenticator(newKeystoneValidator(t, ks), []string{"nova@Default"}, "service")
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	reached := 0
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))

	tests := []struct {
		name   string
		token  string
		status int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"unknown token", "gAAAAABforged", http.StatusUnauthorized},
		{"arbitrary user", ks.IssueToken(aliceUser, time.Now().Add(time.Hour)), http.StatusForbidden},
		{"nova service user", ks.IssueToken(novaUser, time.Now().Add(time.Hour)), http.StatusOK},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodPost, "/attest", strings.NewReader(`{}`))
		if tt.token != "" {
			r.Header.Set(auth.TokenHeader, tt.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s: status %d, want %d", tt.name, w.Code, tt.status)
		}
	}
	if reached != 1 {
		t.Fatalf("handler reached %d times, want 1", reached)
	}
}
