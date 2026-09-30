// Package keystonetest provides a minimal fake Keystone v3 server for tests:
// it authenticates the service's own user (password or application
// credential) and validates subject tokens issued by the test.
package keystonetest

import (
	"crypto/rand"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// keystoneTime is the timestamp format Keystone uses.
const keystoneTime = "2006-01-02T15:04:05.000000Z"

// User is a Keystone user and the roles its tokens carry.
type User struct {
	ID         string
	Name       string
	DomainID   string
	DomainName string
	Roles      []string
}

// Service is the service's own user, as authenticated through the OS_*
// variables returned by Env.
var Service = User{
	ID: "5e7a0c1d2b3f4a5e6d7c8b9a0f1e2d3c", Name: "spire-metadata",
	DomainID: "default", DomainName: "Default", Roles: []string{"service"},
}

const (
	servicePassword      = "service-secret"
	serviceProjectID     = "9a8b7c6d5e4f30211203f4e5d6c7b8a9"
	serviceProjectName   = "service"
	appCredentialID      = "ac0123456789abcdef0123456789abcd"
	appCredentialSecret  = "app-credential-secret"
	serviceTokenLifetime = time.Hour
)

type subject struct {
	user    User
	expires time.Time
}

// Server is a fake Keystone v3 identity endpoint over TLS.
type Server struct {
	*httptest.Server

	mu            sync.Mutex
	serviceTokens map[string]bool
	subjects      map[string]subject

	// Authentications counts successful POST /v3/auth/tokens.
	Authentications atomic.Int32
	// Validations counts GET /v3/auth/tokens requests.
	Validations atomic.Int32
	down        atomic.Bool
}

// New starts a fake Keystone, stopped when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{serviceTokens: map[string]bool{}, subjects: map[string]subject{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v3/auth/tokens", s.authenticate)
	mux.HandleFunc("GET /v3/auth/tokens", s.validate)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.down.Load() {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// Env returns the OS_* variables of a typical openrc file for the service
// user, authenticating with a password and scoped to the service project.
func (s *Server) Env() map[string]string {
	return map[string]string{
		"OS_AUTH_URL":            s.URL + "/v3",
		"OS_USERNAME":            Service.Name,
		"OS_PASSWORD":            servicePassword,
		"OS_USER_DOMAIN_NAME":    Service.DomainName,
		"OS_PROJECT_NAME":        serviceProjectName,
		"OS_PROJECT_DOMAIN_NAME": Service.DomainName,
	}
}

// AppCredentialEnv returns the OS_* variables for authenticating with an
// application credential.
func (s *Server) AppCredentialEnv() map[string]string {
	return map[string]string{
		"OS_AUTH_URL":                      s.URL + "/v3",
		"OS_AUTH_TYPE":                     "v3applicationcredential",
		"OS_APPLICATION_CREDENTIAL_ID":     appCredentialID,
		"OS_APPLICATION_CREDENTIAL_SECRET": appCredentialSecret,
	}
}

// CAFile writes the server's certificate to a PEM file and returns its path.
func (s *Server) CAFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keystone-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("writing CA file: %v", err)
	}
	return path
}

// IssueToken returns a new subject token for the user, valid until expires.
func (s *Server) IssueToken(u User, expires time.Time) string {
	token := "gAAAAAB" + rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subjects[token] = subject{user: u, expires: expires}
	return token
}

// RevokeServiceTokens invalidates every token issued to the service user, so
// that its next request must re-authenticate.
func (s *Server) RevokeServiceTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.serviceTokens)
}

// SetDown makes every request fail with 503 until called with false.
func (s *Server) SetDown(down bool) { s.down.Store(down) }

type authRequest struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password struct {
				User struct {
					ID       string `json:"id"`
					Name     string `json:"name"`
					Password string `json:"password"`
					Domain   struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"domain"`
				} `json:"user"`
			} `json:"password"`
			ApplicationCredential struct {
				ID     string `json:"id"`
				Secret string `json:"secret"`
			} `json:"application_credential"`
		} `json:"identity"`
		Scope struct {
			Project struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Domain struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"domain"`
			} `json:"project"`
		} `json:"scope"`
	} `json:"auth"`
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		keystoneError(w, http.StatusBadRequest, "malformed request")
		return
	}
	id := req.Auth.Identity
	ok := false
	switch {
	case len(id.Methods) == 1 && id.Methods[0] == "password":
		u := id.Password.User
		userOK := u.ID == Service.ID || (u.Name == Service.Name && (u.Domain.Name == Service.DomainName || u.Domain.ID == Service.DomainID))
		p := req.Auth.Scope.Project
		scopeOK := p.ID == serviceProjectID || (p.Name == serviceProjectName && (p.Domain.Name == Service.DomainName || p.Domain.ID == Service.DomainID))
		ok = userOK && scopeOK && u.Password == servicePassword
	case len(id.Methods) == 1 && id.Methods[0] == "application_credential":
		ok = id.ApplicationCredential.ID == appCredentialID && id.ApplicationCredential.Secret == appCredentialSecret
	}
	if !ok {
		keystoneError(w, http.StatusUnauthorized, "The request you have made requires authentication.")
		return
	}

	token := "svc-" + rand.Text()
	s.mu.Lock()
	s.serviceTokens[token] = true
	s.mu.Unlock()
	s.Authentications.Add(1)
	w.Header().Set("X-Subject-Token", token)
	writeToken(w, http.StatusCreated, Service, time.Now().Add(serviceTokenLifetime))
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	s.Validations.Add(1)
	s.mu.Lock()
	authorized := s.serviceTokens[r.Header.Get("X-Auth-Token")]
	sub, found := s.subjects[r.Header.Get("X-Subject-Token")]
	s.mu.Unlock()
	if !authorized {
		keystoneError(w, http.StatusUnauthorized, "The request you have made requires authentication.")
		return
	}
	if !found || !time.Now().Before(sub.expires) {
		keystoneError(w, http.StatusNotFound, "Could not find token.")
		return
	}
	writeToken(w, http.StatusOK, sub.user, sub.expires)
}

func writeToken(w http.ResponseWriter, status int, u User, expires time.Time) {
	roles := make([]map[string]string, 0, len(u.Roles))
	for _, role := range u.Roles {
		roles = append(roles, map[string]string{"id": "role-" + role, "name": role})
	}
	body := map[string]any{"token": map[string]any{
		"methods":    []string{"password"},
		"issued_at":  time.Now().UTC().Format(keystoneTime),
		"expires_at": expires.UTC().Format(keystoneTime),
		"user": map[string]any{
			"id": u.ID, "name": u.Name,
			"domain": map[string]string{"id": u.DomainID, "name": u.DomainName},
		},
		"roles": roles,
		"project": map[string]any{
			"id": serviceProjectID, "name": serviceProjectName,
			"domain": map[string]string{"id": Service.DomainID, "name": Service.DomainName},
		},
		"catalog": []any{},
	}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, body)
}

func keystoneError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, map[string]any{"error": map[string]any{
		"code": status, "message": message, "title": http.StatusText(status),
	}})
}
