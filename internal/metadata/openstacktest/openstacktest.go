// Package openstacktest provides a minimal fake OpenStack control plane for
// tests: a Keystone v3 endpoint that authenticates the service's own user
// (password or application credential), validates subject tokens issued by
// the test and serves project records, and a Nova compute endpoint, listed
// in the service catalog, that serves server records.
package openstacktest

import (
	"crypto/rand"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Region is the region of the endpoints in the service catalog.
const Region = "RegionOne"

// computePath is the path of the compute endpoint in the catalog.
const computePath = "/compute/v2.1"

// Instance is a Nova server record.
type Instance struct {
	ID               string
	ProjectID        string
	UserID           string
	Status           string
	AvailabilityZone string
	// FlavorName is the flavor's original_name, returned for compute
	// microversions 2.47 and later.
	FlavorName string
}

// Project is a Keystone project record.
type Project struct {
	ID       string
	Name     string
	DomainID string
}

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

// Server is a fake Keystone v3 and Nova control plane over TLS.
type Server struct {
	*httptest.Server

	mu               sync.Mutex
	serviceTokens    map[string]bool
	subjects         map[string]subject
	instances        map[string]Instance
	projects         map[string]Project
	lastMicroversion string

	// Authentications counts successful POST /v3/auth/tokens.
	Authentications atomic.Int32
	// Validations counts GET /v3/auth/tokens requests.
	Validations atomic.Int32
	// ServerLookups counts GET /servers/{id} requests.
	ServerLookups atomic.Int32
	// ProjectLookups counts GET /v3/projects/{id} requests.
	ProjectLookups atomic.Int32
	down           atomic.Bool
}

// New starts a fake OpenStack control plane, stopped when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		serviceTokens: map[string]bool{}, subjects: map[string]subject{},
		instances: map[string]Instance{}, projects: map[string]Project{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v3/auth/tokens", s.authenticate)
	mux.HandleFunc("GET /v3/auth/tokens", s.validate)
	mux.HandleFunc("GET /v3/projects/{id}", s.project)
	mux.HandleFunc("GET /v3/auth/catalog", s.catalog)
	mux.HandleFunc("GET "+computePath+"/{$}", s.computeVersion)
	mux.HandleFunc("GET "+computePath+"/servers/{id}", s.server)
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

// AddInstance adds a server record to the fake Nova.
func (s *Server) AddInstance(i Instance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.instances[i.ID] = i
}

// AddProject adds a project record to the fake Keystone.
func (s *Server) AddProject(p Project) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projects[p.ID] = p
}

// LastComputeMicroversion returns the compute API microversion requested by
// the latest server lookup.
func (s *Server) LastComputeMicroversion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastMicroversion
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
	s.writeToken(w, http.StatusCreated, Service, time.Now().Add(serviceTokenLifetime))
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
	s.writeToken(w, http.StatusOK, sub.user, sub.expires)
}

// authorized reports whether the request carries a valid service token,
// replying 401 if not.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	ok := s.serviceTokens[r.Header.Get("X-Auth-Token")]
	s.mu.Unlock()
	if !ok {
		keystoneError(w, http.StatusUnauthorized, "The request you have made requires authentication.")
	}
	return ok
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalog": s.catalogEntries()})
}

func (s *Server) computeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": map[string]any{
		"id": "v2.1", "status": "CURRENT", "min_version": "2.1", "version": "2.96",
	}})
}

func (s *Server) project(w http.ResponseWriter, r *http.Request) {
	s.ProjectLookups.Add(1)
	if !s.authorized(w, r) {
		return
	}
	s.mu.Lock()
	p, found := s.projects[r.PathValue("id")]
	s.mu.Unlock()
	if !found {
		keystoneError(w, http.StatusNotFound, "Could not find project.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": map[string]any{
		"id": p.ID, "name": p.Name, "domain_id": p.DomainID, "enabled": true, "is_domain": false,
	}})
}

func (s *Server) server(w http.ResponseWriter, r *http.Request) {
	s.ServerLookups.Add(1)
	if !s.authorized(w, r) {
		return
	}
	microversion := r.Header.Get("X-OpenStack-Nova-API-Version")
	s.mu.Lock()
	i, found := s.instances[r.PathValue("id")]
	s.lastMicroversion = microversion
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"itemNotFound": map[string]any{
			"code": http.StatusNotFound, "message": "Instance " + r.PathValue("id") + " could not be found.",
		}})
		return
	}
	flavor := map[string]any{"id": "flavor-" + i.FlavorName}
	if atLeast(microversion, 47) {
		flavor = map[string]any{"original_name": i.FlavorName, "vcpus": 1, "ram": 512, "disk": 1}
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": map[string]any{
		"id": i.ID, "tenant_id": i.ProjectID, "user_id": i.UserID, "status": i.Status,
		"OS-EXT-AZ:availability_zone": i.AvailabilityZone, "flavor": flavor, "name": "vm",
	}})
}

// atLeast reports whether a "2.N" microversion is at least 2.minor.
func atLeast(microversion string, minor int) bool {
	major, m, ok := strings.Cut(microversion, ".")
	n, err := strconv.Atoi(m)
	return ok && major == "2" && err == nil && n >= minor
}

func (s *Server) writeToken(w http.ResponseWriter, status int, u User, expires time.Time) {
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
		"catalog": s.catalogEntries(),
	}}
	writeJSON(w, status, body)
}

func (s *Server) catalogEntries() []any {
	return []any{map[string]any{
		"id": "compute-service", "type": "compute", "name": "nova",
		"endpoints": []any{map[string]any{
			"id": "compute-public", "interface": "public", "region": Region, "region_id": Region,
			"url": s.URL + computePath,
		}},
	}}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
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
