package novalookup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	projectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	instanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
)

var testNow = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeBackend struct {
	mu         sync.Mutex
	servers    map[string]Server
	projects   map[string]Project
	serverErr  error
	projectErr error

	serverCalls  atomic.Int32
	projectCalls atomic.Int32

	// serverHook and projectHook, if set, run at the start of each lookup
	// and may fail it.
	serverHook  func(ctx context.Context) error
	projectHook func(ctx context.Context) error
}

func newBackend() *fakeBackend {
	return &fakeBackend{
		servers: map[string]Server{instanceID: {
			ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: "m1.small",
		}},
		projects: map[string]Project{projectID: {Name: "web", DomainID: "default"}},
	}
}

func (f *fakeBackend) Server(ctx context.Context, id string) (Server, error) {
	f.serverCalls.Add(1)
	if f.serverHook != nil {
		if err := f.serverHook(ctx); err != nil {
			return Server{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.serverErr != nil {
		return Server{}, f.serverErr
	}
	s, ok := f.servers[id]
	if !ok {
		return Server{}, fmt.Errorf("server %s: %w", id, ErrNotFound)
	}
	return s, nil
}

func (f *fakeBackend) Project(ctx context.Context, id string) (Project, error) {
	f.projectCalls.Add(1)
	if f.projectHook != nil {
		if err := f.projectHook(ctx); err != nil {
			return Project{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.projectErr != nil {
		return Project{}, f.projectErr
	}
	p, ok := f.projects[id]
	if !ok {
		return Project{}, fmt.Errorf("project %s: %w", id, ErrNotFound)
	}
	return p, nil
}

func (f *fakeBackend) setServer(s Server) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers[instanceID] = s
}

func newVerifier(t *testing.T, b Backend, clock *testClock, options ...Option) *Verifier {
	t.Helper()
	v, err := NewVerifier(b, append([]Option{WithClock(clock.Now)}, options...)...)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerifiedInstanceWithoutEnrichment(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow})
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if e != (claims.Enrichment{}) {
		t.Fatalf("enrichment %+v without enrich configured", e)
	}
	if b.serverCalls.Load() != 1 || b.projectCalls.Load() != 0 {
		t.Fatalf("%d server and %d project lookups, want 1 and 0", b.serverCalls.Load(), b.projectCalls.Load())
	}
}

func TestMismatches(t *testing.T) {
	tests := []struct {
		name      string
		project   string
		instance  string
		setup     func(b *fakeBackend)
		reasonHas string
	}{
		{"unknown instance", projectID, "00000000-0000-4000-8000-000000000000", nil, "not found"},
		{"instance of another project", "0123456789abcdef0123456789abcdef", instanceID, nil, "project"},
		{"deleted instance", projectID, instanceID, func(b *fakeBackend) {
			b.setServer(Server{ProjectID: projectID, Status: "DELETED"})
		}, "status"},
		{"errored instance", projectID, instanceID, func(b *fakeBackend) {
			b.setServer(Server{ProjectID: projectID, Status: "ERROR"})
		}, "status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBackend()
			if tt.setup != nil {
				tt.setup(b)
			}
			v := newVerifier(t, b, &testClock{now: testNow})
			_, err := v.Verify(context.Background(), tt.project, tt.instance)
			if !errors.Is(err, ErrInstanceMismatch) || errors.Is(err, ErrLookupUnavailable) {
				t.Fatalf("Verify error %v, want ErrInstanceMismatch only", err)
			}
		})
	}
}

func TestAllowedStatusesOption(t *testing.T) {
	b := newBackend()
	b.setServer(Server{ProjectID: projectID, Status: "RESCUE"})
	v := newVerifier(t, b, &testClock{now: testNow})
	if _, err := v.Verify(context.Background(), projectID, instanceID); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("RESCUE allowed by default: %v", err)
	}
	v = newVerifier(t, b, &testClock{now: testNow}, WithAllowedStatuses([]string{"ACTIVE", "RESCUE"}))
	if _, err := v.Verify(context.Background(), projectID, instanceID); err != nil {
		t.Fatalf("RESCUE explicitly allowed: %v", err)
	}
}

func TestDefaultAllowedStatuses(t *testing.T) {
	want := []string{"ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "PASSWORD"}
	got := DefaultAllowedStatuses()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("DefaultAllowedStatuses() = %v, want %v", got, want)
	}
	got[0] = "tampered"
	if DefaultAllowedStatuses()[0] != "ACTIVE" {
		t.Fatal("DefaultAllowedStatuses exposes internal state")
	}
}

func TestBackendUnavailable(t *testing.T) {
	boom := errors.New("dial tcp: connection refused")
	for _, tt := range []struct {
		name   string
		setup  func(*fakeBackend)
		enrich []string
	}{
		{"nova down", func(b *fakeBackend) { b.serverErr = boom }, nil},
		{"keystone down", func(b *fakeBackend) { b.projectErr = boom }, []string{iid.ClaimProjectName}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newBackend()
			tt.setup(b)
			v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment(tt.enrich))
			_, err := v.Verify(context.Background(), projectID, instanceID)
			if !errors.Is(err, ErrLookupUnavailable) || errors.Is(err, ErrInstanceMismatch) {
				t.Fatalf("Verify error %v, want ErrLookupUnavailable only", err)
			}
		})
	}
}

func TestEnrichment(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment(iid.EnrichmentClaims()))
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := claims.Enrichment{AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default"}
	if e != want {
		t.Fatalf("enrichment %+v, want %+v", e, want)
	}
}

func TestOnlyEnabledAttributesAreEmitted(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment([]string{iid.ClaimAvailabilityZone, iid.ClaimDomainID}))
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if want := (claims.Enrichment{AvailabilityZone: "az-1", DomainID: "default"}); e != want {
		t.Fatalf("enrichment %+v, want %+v", e, want)
	}
}

func TestKeystoneOnlyEnrichmentWithoutVerification(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithInstanceVerification(false), WithEnrichment([]string{iid.ClaimProjectName}))
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if e != (claims.Enrichment{ProjectName: "web"}) {
		t.Fatalf("enrichment %+v", e)
	}
	if b.serverCalls.Load() != 0 {
		t.Fatal("Nova consulted with instance verification disabled")
	}
}

func TestNoLookupsWhenDisabled(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithInstanceVerification(false))
	if _, err := v.Verify(context.Background(), projectID, "anything"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if b.serverCalls.Load()+b.projectCalls.Load() != 0 {
		t.Fatal("lookups performed with verification and enrichment disabled")
	}
}

func TestUnknownProjectIsAMismatch(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow}, WithInstanceVerification(false), WithEnrichment([]string{iid.ClaimProjectName}))
	if _, err := v.Verify(context.Background(), "0123456789abcdef0123456789abcdef", instanceID); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("Verify error %v, want ErrInstanceMismatch", err)
	}
}

func TestMissingEnrichmentAttributeIsUnavailable(t *testing.T) {
	b := newBackend()
	b.setServer(Server{ProjectID: projectID, UserID: "u1", Status: "BUILD"}) // not scheduled yet: no zone
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment([]string{iid.ClaimAvailabilityZone}))
	_, err := v.Verify(context.Background(), projectID, instanceID)
	if !errors.Is(err, ErrLookupUnavailable) {
		t.Fatalf("Verify error %v, want ErrLookupUnavailable (never a token with a missing enrichment claim)", err)
	}
}

func TestInvalidEnrichmentValueIsUnavailable(t *testing.T) {
	for name, tc := range map[string]struct {
		server  Server
		project Project
	}{
		"format character in zone": {
			server:  Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az\u202e-1", Flavor: "m1.small"},
			project: Project{Name: "web", DomainID: "default"},
		},
		"oversized flavor": {
			server:  Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: strings.Repeat("f", 256)},
			project: Project{Name: "web", DomainID: "default"},
		},
		"control character in project name": {
			server:  Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: "m1.small"},
			project: Project{Name: "web\nlevel=ERROR", DomainID: "default"},
		},
		"invalid UTF-8 in domain ID": {
			server:  Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: "m1.small"},
			project: Project{Name: "web", DomainID: "def\xffault"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBackend()
			b.setServer(tc.server)
			b.projects[projectID] = tc.project
			v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment(iid.EnrichmentClaims()))
			e, err := v.Verify(context.Background(), projectID, instanceID)
			if !errors.Is(err, ErrLookupUnavailable) {
				t.Fatalf("Verify = %+v, %v, want ErrLookupUnavailable (never a token the SPIRE Server would reject)", e, err)
			}
		})
	}
}

func TestInvalidValueOfDisabledEnrichmentIsIgnored(t *testing.T) {
	b := newBackend()
	b.setServer(Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: "m1\u200bsmall"})
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment([]string{iid.ClaimAvailabilityZone}))
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if e != (claims.Enrichment{AvailabilityZone: "az-1"}) {
		t.Fatalf("enrichment %+v", e)
	}
}

func TestServerRecordsCached(t *testing.T) {
	b := newBackend()
	clock := &testClock{now: testNow}
	v := newVerifier(t, b, clock, WithServerCacheTTL(time.Minute))
	ctx := context.Background()
	for range 3 {
		if _, err := v.Verify(ctx, projectID, instanceID); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	if n := b.serverCalls.Load(); n != 1 {
		t.Fatalf("%d server lookups within the TTL, want 1", n)
	}
	// the cached record is still checked against each request
	if _, err := v.Verify(ctx, "0123456789abcdef0123456789abcdef", instanceID); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("cached record not checked against the request: %v", err)
	}
	clock.Advance(time.Minute)
	v.Verify(ctx, projectID, instanceID)
	if n := b.serverCalls.Load(); n != 2 {
		t.Fatalf("%d server lookups after the TTL, want 2", n)
	}
}

func TestProjectRecordsCached(t *testing.T) {
	b := newBackend()
	clock := &testClock{now: testNow}
	v := newVerifier(t, b, clock, WithEnrichment([]string{iid.ClaimProjectName}), WithProjectCacheTTL(10*time.Minute), WithServerCacheTTL(time.Minute))
	ctx := context.Background()
	v.Verify(ctx, projectID, instanceID)
	clock.Advance(2 * time.Minute)
	v.Verify(ctx, projectID, instanceID)
	if b.serverCalls.Load() != 2 || b.projectCalls.Load() != 1 {
		t.Fatalf("%d server and %d project lookups, want 2 and 1", b.serverCalls.Load(), b.projectCalls.Load())
	}
	clock.Advance(8 * time.Minute)
	v.Verify(ctx, projectID, instanceID)
	if b.projectCalls.Load() != 2 {
		t.Fatalf("%d project lookups after the TTL, want 2", b.projectCalls.Load())
	}
}

func TestFailuresAreNotCached(t *testing.T) {
	b := newBackend()
	v := newVerifier(t, b, &testClock{now: testNow})
	ctx := context.Background()
	if _, err := v.Verify(ctx, projectID, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("got %v", err)
	}
	b.mu.Lock()
	b.servers["00000000-0000-4000-8000-000000000000"] = Server{ProjectID: projectID, Status: "ACTIVE"}
	b.mu.Unlock()
	if _, err := v.Verify(ctx, projectID, "00000000-0000-4000-8000-000000000000"); err != nil {
		t.Fatalf("instance created after a failed lookup: %v", err)
	}
}

func TestNewVerifierValidation(t *testing.T) {
	b := newBackend()
	tests := []struct {
		name    string
		backend Backend
		options []Option
	}{
		{"nil backend", nil, nil},
		{"unknown enrichment", b, []Option{WithEnrichment([]string{"hypervisor_hostname"})}},
		{"server enrichment without verification", b, []Option{WithInstanceVerification(false), WithEnrichment([]string{iid.ClaimFlavor})}},
		{"no allowed statuses", b, []Option{WithAllowedStatuses(nil)}},
		{"zero server cache TTL", b, []Option{WithServerCacheTTL(0)}},
		{"server cache TTL above token TTL", b, []Option{WithServerCacheTTL(iid.TTL + time.Second)}},
		{"zero project cache TTL", b, []Option{WithProjectCacheTTL(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewVerifier(tt.backend, tt.options...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestLookupsRunInParallel makes each lookup wait until the other one has
// started: run one after the other, they would time out.
func TestLookupsRunInParallel(t *testing.T) {
	b := newBackend()
	serverStarted, projectStarted := make(chan struct{}), make(chan struct{})
	await := func(ctx context.Context, other <-chan struct{}) error {
		select {
		case <-other:
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("the other lookup never started: lookups are sequential")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.serverHook = func(ctx context.Context) error { close(serverStarted); return await(ctx, projectStarted) }
	b.projectHook = func(ctx context.Context) error { close(projectStarted); return await(ctx, serverStarted) }
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment(iid.EnrichmentClaims()))

	e, err := v.Verify(context.Background(), projectID, instanceID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := claims.Enrichment{AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default"}
	if e != want {
		t.Fatalf("enrichment %+v, want %+v", e, want)
	}
}

func TestServerFailureDoesNotWaitForTheProjectLookup(t *testing.T) {
	b := newBackend()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	b.projectHook = func(ctx context.Context) error { <-release; return nil } // Keystone hangs
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment([]string{iid.ClaimProjectName}))

	start := time.Now()
	_, err := v.Verify(context.Background(), projectID, "00000000-0000-4000-8000-000000000000")
	if !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("Verify error %v, want ErrInstanceMismatch", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Verify took %v: it waited for the hanging project lookup", elapsed)
	}
}

func TestProjectFailureAfterServerSuccess(t *testing.T) {
	b := newBackend()
	b.projectErr = errors.New("connection refused")
	v := newVerifier(t, b, &testClock{now: testNow}, WithEnrichment([]string{iid.ClaimAvailabilityZone, iid.ClaimDomainID}))
	e, err := v.Verify(context.Background(), projectID, instanceID)
	if !errors.Is(err, ErrLookupUnavailable) || e != (claims.Enrichment{}) {
		t.Fatalf("Verify = %+v, %v; want no enrichment and ErrLookupUnavailable", e, err)
	}
}
