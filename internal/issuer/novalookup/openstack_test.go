package novalookup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/issuer/openstacktest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/osclient"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	projectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	instanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
)

func newBackend(t *testing.T, os *openstacktest.Server) *novalookup.OpenStack {
	t.Helper()
	env := os.Env()
	creds, err := osclient.CredentialsFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	client, err := osclient.New(context.Background(), creds, os.CAFile(t))
	if err != nil {
		t.Fatalf("osclient.New: %v", err)
	}
	compute, err := client.Compute()
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	identity, err := client.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	b, err := novalookup.NewOpenStack(compute, identity)
	if err != nil {
		t.Fatalf("NewOpenStack: %v", err)
	}
	return b
}

func fakeCloud(t *testing.T) *openstacktest.Server {
	t.Helper()
	os := openstacktest.New(t)
	os.AddInstance(openstacktest.Instance{
		ID: instanceID, ProjectID: projectID, UserID: "u1", Status: "ACTIVE",
		AvailabilityZone: "az-1", FlavorName: "m1.small",
	})
	os.AddProject(openstacktest.Project{ID: projectID, Name: "web", DomainID: "default"})
	return os
}

func TestOpenStackBackendRecords(t *testing.T) {
	os := fakeCloud(t)
	b := newBackend(t, os)
	ctx := context.Background()

	s, err := b.Server(ctx, instanceID)
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	want := novalookup.Server{ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", Flavor: "m1.small"}
	if s != want {
		t.Fatalf("server %+v, want %+v", s, want)
	}
	if mv := os.LastComputeMicroversion(); mv != "2.47" {
		t.Fatalf("requested microversion %q, want 2.47", mv)
	}

	p, err := b.Project(ctx, projectID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if p != (novalookup.Project{Name: "web", DomainID: "default"}) {
		t.Fatalf("project %+v", p)
	}
}

func TestOpenStackBackendErrors(t *testing.T) {
	os := fakeCloud(t)
	b := newBackend(t, os)
	ctx := context.Background()

	if _, err := b.Server(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, novalookup.ErrNotFound) {
		t.Fatalf("unknown server: %v, want ErrNotFound", err)
	}
	if _, err := b.Project(ctx, "0123456789abcdef0123456789abcdef"); !errors.Is(err, novalookup.ErrNotFound) {
		t.Fatalf("unknown project: %v, want ErrNotFound", err)
	}
	os.SetDown(true)
	if _, err := b.Server(ctx, instanceID); err == nil || errors.Is(err, novalookup.ErrNotFound) {
		t.Fatalf("Nova down: %v, want a non-ErrNotFound error", err)
	}
	if _, err := b.Project(ctx, projectID); err == nil || errors.Is(err, novalookup.ErrNotFound) {
		t.Fatalf("Keystone down: %v, want a non-ErrNotFound error", err)
	}
}

// TestVerifierAgainstFakeCloud runs the verifier end to end through
// gophercloud: verification, enrichment and caching.
func TestVerifierAgainstFakeCloud(t *testing.T) {
	os := fakeCloud(t)
	v, err := novalookup.NewVerifier(newBackend(t, os), novalookup.WithEnrichment(iid.EnrichmentClaims()))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()

	for range 3 {
		e, err := v.Verify(ctx, projectID, instanceID)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		want := claims.Enrichment{AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default"}
		if e != want {
			t.Fatalf("enrichment %+v, want %+v", e, want)
		}
	}
	if os.ServerLookups.Load() != 1 || os.ProjectLookups.Load() != 1 {
		t.Fatalf("%d server and %d project lookups, want 1 each (cached)", os.ServerLookups.Load(), os.ProjectLookups.Load())
	}

	if _, err := v.Verify(ctx, "0123456789abcdef0123456789abcdef", instanceID); !errors.Is(err, novalookup.ErrInstanceMismatch) {
		t.Fatalf("project mismatch: %v, want ErrInstanceMismatch", err)
	}
	if _, err := v.Verify(ctx, projectID, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, novalookup.ErrInstanceMismatch) {
		t.Fatalf("unknown instance: %v, want ErrInstanceMismatch", err)
	}
	os.SetDown(true)
	if _, err := v.Verify(ctx, projectID, "11111111-1111-4111-8111-111111111111"); !errors.Is(err, novalookup.ErrLookupUnavailable) {
		t.Fatalf("Nova down: %v, want ErrLookupUnavailable", err)
	}
}
