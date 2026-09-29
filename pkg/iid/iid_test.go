package iid

import (
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if TargetName != "openstack_iid" {
		t.Errorf("TargetName = %q, want %q", TargetName, "openstack_iid")
	}
	if Issuer != "nova-spire-plugin" {
		t.Errorf("Issuer = %q, want %q", Issuer, "nova-spire-plugin")
	}
	if Audience != "spire-node-attestation" {
		t.Errorf("Audience = %q, want %q", Audience, "spire-node-attestation")
	}
	if TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m", TTL)
	}
	if MaxTagsBytes != 1024 {
		t.Errorf("MaxTagsBytes = %d, want 1024", MaxTagsBytes)
	}
	if Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", Algorithm, "RS256")
	}
}

func TestClaimsJSONFieldNames(t *testing.T) {
	claims := Claims{
		Issuer:     Issuer,
		Audience:   Audience,
		Subject:    "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a",
		IssuedAt:   1758000000,
		NotBefore:  1758000000,
		Expiry:     1758000300,
		ID:         "5b1f0f3e-2f7a-4c1e-8d0a-6c2f9b7e4a11",
		ProjectID:  "f3c9a1d2b4e5",
		InstanceID: "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a",
		Hostname:   "vm-01",
		Tags:       map[string]string{"role": "web"},
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"aud", "exp", "hostname", "iat", "instance_id", "iss", "jti", "nbf", "project_id", "sub", "tags"}
	got := slices.Sorted(maps.Keys(generic))
	if !slices.Equal(got, want) {
		t.Fatalf("claim names = %v, want %v", got, want)
	}

	var back Claims
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal into Claims: %v", err)
	}
	if back.Subject != claims.Subject || back.Expiry != claims.Expiry || back.Tags["role"] != "web" {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestClaimsEmptyTagsAlwaysPresent(t *testing.T) {
	data, err := json.Marshal(Claims{Tags: map[string]string{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := generic["tags"]; !ok {
		t.Fatalf("tags claim missing from %s", data)
	}
}

func TestHeaderJSON(t *testing.T) {
	data, err := json.Marshal(Header{Algorithm: Algorithm, KeyID: "2026-09-29-replica-a-key-1", Type: "JWT"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"alg":"RS256","kid":"2026-09-29-replica-a-key-1","typ":"JWT"}`
	if string(data) != want {
		t.Fatalf("header = %s, want %s", data, want)
	}
}

func TestVendorDataResponseShape(t *testing.T) {
	data, err := json.Marshal(NewVendorDataResponse("a.b.c"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"openstack_iid":{"jwt":"a.b.c"}}`
	if string(data) != want {
		t.Fatalf("response = %s, want %s", data, want)
	}

	var back VendorDataResponse
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Target.JWT != "a.b.c" {
		t.Fatalf("round trip jwt = %q", back.Target.JWT)
	}
}

func TestClaimsCustomClaimsAtTopLevel(t *testing.T) {
	data, err := json.Marshal(Claims{
		Subject: "i",
		Tags:    map[string]string{},
		Custom:  map[string]string{"country": "italy", "region": "eu-south-1"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if generic["country"] != "italy" || generic["region"] != "eu-south-1" {
		t.Fatalf("custom claims not at top level: %s", data)
	}

	var back Claims
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal into Claims: %v", err)
	}
	if len(back.Custom) != 2 || back.Custom["country"] != "italy" {
		t.Fatalf("custom claims round trip = %v", back.Custom)
	}
}

// Always-emitted claims are also protected by the encoder itself; optional
// (enrichment) claims rely on ValidateCustomClaims, which the minter re-runs
// right before signing.
func TestClaimsCustomClaimCannotShadowAlwaysEmittedClaim(t *testing.T) {
	for _, name := range ReservedClaims() {
		if slices.Contains(EnrichmentClaims(), name) {
			continue
		}
		_, err := json.Marshal(Claims{
			Tags:   map[string]string{},
			Custom: map[string]string{name: "evil"},
		})
		if err == nil {
			t.Errorf("marshaling custom claim %q succeeded, want duplicate name error", name)
		}
	}
}

func TestReservedClaims(t *testing.T) {
	want := []string{"aud", "availability_zone", "domain_id", "exp", "flavor", "hostname", "iat", "instance_id", "iss", "jti", "nbf", "project_id", "project_name", "sub", "tags", "user_id"}
	got := ReservedClaims()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("ReservedClaims() = %v, want %v", got, want)
	}
	for _, name := range want {
		if !IsReservedClaim(name) {
			t.Errorf("IsReservedClaim(%q) = false", name)
		}
	}
	if IsReservedClaim("country") {
		t.Errorf("IsReservedClaim(\"country\") = true")
	}
	// the returned slice must be a copy
	got[0] = "tampered"
	if IsReservedClaim("tampered") {
		t.Errorf("ReservedClaims() exposes internal state")
	}
}

func TestValidateCustomClaims(t *testing.T) {
	if err := ValidateCustomClaims(map[string]string{"country": "italy"}); err != nil {
		t.Fatalf("valid custom claims rejected: %v", err)
	}
	if err := ValidateCustomClaims(nil); err != nil {
		t.Fatalf("nil custom claims rejected: %v", err)
	}
	for _, bad := range []map[string]string{
		{"": "x"},
		{"project_id": "someone-else"},
		{"sub": "x"},
		{"tags": "x"},
	} {
		if err := ValidateCustomClaims(bad); !errors.Is(err, ErrInvalidCustomClaim) {
			t.Errorf("ValidateCustomClaims(%v) = %v, want ErrInvalidCustomClaim", bad, err)
		}
	}
}

func TestEnrichmentClaims(t *testing.T) {
	want := []string{"availability_zone", "flavor", "user_id", "project_name", "domain_id"}
	got := EnrichmentClaims()
	if !slices.Equal(got, want) {
		t.Fatalf("EnrichmentClaims() = %v, want %v", got, want)
	}
	got[0] = "tampered"
	if EnrichmentClaims()[0] != ClaimAvailabilityZone {
		t.Fatalf("EnrichmentClaims() exposes internal state")
	}
}
