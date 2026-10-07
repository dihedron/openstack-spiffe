package iid

import (
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
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
	if MaxTokenBytes != 16*1024 {
		t.Errorf("MaxTokenBytes = %d, want 16384", MaxTokenBytes)
	}
	if MaxJWKSKeys != 100 {
		t.Errorf("MaxJWKSKeys = %d, want 100", MaxJWKSKeys)
	}
	if MaxCustomClaimsBytes != 2048 {
		t.Errorf("MaxCustomClaimsBytes = %d, want 2048", MaxCustomClaimsBytes)
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

func TestValidateCustomClaimsSize(t *testing.T) {
	// {"c":"<value>"} serializes to len(value) + 8 bytes
	fits := map[string]string{"c": strings.Repeat("x", MaxCustomClaimsBytes-8)}
	if err := ValidateCustomClaims(fits); err != nil {
		t.Fatalf("custom claims of exactly %d bytes rejected: %v", MaxCustomClaimsBytes, err)
	}
	tooLarge := map[string]string{"c": strings.Repeat("x", MaxCustomClaimsBytes-7)}
	if err := ValidateCustomClaims(tooLarge); !errors.Is(err, ErrInvalidCustomClaim) {
		t.Fatalf("custom claims over %d bytes: error = %v, want ErrInvalidCustomClaim", MaxCustomClaimsBytes, err)
	}
	// escaping counts: each '"' takes two bytes once serialized
	escaped := map[string]string{"c": strings.Repeat(`"`, (MaxCustomClaimsBytes-8)/2+1)}
	if err := ValidateCustomClaims(escaped); !errors.Is(err, ErrInvalidCustomClaim) {
		t.Fatalf("escaped custom claims over %d bytes: error = %v, want ErrInvalidCustomClaim", MaxCustomClaimsBytes, err)
	}
}

const testInstanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"

func TestValidateProjectID(t *testing.T) {
	for _, valid := range []string{"f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d", "a", "my_project-01", strings.Repeat("a", 64)} {
		if err := ValidateProjectID(valid); err != nil {
			t.Errorf("ValidateProjectID(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", "abc/def", "a b", "ü", strings.Repeat("a", 65)} {
		if err := ValidateProjectID(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateProjectID(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateInstanceID(t *testing.T) {
	if err := ValidateInstanceID(testInstanceID); err != nil {
		t.Errorf("ValidateInstanceID(%q) = %v, want nil", testInstanceID, err)
	}
	for _, invalid := range []string{
		"",
		"not-a-uuid",
		strings.ToUpper(testInstanceID),
		"{" + testInstanceID + "}",
		"urn:uuid:" + testInstanceID,
		strings.ReplaceAll(testInstanceID, "-", ""),
	} {
		if err := ValidateInstanceID(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateInstanceID(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	for _, valid := range []string{"vm-01", "web.example.org", strings.Repeat("h", 255)} {
		if err := ValidateHostname(valid); err != nil {
			t.Errorf("ValidateHostname(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", strings.Repeat("h", 256), "vm\n01", "vm\x0001", "vm\u008501"} {
		if err := ValidateHostname(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateHostname(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateTagKey(t *testing.T) {
	for _, valid := range []string{"role", "env", "a.b", "a/b", "a=b"} {
		if err := ValidateTagKey(valid); err != nil {
			t.Errorf("ValidateTagKey(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", ":", "a:b", "role:", "ro\u202ele", "ro\u200ble", "ro\x00le", "ro\nle", "ro\u0085le", "ro\xffle"} {
		if err := ValidateTagKey(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateTagKey(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateTagValue(t *testing.T) {
	for _, valid := range []string{"", "web", "a:b:c", "ünïcødé", "with space", strings.Repeat("v", 2048)} {
		if err := ValidateTagValue(valid); err != nil {
			t.Errorf("ValidateTagValue(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"we\u202eb", "we\u200bb", "\ufeffweb", "we\x00b", "we\tb", "we\u0085b", "we\xffb"} {
		if err := ValidateTagValue(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateTagValue(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateEnrichmentValue(t *testing.T) {
	for _, valid := range []string{"nova", "m1.small", "zone a", "ünïcødé", strings.Repeat("e", 255)} {
		if err := ValidateEnrichmentValue(valid); err != nil {
			t.Errorf("ValidateEnrichmentValue(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", strings.Repeat("e", 256), strings.Repeat("é", 128), "no\u202eva", "no\u200bva", "no\nva", "no\xffva"} {
		if err := ValidateEnrichmentValue(invalid); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("ValidateEnrichmentValue(%q) = %v, want ErrInvalidClaim", invalid, err)
		}
	}
}

func TestValidateReplicaID(t *testing.T) {
	for _, valid := range []string{"a", "signer-a", "s1", "0", strings.Repeat("r", 63)} {
		if err := ValidateReplicaID(valid); err != nil {
			t.Errorf("ValidateReplicaID(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", "Signer", "-a", "a-", "a.b", "a_b", strings.Repeat("r", 64)} {
		if err := ValidateReplicaID(invalid); err == nil {
			t.Errorf("ValidateReplicaID(%q) = nil, want an error", invalid)
		}
	}
}

func TestValidateKeyID(t *testing.T) {
	longest := "2026-10-04-" + strings.Repeat("r", 63) + "-key-" + strings.Repeat("9", 128-len("2026-10-04-")-63-len("-key-"))
	for _, valid := range []string{
		"2026-10-04-signer-a-key-0",     //gitleaks:allow
		"2026-10-04-signer-a-key-86399", //gitleaks:allow
		"2026-10-04-key-key-12",         // a replica ID may itself be "key"
		"2026-10-04-a-key-b-key-7",
		longest,
	} {
		if err := ValidateKeyID(valid); err != nil {
			t.Errorf("ValidateKeyID(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{
		"",
		"key-1",
		"2026-10-4-signer-a-key-1",
		"20261004-signer-a-key-1",
		"2026-10-04-signer-a-key-",
		"2026-10-04-signer-a-key-x",
		"2026-10-04--key-1",
		"2026-10-04-Signer-key-1",
		"2026-10-04-signer_a-key-1",
		"2026-10-04-signer-a-key-1\n",
		"2026-10-04-signer\u202e-key-1",
		"2026-10-04-signer-a-key-1/../../x",
		longest + "9",
	} {
		if err := ValidateKeyID(invalid); !errors.Is(err, ErrInvalidKeyID) {
			t.Errorf("ValidateKeyID(%q) = %v, want ErrInvalidKeyID", invalid, err)
		}
	}
}

func TestValidateKeyIDErrorOmitsKeyID(t *testing.T) {
	const kid = "attacker-controlled\x1b[31m"
	err := ValidateKeyID(kid)
	if err == nil {
		t.Fatal("ValidateKeyID accepted a malformed kid")
	}
	if strings.Contains(err.Error(), "attacker") {
		t.Errorf("error %q contains the kid", err)
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

func TestEnrichmentClaimsJSON(t *testing.T) {
	claims := Claims{
		Subject: "i", Tags: map[string]string{},
		AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default",
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range EnrichmentClaims() {
		if _, ok := generic[name]; !ok {
			t.Fatalf("enrichment claim %q missing from %s", name, data)
		}
	}
	var back Claims
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal into Claims: %v", err)
	}
	if back.AvailabilityZone != "az-1" || back.Flavor != "m1.small" || back.UserID != "u1" ||
		back.ProjectName != "web" || back.DomainID != "default" || len(back.Custom) != 0 {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestParseClaims(t *testing.T) {
	payload := `{"iss":"nova-spire-plugin","aud":"spire-node-attestation","sub":"i","iat":1,"nbf":1,"exp":2,"jti":"j",` +
		`"project_id":"p","instance_id":"i","hostname":"h","tags":{"role":"web"},"flavor":"m1.small",` +
		`"country":"italy","future_number":5,"future_object":{"a":[1,2]},"future_null":null}`
	c, err := ParseClaims([]byte(payload))
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if c.Subject != "i" || c.Expiry != 2 || c.Tags["role"] != "web" || c.Flavor != "m1.small" {
		t.Fatalf("parsed %+v", c)
	}
	// unknown string claims are kept, unknown claims of other types skipped
	if want := map[string]string{"country": "italy"}; !maps.Equal(c.Custom, want) {
		t.Fatalf("Custom = %v, want %v", c.Custom, want)
	}
}

func TestParseClaimsRejects(t *testing.T) {
	for name, payload := range map[string]string{
		"not an object":          `[]`,
		"malformed":              `{"sub":`,
		"duplicate claim":        `{"sub":"a","sub":"b"}`,
		"duplicate unknown":      `{"x":"a","x":"b"}`,
		"non-string tag":         `{"tags":{"count":3}}`,
		"wrong type":             `{"iat":"yesterday"}`,
		"empty enrichment claim": `{"flavor":""}`,
		"non-string enrichment":  `{"availability_zone":3}`,
	} {
		if _, err := ParseClaims([]byte(payload)); err == nil {
			t.Errorf("%s: ParseClaims(%s) succeeded", name, payload)
		}
	}
}
