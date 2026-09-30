package claims

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	testProjectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	testInstanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
)

func validRequest() NovaRequest {
	return NovaRequest{
		ProjectID:  testProjectID,
		InstanceID: testInstanceID,
		ImageID:    "0d4c1a3e-5b6f-4e7a-8c9d-0e1f2a3b4c5d",
		Hostname:   "vm-01",
		Metadata:   map[string]any{"role": "web", "env": "prod"},
	}
}

func TestNovaRequestDecodeIgnoresExtraFields(t *testing.T) {
	body := `{
		"project-id": "` + testProjectID + `",
		"instance-id": "` + testInstanceID + `",
		"image-id": "img",
		"hostname": "vm-01",
		"metadata": {"role": "web", "count": 3},
		"user-data": "I2Nsb3VkLWNvbmZpZw==",
		"boot-roles": "member,reader"
	}`
	var req NovaRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.ProjectID != testProjectID || req.InstanceID != testInstanceID || req.ImageID != "img" || req.Hostname != "vm-01" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.Metadata["role"] != "web" {
		t.Fatalf("metadata not decoded: %+v", req.Metadata)
	}
}

func TestNovaRequestDecodeRejectsDuplicateFields(t *testing.T) {
	body := `{"project-id":"a","instance-id":"` + testInstanceID + `","instance-id":"other"}`
	var req NovaRequest
	if err := json.Unmarshal([]byte(body), &req); err == nil {
		t.Fatalf("expected error on duplicate instance-id, got %+v", req)
	}
}

func TestNovaRequestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NovaRequest)
		field  string
	}{
		{"valid", func(*NovaRequest) {}, ""},
		{"valid without image (boot from volume)", func(r *NovaRequest) { r.ImageID = "" }, ""},
		{"valid without metadata", func(r *NovaRequest) { r.Metadata = nil }, ""},
		{"missing project-id", func(r *NovaRequest) { r.ProjectID = "" }, "project-id"},
		{"project-id with invalid characters", func(r *NovaRequest) { r.ProjectID = "abc/def" }, "project-id"},
		{"project-id too long", func(r *NovaRequest) { r.ProjectID = strings.Repeat("a", 65) }, "project-id"},
		{"missing instance-id", func(r *NovaRequest) { r.InstanceID = "" }, "instance-id"},
		{"instance-id not a uuid", func(r *NovaRequest) { r.InstanceID = "not-a-uuid" }, "instance-id"},
		{"instance-id uppercase", func(r *NovaRequest) { r.InstanceID = strings.ToUpper(testInstanceID) }, "instance-id"},
		{"instance-id urn form", func(r *NovaRequest) { r.InstanceID = "urn:uuid:" + testInstanceID }, "instance-id"},
		{"missing hostname", func(r *NovaRequest) { r.Hostname = "" }, "hostname"},
		{"hostname too long", func(r *NovaRequest) { r.Hostname = strings.Repeat("h", 256) }, "hostname"},
		{"hostname with control characters", func(r *NovaRequest) { r.Hostname = "vm\n01" }, "hostname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validRequest()
			tt.mutate(&req)
			err := req.Validate()
			if tt.field == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error %q does not mention field %q", err, tt.field)
			}
		})
	}
}

func droppedKeys(dropped []DroppedTag) []string {
	keys := make([]string, 0, len(dropped))
	for _, d := range dropped {
		keys = append(keys, d.Key)
	}
	return keys
}

func TestFilterTagsDropsNonStringValues(t *testing.T) {
	tags, dropped := FilterTags(map[string]any{
		"role":   "web",
		"count":  3.0,
		"flag":   true,
		"nested": map[string]any{"a": "b"},
		"list":   []any{"a"},
		"null":   nil,
	}, nil, iid.MaxTagsBytes)

	if len(tags) != 1 || tags["role"] != "web" {
		t.Fatalf("tags = %v, want only role=web", tags)
	}
	if got, want := droppedKeys(dropped), []string{"count", "flag", "list", "nested", "null"}; !slices.Equal(got, want) {
		t.Fatalf("dropped = %v, want %v", got, want)
	}
	for _, d := range dropped {
		if d.Reason != ReasonNotString {
			t.Errorf("dropped %q reason = %q, want %q", d.Key, d.Reason, ReasonNotString)
		}
	}
}

func TestFilterTagsAllowlist(t *testing.T) {
	tags, dropped := FilterTags(map[string]any{
		"role":    "web",
		"env":     "prod",
		"secret":  "s3cr3t",
		"counter": 1.0,
	}, []string{"role", "env", "counter"}, iid.MaxTagsBytes)

	if len(tags) != 2 || tags["role"] != "web" || tags["env"] != "prod" {
		t.Fatalf("tags = %v", tags)
	}
	reasons := map[string]Reason{}
	for _, d := range dropped {
		reasons[d.Key] = d.Reason
	}
	if reasons["secret"] != ReasonNotAllowed {
		t.Errorf("secret reason = %q, want %q", reasons["secret"], ReasonNotAllowed)
	}
	if reasons["counter"] != ReasonNotString {
		t.Errorf("counter reason = %q, want %q", reasons["counter"], ReasonNotString)
	}
}

func TestFilterTagsEmptyAndNil(t *testing.T) {
	for _, metadata := range []map[string]any{nil, {}} {
		tags, dropped := FilterTags(metadata, nil, iid.MaxTagsBytes)
		if tags == nil || len(tags) != 0 || len(dropped) != 0 {
			t.Fatalf("FilterTags(%v) = %v, %v; want empty non-nil map and nothing dropped", metadata, tags, dropped)
		}
	}
}

func TestFilterTagsSizeCap(t *testing.T) {
	metadata := map[string]any{}
	for i := range 40 {
		// each entry serializes to ~70 bytes; 40 of them overflow 1024 bytes
		metadata[fmt.Sprintf("key-%02d", i)] = strings.Repeat("v", 60)
	}

	tags, dropped := FilterTags(metadata, nil, iid.MaxTagsBytes)

	data, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > iid.MaxTagsBytes {
		t.Fatalf("serialized tags are %d bytes, want <= %d", len(data), iid.MaxTagsBytes)
	}
	if len(tags)+len(dropped) != len(metadata) {
		t.Fatalf("kept %d + dropped %d != %d", len(tags), len(dropped), len(metadata))
	}
	if len(dropped) == 0 {
		t.Fatalf("expected some tags to be dropped")
	}
	// deterministic: the lowest keys (in sorted order) are kept
	for i := range len(tags) {
		if _, ok := tags[fmt.Sprintf("key-%02d", i)]; !ok {
			t.Fatalf("key-%02d missing; kept keys must be a sorted prefix: %v", i, tags)
		}
	}
	for _, d := range dropped {
		if d.Reason != ReasonTooLarge {
			t.Errorf("dropped %q reason = %q, want %q", d.Key, d.Reason, ReasonTooLarge)
		}
	}

	// same input, same output
	again, _ := FilterTags(metadata, nil, iid.MaxTagsBytes)
	if len(again) != len(tags) {
		t.Fatalf("non-deterministic result: %d vs %d tags", len(again), len(tags))
	}
}

func TestFilterTagsSizeCapSkipsOversizedEntryButKeepsLaterOnes(t *testing.T) {
	tags, dropped := FilterTags(map[string]any{
		"a": "small",
		"b": strings.Repeat("x", 2000),
		"c": "small",
	}, nil, iid.MaxTagsBytes)
	if len(tags) != 2 || tags["a"] != "small" || tags["c"] != "small" {
		t.Fatalf("tags = %v, want a and c", tags)
	}
	if len(dropped) != 1 || dropped[0].Key != "b" || dropped[0].Reason != ReasonTooLarge {
		t.Fatalf("dropped = %+v, want b too large", dropped)
	}
}

func TestFilterTagsSizeAccountsForEscaping(t *testing.T) {
	// characters that JSON escapes expand on serialization (e.g. '<' -> <)
	metadata := map[string]any{}
	for i := range 20 {
		metadata[fmt.Sprintf("k%02d", i)] = strings.Repeat("<\"", 20)
	}
	tags, _ := FilterTags(metadata, nil, iid.MaxTagsBytes)
	data, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > iid.MaxTagsBytes {
		t.Fatalf("serialized tags are %d bytes, want <= %d", len(data), iid.MaxTagsBytes)
	}
}

func TestReasonString(t *testing.T) {
	tests := map[Reason]string{
		ReasonNotString:    "non-string value",
		ReasonNotAllowed:   "key not in allowlist",
		ReasonTooLarge:     "tags size cap exceeded",
		ReasonNotEncodable: "not encodable",
		Reason(0):          "unknown reason (0)",
		Reason(-1):         "unknown reason (-1)",
	}
	for reason, want := range tests {
		if got := reason.String(); got != want {
			t.Errorf("Reason(%d).String() = %q, want %q", int8(reason), got, want)
		}
	}
}

func fixedBuilder(t *testing.T, now time.Time) *Builder {
	t.Helper()
	n := 0
	b, err := NewBuilder(
		WithClock(func() time.Time { return now }),
		WithIDGenerator(func() string { n++; return fmt.Sprintf("jti-%d", n) }),
	)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

func TestBuilderBuild(t *testing.T) {
	now := time.Unix(1758000000, 999_000_000)
	b := fixedBuilder(t, now)

	req := validRequest()
	req.Metadata["count"] = 3.0
	claims, err := b.Build(context.Background(), req, Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := iid.Claims{
		Issuer:     iid.Issuer,
		Audience:   iid.Audience,
		Subject:    testInstanceID,
		IssuedAt:   1758000000,
		NotBefore:  1758000000,
		Expiry:     1758000300,
		ID:         "jti-1",
		ProjectID:  testProjectID,
		InstanceID: testInstanceID,
		Hostname:   "vm-01",
	}
	if claims.Issuer != want.Issuer || claims.Audience != want.Audience || claims.Subject != want.Subject ||
		claims.IssuedAt != want.IssuedAt || claims.NotBefore != want.NotBefore || claims.Expiry != want.Expiry ||
		claims.ID != want.ID || claims.ProjectID != want.ProjectID || claims.InstanceID != want.InstanceID ||
		claims.Hostname != want.Hostname {
		t.Fatalf("claims = %+v\nwant   %+v", claims, want)
	}
	if len(claims.Tags) != 2 || claims.Tags["role"] != "web" || claims.Tags["env"] != "prod" {
		t.Fatalf("tags = %v", claims.Tags)
	}
	if claims.Expiry-claims.IssuedAt != int64(iid.TTL/time.Second) {
		t.Fatalf("exp - iat = %d, want %d", claims.Expiry-claims.IssuedAt, int64(iid.TTL/time.Second))
	}
}

func TestBuilderFreshJTIPerToken(t *testing.T) {
	b, err := NewBuilder() // default generator: random UUIDs
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	seen := map[string]bool{}
	for range 100 {
		claims, err := b.Build(context.Background(), validRequest(), Enrichment{})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if claims.ID == "" || seen[claims.ID] {
			t.Fatalf("jti %q empty or reused", claims.ID)
		}
		seen[claims.ID] = true
	}
}

func TestBuilderRejectsInvalidRequest(t *testing.T) {
	b := fixedBuilder(t, time.Now())
	req := validRequest()
	req.InstanceID = "bogus"
	if _, err := b.Build(context.Background(), req, Enrichment{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Build error = %v, want ErrInvalidRequest", err)
	}
}

func TestBuilderDoesNotAliasRequestMetadata(t *testing.T) {
	b := fixedBuilder(t, time.Now())
	req := validRequest()
	claims, err := b.Build(context.Background(), req, Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	req.Metadata["role"] = "changed"
	if claims.Tags["role"] != "web" {
		t.Fatalf("claims tags alias request metadata")
	}
}

func TestNewBuilderTTLBounds(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, iid.TTL + time.Second} {
		if _, err := NewBuilder(WithTTL(ttl)); err == nil {
			t.Errorf("NewBuilder(WithTTL(%v)) succeeded, want error", ttl)
		}
	}
	if _, err := NewBuilder(WithTTL(time.Minute)); err != nil {
		t.Errorf("NewBuilder(WithTTL(1m)): %v", err)
	}
}

func TestNewBuilderMaxTagsBytesBounds(t *testing.T) {
	for _, size := range []int{1, iid.MaxTagsBytes + 1} {
		if _, err := NewBuilder(WithMaxTagsBytes(size)); err == nil {
			t.Errorf("NewBuilder(WithMaxTagsBytes(%d)) succeeded, want error", size)
		}
	}
}

func TestBuilderAllowlist(t *testing.T) {
	b, err := NewBuilder(WithAllowlist([]string{"env"}))
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	claims, err := b.Build(context.Background(), validRequest(), Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(claims.Tags) != 1 || claims.Tags["env"] != "prod" {
		t.Fatalf("tags = %v, want only env", claims.Tags)
	}
}

func TestBuilderCustomClaims(t *testing.T) {
	custom := map[string]string{"country": "italy"}
	b, err := NewBuilder(WithCustomClaims(custom))
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	custom["country"] = "changed" // the builder must hold its own copy

	claims, err := b.Build(context.Background(), validRequest(), Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(claims.Custom) != 1 || claims.Custom["country"] != "italy" {
		t.Fatalf("custom claims = %v, want country=italy", claims.Custom)
	}
	claims.Custom["country"] = "tampered" // tokens must not share the map
	again, err := b.Build(context.Background(), validRequest(), Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if again.Custom["country"] != "italy" {
		t.Fatalf("custom claims shared between tokens")
	}
}

func TestBuilderWithoutCustomClaims(t *testing.T) {
	claims, err := fixedBuilder(t, time.Now()).Build(context.Background(), validRequest(), Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(claims.Custom) != 0 {
		t.Fatalf("custom claims = %v, want none", claims.Custom)
	}
}

func TestNewBuilderRejectsReservedCustomClaims(t *testing.T) {
	for _, name := range iid.ReservedClaims() {
		if _, err := NewBuilder(WithCustomClaims(map[string]string{name: "x"})); !errors.Is(err, iid.ErrInvalidCustomClaim) {
			t.Errorf("NewBuilder with custom claim %q: err = %v, want ErrInvalidCustomClaim", name, err)
		}
	}
	if _, err := NewBuilder(WithCustomClaims(map[string]string{"": "x"})); !errors.Is(err, iid.ErrInvalidCustomClaim) {
		t.Errorf("NewBuilder with empty custom claim name: err = %v, want ErrInvalidCustomClaim", err)
	}
}

func TestBuildAddsEnrichment(t *testing.T) {
	b := fixedBuilder(t, time.Now())
	enrichment := Enrichment{AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default"}
	claims, err := b.Build(context.Background(), validRequest(), enrichment)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if claims.AvailabilityZone != "az-1" || claims.Flavor != "m1.small" || claims.UserID != "u1" ||
		claims.ProjectName != "web" || claims.DomainID != "default" {
		t.Fatalf("enrichment not applied: %+v", claims)
	}
	plain, err := b.Build(context.Background(), validRequest(), Enrichment{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if plain.AvailabilityZone != "" || plain.Flavor != "" || plain.UserID != "" || plain.ProjectName != "" || plain.DomainID != "" {
		t.Fatalf("enrichment claims set without enrichment: %+v", plain)
	}
}
