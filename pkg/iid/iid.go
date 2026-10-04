// Package iid defines the contract shared between the OpenStack metadata JWT
// issuer (openstack-spire-issuer) and the openstack_iid SPIRE node attestor
// plugins: the JWT header and claim schema, the fixed issuer/audience values
// and the shape of the vendordata response. Both sides must import it rather
// than re-declaring any of these values.
package iid

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// TargetName is the name of the Nova DynamicJSON vendordata target; Nova
	// nests this service's response under this key in vendor_data2.json.
	TargetName = "openstack_iid"
	// Issuer is the value of the "iss" claim of every issued token.
	Issuer = "nova-spire-plugin"
	// Audience is the value of the "aud" claim of every issued token.
	Audience = "spire-node-attestation"
	// Algorithm is the default JWS signing algorithm.
	Algorithm = "RS256"
	// TTL is the fixed validity window of every issued token (exp - iat).
	TTL = 5 * time.Minute
	// MaxTagsBytes is the maximum size of the JSON-serialized "tags" claim.
	MaxTagsBytes = 1024
	// MaxCustomClaimsBytes is the maximum size of the operator-configured
	// custom claims, serialized as a JSON object.
	MaxCustomClaimsBytes = 2048
	// MaxTokenBytes is the maximum size of a compact-serialized token: the
	// issuer never mints a larger one, and the SPIRE plugins reject it.
	MaxTokenBytes = 16 << 10
	// MaxJWKSKeys is the maximum number of keys in a JWK Set: a larger set
	// is a failed fetch, never truncated.
	MaxJWKSKeys = 100
)

const (
	maxProjectIDLength       = 64
	maxHostnameLength        = 255
	maxEnrichmentValueLength = 255
	// MaxKeyIDBytes is the maximum length of a kid.
	MaxKeyIDBytes = 128
)

var (
	// canonical, lowercase UUID form as produced by Nova; alternative forms
	// (braces, URN prefix, uppercase) are rejected so that the same instance
	// can never appear under two different "sub" values.
	instanceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	projectIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// a lowercase DNS label: replica IDs end up in every kid.
	replicaIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// <YYYY-MM-DD>-<replica-id>-key-<n>, the replica ID being a DNS label.
	keyIDPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?-key-[0-9]+$`)
)

// Header is the JOSE header of an issued token.
type Header struct {
	// Algorithm is the JWS signing algorithm (e.g. "RS256").
	Algorithm string `json:"alg"`
	// KeyID identifies the signing key in the JWKS.
	KeyID string `json:"kid"`
	// Type is the media type of the token, always "JWT".
	Type string `json:"typ"`
}

// Claims is the payload of an issued token.
type Claims struct {
	// Issuer is always Issuer.
	Issuer string `json:"iss"`
	// Audience is always Audience.
	Audience string `json:"aud"`
	// Subject is the instance ID.
	Subject string `json:"sub"`
	// IssuedAt is the issuance time, in seconds since the Unix epoch.
	IssuedAt int64 `json:"iat"`
	// NotBefore is the start of validity, in seconds since the Unix epoch.
	NotBefore int64 `json:"nbf"`
	// Expiry is the end of validity, in seconds since the Unix epoch.
	Expiry int64 `json:"exp"`
	// ID is a UUID freshly generated for every token.
	ID string `json:"jti"`
	// ProjectID is the project owning the instance, as reported by Nova.
	ProjectID string `json:"project_id"`
	// InstanceID is the instance UUID, as reported by Nova.
	InstanceID string `json:"instance_id"`
	// Hostname is the instance hostname, as reported by Nova.
	Hostname string `json:"hostname"`
	// Tags holds the filtered, string-only instance metadata.
	Tags map[string]string `json:"tags"`
	// AvailabilityZone is the instance's availability zone (optional
	// enrichment claim, from the Nova server record).
	AvailabilityZone string `json:"availability_zone,omitempty"`
	// Flavor is the name of the instance's flavor (optional enrichment
	// claim, from the Nova server record).
	Flavor string `json:"flavor,omitempty"`
	// UserID is the ID of the user who booted the instance (optional
	// enrichment claim, from the Nova server record).
	UserID string `json:"user_id,omitempty"`
	// ProjectName is the name of the project owning the instance (optional
	// enrichment claim, from Keystone).
	ProjectName string `json:"project_name,omitempty"`
	// DomainID is the ID of the domain of the project owning the instance
	// (optional enrichment claim, from Keystone).
	DomainID string `json:"domain_id,omitempty"`
	// Custom holds the operator-configured static claims, serialized as
	// top-level claims. Custom claims must not use reserved names: issuers
	// must check them with ValidateCustomClaims; in addition, marshaling
	// fails if one collides with an always-emitted claim. On unmarshal it
	// collects every claim not otherwise modelled here.
	Custom map[string]string `json:",embed"`
}

// ErrInvalidCustomClaim is returned (wrapped) when a custom claim has an
// empty or reserved name, or when the custom claims are too large.
var ErrInvalidCustomClaim = errors.New("invalid custom claim")

// ErrInvalidClaim is returned (wrapped) by the field validators. Their
// messages describe the problem without naming the field, so that callers
// can name it in their own terms (e.g. "project-id" in a Nova request,
// "project_id" in a token).
var ErrInvalidClaim = errors.New("invalid claim")

// ValidateProjectID checks a project ID: 1 to 64 characters from
// [A-Za-z0-9_-]. Project IDs end up in SPIFFE ID paths.
func ValidateProjectID(id string) error {
	switch {
	case id == "":
		return fmt.Errorf("%w: missing", ErrInvalidClaim)
	case len(id) > maxProjectIDLength:
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidClaim, maxProjectIDLength)
	case !projectIDPattern.MatchString(id):
		return fmt.Errorf("%w: contains invalid characters", ErrInvalidClaim)
	}
	return nil
}

// ValidateInstanceID checks an instance ID: a canonical lowercase UUID.
func ValidateInstanceID(id string) error {
	switch {
	case id == "":
		return fmt.Errorf("%w: missing", ErrInvalidClaim)
	case !instanceIDPattern.MatchString(id):
		return fmt.Errorf("%w: not a canonical lowercase UUID", ErrInvalidClaim)
	}
	return nil
}

// ValidateHostname checks a hostname: non-empty, at most 255 characters,
// without control characters.
func ValidateHostname(hostname string) error {
	switch {
	case hostname == "":
		return fmt.Errorf("%w: missing", ErrInvalidClaim)
	case len(hostname) > maxHostnameLength:
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidClaim, maxHostnameLength)
	case strings.ContainsFunc(hostname, unicode.IsControl):
		return fmt.Errorf("%w: contains control characters", ErrInvalidClaim)
	}
	return nil
}

// ValidateTagKey checks the key of a "tags" entry: non-empty, without ':',
// which would make the "tag:<key>:<value>" selector ambiguous, and with the
// character rules of ValidateTagValue.
func ValidateTagKey(key string) error {
	switch {
	case key == "":
		return fmt.Errorf("%w: empty tag key", ErrInvalidClaim)
	case strings.Contains(key, ":"):
		return fmt.Errorf("%w: tag key contains ':'", ErrInvalidClaim)
	}
	if err := checkCharacters(key); err != nil {
		return fmt.Errorf("%w: tag key %w", ErrInvalidClaim, err)
	}
	return nil
}

// ValidateTagValue checks the value of a "tags" entry: valid UTF-8, without
// control (Cc) or format (Cf) characters, which could make selectors that
// look alike differ, or forge log lines. Empty values are valid.
func ValidateTagValue(value string) error {
	if err := checkCharacters(value); err != nil {
		return fmt.Errorf("%w: tag value %w", ErrInvalidClaim, err)
	}
	return nil
}

// ValidateEnrichmentValue checks the value of an enrichment claim: non-empty,
// at most 255 bytes, with the character rules of ValidateTagValue.
func ValidateEnrichmentValue(value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%w: empty enrichment value", ErrInvalidClaim)
	case len(value) > maxEnrichmentValueLength:
		return fmt.Errorf("%w: enrichment value longer than %d bytes", ErrInvalidClaim, maxEnrichmentValueLength)
	}
	if err := checkCharacters(value); err != nil {
		return fmt.Errorf("%w: enrichment value %w", ErrInvalidClaim, err)
	}
	return nil
}

// checkCharacters returns an error, phrased to follow the name of what is
// checked, if s is not valid UTF-8 or contains control or format characters.
func checkCharacters(s string) error {
	switch {
	case !utf8.ValidString(s):
		return errors.New("is not valid UTF-8")
	case strings.ContainsFunc(s, unicode.IsControl):
		return errors.New("contains control characters")
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Cf, r) }):
		return errors.New("contains format characters")
	}
	return nil
}

// ValidateReplicaID checks a replica ID: a lowercase DNS label, since it ends
// up in every kid the replica issues.
func ValidateReplicaID(id string) error {
	if !replicaIDPattern.MatchString(id) {
		return fmt.Errorf("replica ID %q is not a lowercase DNS label", id)
	}
	return nil
}

// ErrInvalidKeyID marks a kid that does not have the issuer's format.
var ErrInvalidKeyID = errors.New("invalid kid")

// ValidateKeyID checks a kid: at most MaxKeyIDBytes, of the form
// <YYYY-MM-DD>-<replica-id>-key-<n>, the replica ID being a lowercase DNS
// label. Until a token's signature is checked its kid is attacker-controlled,
// so the error never contains it.
func ValidateKeyID(kid string) error {
	switch {
	case kid == "":
		return fmt.Errorf("%w: missing", ErrInvalidKeyID)
	case len(kid) > MaxKeyIDBytes:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidKeyID, MaxKeyIDBytes)
	case !keyIDPattern.MatchString(kid):
		return fmt.Errorf("%w: not of the form <YYYY-MM-DD>-<replica-id>-key-<n>", ErrInvalidKeyID)
	}
	return nil
}

// Names of the optional enrichment claims, looked up from Nova and Keystone
// when enabled in the issuer configuration.
const (
	// ClaimAvailabilityZone is the availability zone the instance runs in.
	ClaimAvailabilityZone = "availability_zone"
	// ClaimFlavor is the name of the instance flavor.
	ClaimFlavor = "flavor"
	// ClaimUserID is the ID of the user who booted the instance.
	ClaimUserID = "user_id"
	// ClaimProjectName is the name of the project owning the instance.
	ClaimProjectName = "project_name"
	// ClaimDomainID is the ID of the domain of the project owning the instance.
	ClaimDomainID = "domain_id"
)

var enrichmentClaims = []string{
	ClaimAvailabilityZone, ClaimFlavor, ClaimUserID, ClaimProjectName, ClaimDomainID,
}

// reservedClaims are the claim names defined by this contract; custom claims
// must not use them.
var reservedClaims = append([]string{
	"iss", "aud", "sub", "iat", "nbf", "exp", "jti",
	"project_id", "instance_id", "hostname", "tags",
}, enrichmentClaims...)

// EnrichmentClaims returns the names of the optional enrichment claims.
func EnrichmentClaims() []string {
	return slices.Clone(enrichmentClaims)
}

// ReservedClaims returns the claim names that custom claims must not use.
func ReservedClaims() []string {
	return slices.Clone(reservedClaims)
}

// IsReservedClaim reports whether name is a claim defined by this contract.
func IsReservedClaim(name string) bool {
	return slices.Contains(reservedClaims, name)
}

// ValidateCustomClaims checks that no custom claim has an empty or reserved
// name, and that the custom claims, serialized as a JSON object, do not
// exceed MaxCustomClaimsBytes.
func ValidateCustomClaims(custom map[string]string) error {
	for name := range custom {
		if name == "" {
			return fmt.Errorf("%w: empty name", ErrInvalidCustomClaim)
		}
		if IsReservedClaim(name) {
			return fmt.Errorf("%w: %q is a reserved claim", ErrInvalidCustomClaim, name)
		}
	}
	size, err := CustomClaimsSize(custom)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCustomClaim, err)
	}
	if size > MaxCustomClaimsBytes {
		return fmt.Errorf("%w: %d bytes once serialized, at most %d allowed", ErrInvalidCustomClaim, size, MaxCustomClaimsBytes)
	}
	return nil
}

// CustomClaimsSize returns the size of the custom claims serialized as a
// JSON object, escaping included.
func CustomClaimsSize(custom map[string]string) (int, error) {
	if len(custom) == 0 {
		return 0, nil
	}
	data, err := json.Marshal(custom)
	if err != nil {
		return 0, fmt.Errorf("encoding custom claims: %w", err)
	}
	return len(data), nil
}

// ParseClaims decodes a token payload. Unlike a plain decode into Claims, it
// skips claims it does not model whose values are not strings, so that a
// claim added later by the issuer never breaks parsing; unknown string claims
// are collected into Custom. Duplicate claim names are rejected, and an
// enrichment claim, when present, must be a non-empty string: the issuer
// never emits an empty one.
func ParseClaims(payload []byte) (Claims, error) {
	var members map[string]jsontext.Value
	if err := json.Unmarshal(payload, &members); err != nil {
		return Claims{}, fmt.Errorf("decoding claims: %w", err)
	}
	for name, value := range members {
		switch {
		case slices.Contains(enrichmentClaims, name):
			if value.Kind() != '"' || string(value) == `""` {
				return Claims{}, fmt.Errorf("decoding claims: %q must be a non-empty string", name)
			}
		case !IsReservedClaim(name) && value.Kind() != '"':
			delete(members, name)
		}
	}
	filtered, err := json.Marshal(members)
	if err != nil {
		return Claims{}, fmt.Errorf("decoding claims: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(filtered, &c); err != nil {
		return Claims{}, fmt.Errorf("decoding claims: %w", err)
	}
	return c, nil
}

// VendorDataResponse is the part of vendor_data2.json the agent plugin
// reads: Nova nests every DynamicJSON target's response under the target's
// name, so the issuer's VendorData appears under TargetName. Other targets
// may sit next to it.
type VendorDataResponse struct {
	Target VendorData `json:"openstack_iid"`
}

// VendorData is the body the issuer returns to Nova for the TargetName
// target.
type VendorData struct {
	// JWT is the compact-serialized signed token.
	JWT string `json:"jwt"`
}

// NewVendorDataResponse returns the vendor_data2.json content an instance
// sees for a token (e.g. to fake Nova's metadata service in tests).
func NewVendorDataResponse(token string) VendorDataResponse {
	return VendorDataResponse{Target: VendorData{JWT: token}}
}
