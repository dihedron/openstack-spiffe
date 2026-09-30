// Package iid defines the contract shared between the Nova vendordata JWT
// issuer (openstack-spire-metadata) and the openstack_iid SPIRE node attestor
// plugins: the JWT header and claim schema, the fixed issuer/audience values
// and the shape of the vendordata response. Both sides must import it rather
// than re-declaring any of these values.
package iid

import (
	"errors"
	"fmt"
	"slices"
	"time"
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
// empty or reserved name.
var ErrInvalidCustomClaim = errors.New("invalid custom claim")

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
// name.
func ValidateCustomClaims(custom map[string]string) error {
	for name := range custom {
		if name == "" {
			return fmt.Errorf("%w: empty name", ErrInvalidCustomClaim)
		}
		if IsReservedClaim(name) {
			return fmt.Errorf("%w: %q is a reserved claim", ErrInvalidCustomClaim, name)
		}
	}
	return nil
}

// VendorDataResponse is the body returned to Nova; its only key must match
// TargetName so that the agent plugin can rely on a fixed lookup path.
type VendorDataResponse struct {
	Target VendorData `json:"openstack_iid"`
}

// VendorData is the per-target content of the vendordata response.
type VendorData struct {
	// JWT is the compact-serialized signed token.
	JWT string `json:"jwt"`
}

// NewVendorDataResponse wraps a signed token into the vendordata response.
func NewVendorDataResponse(token string) VendorDataResponse {
	return VendorDataResponse{Target: VendorData{JWT: token}}
}
