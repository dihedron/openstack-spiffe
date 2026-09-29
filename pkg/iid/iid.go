// Package iid defines the contract shared between the Nova vendordata JWT
// issuer (openstack-spire-metadata) and the openstack_iid SPIRE node attestor
// plugins: the JWT header and claim schema, the fixed issuer/audience values
// and the shape of the vendordata response. Both sides must import it rather
// than re-declaring any of these values.
package iid

import "time"

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
