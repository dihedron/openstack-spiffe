// Package openstackiid implements the server side of the openstack_iid SPIRE
// node attestor: it verifies the instance identity token issued by the
// OpenStack metadata JWT issuer (openstack-spire-issuer) against the
// issuer's published keys, and turns its claims into the agent's SPIFFE ID
// and selectors.
//
// The claims are bound to the real instance by the issuer, which
// authenticates Nova's service token against Keystone and cross-checks the
// instance and project against the Nova API before signing; this plugin
// relies on that invariant without being able to enforce it.
package openstackiid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

var (
	// ErrInvalidToken is returned (wrapped) for a token failing any check.
	ErrInvalidToken = errors.New("invalid token")
	// ErrUnknownKID is returned (wrapped) when no verification key has the
	// token's kid; the caller may re-fetch the JWK Set and try again.
	ErrUnknownKID = errors.New("unknown kid")
)

// es256SignatureSize is the size of an ES256 signature: R || S, 32 bytes
// each (RFC 7518, section 3.4).
const es256SignatureSize = 64

// KeyLookup returns the verification key with the given kid.
type KeyLookup func(kid string) (keystore.PublicKey, bool)

// Verify checks a compact-serialized openstack_iid token and returns its
// header and claims: the signature, by the key its kid selects (exactly one
// key, never trying others), and every claim rule of the shared contract.
// The tolerance absorbs clock differences between the issuer and this
// server, so a token is accepted for at most iid.TTL + 2 × skew; it never
// stretches the lifetime itself (exp - iat <= iid.TTL). Verify is pure: it
// neither fetches keys nor records anything.
func Verify(token string, lookup KeyLookup, now time.Time, skew time.Duration) (iid.Header, iid.Claims, error) {
	if len(token) > iid.MaxTokenBytes {
		return iid.Header{}, iid.Claims{}, fmt.Errorf("%w: %d bytes, at most %d allowed", ErrInvalidToken, len(token), iid.MaxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return iid.Header{}, iid.Claims{}, fmt.Errorf("%w: not a compact-serialized JWS", ErrInvalidToken)
	}

	header, err := parseHeader(parts[0])
	if err != nil {
		return header, iid.Claims{}, err
	}
	key, ok := lookup(header.KeyID)
	if !ok {
		return header, iid.Claims{}, fmt.Errorf("%w %q", ErrUnknownKID, header.KeyID)
	}
	if key.Algorithm != header.Algorithm {
		return header, iid.Claims{}, fmt.Errorf("%w: alg %s, but key %q is for %s", ErrInvalidToken, header.Algorithm, key.ID, key.Algorithm)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return header, iid.Claims{}, fmt.Errorf("%w: decoding signature: %w", ErrInvalidToken, err)
	}
	if err := verifySignature(key, parts[0]+"."+parts[1], signature); err != nil {
		return header, iid.Claims{}, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return header, iid.Claims{}, fmt.Errorf("%w: decoding payload: %w", ErrInvalidToken, err)
	}
	claims, err := iid.ParseClaims(payload)
	if err != nil {
		return header, iid.Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if err := checkClaims(claims, now, skew); err != nil {
		return header, claims, err
	}
	return header, claims, nil
}

// parseHeader decodes the JOSE header and checks the algorithm allowlist.
func parseHeader(encoded string) (iid.Header, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return iid.Header{}, fmt.Errorf("%w: decoding header: %w", ErrInvalidToken, err)
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(data, &members); err != nil {
		return iid.Header{}, fmt.Errorf("%w: decoding header: %w", ErrInvalidToken, err)
	}
	// critical extensions must be understood (RFC 7515, section 4.1.11):
	// the issuer never uses any
	if _, ok := members["crit"]; ok {
		return iid.Header{}, fmt.Errorf("%w: critical header extensions are not supported", ErrInvalidToken)
	}
	var header iid.Header
	if err := json.Unmarshal(data, &header); err != nil {
		return iid.Header{}, fmt.Errorf("%w: decoding header: %w", ErrInvalidToken, err)
	}
	switch {
	case header.Algorithm != "RS256" && header.Algorithm != "ES256":
		return header, fmt.Errorf("%w: algorithm %q not allowed", ErrInvalidToken, header.Algorithm)
	case header.Type != "" && header.Type != "JWT":
		return header, fmt.Errorf("%w: type %q, want JWT", ErrInvalidToken, header.Type)
	}
	// checked before any key lookup, re-fetch or logging: until the
	// signature is verified the kid is attacker-controlled
	if err := iid.ValidateKeyID(header.KeyID); err != nil {
		return header, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return header, nil
}

// verifySignature checks a JWS signature over the signing input.
func verifySignature(key keystore.PublicKey, input string, signature []byte) error {
	digest := sha256.Sum256([]byte(input))
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		if key.Algorithm != "RS256" {
			break
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("%w: signature does not verify with key %q", ErrInvalidToken, key.ID)
		}
		return nil
	case *ecdsa.PublicKey:
		if key.Algorithm != "ES256" {
			break
		}
		if len(signature) != es256SignatureSize {
			return fmt.Errorf("%w: ES256 signature of %d bytes, want %d", ErrInvalidToken, len(signature), es256SignatureSize)
		}
		r := new(big.Int).SetBytes(signature[:es256SignatureSize/2])
		s := new(big.Int).SetBytes(signature[es256SignatureSize/2:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("%w: signature does not verify with key %q", ErrInvalidToken, key.ID)
		}
		return nil
	}
	return fmt.Errorf("%w: key %q (%s, %T) cannot verify tokens", ErrInvalidToken, key.ID, key.Algorithm, key.Key)
}

// checkClaims applies the claim rules of the shared contract.
func checkClaims(c iid.Claims, now time.Time, skew time.Duration) error {
	switch {
	case c.Issuer != iid.Issuer:
		return fmt.Errorf("%w: issuer %q, want %q", ErrInvalidToken, c.Issuer, iid.Issuer)
	case c.Audience != iid.Audience:
		return fmt.Errorf("%w: audience %q, want %q", ErrInvalidToken, c.Audience, iid.Audience)
	case c.ID == "":
		return fmt.Errorf("%w: no jti", ErrInvalidToken)
	}

	// the lifetime is checked on the token's own values, without tolerance
	if c.NotBefore > c.IssuedAt || c.IssuedAt >= c.Expiry {
		return fmt.Errorf("%w: inconsistent times (nbf %d, iat %d, exp %d)", ErrInvalidToken, c.NotBefore, c.IssuedAt, c.Expiry)
	}
	if lifetime := time.Duration(c.Expiry-c.IssuedAt) * time.Second; lifetime > iid.TTL {
		return fmt.Errorf("%w: lifetime %v exceeds %v", ErrInvalidToken, lifetime, iid.TTL)
	}
	// then against this server's clock, with tolerance
	latest := now.Add(skew)
	if time.Unix(c.NotBefore, 0).After(latest) || time.Unix(c.IssuedAt, 0).After(latest) {
		return fmt.Errorf("%w: not valid yet (nbf %d, iat %d)", ErrInvalidToken, c.NotBefore, c.IssuedAt)
	}
	if !time.Unix(c.Expiry, 0).After(now.Add(-skew)) {
		return fmt.Errorf("%w: expired (exp %d)", ErrInvalidToken, c.Expiry)
	}

	if c.Subject != c.InstanceID {
		return fmt.Errorf("%w: sub differs from instance_id", ErrInvalidToken)
	}
	if err := iid.ValidateInstanceID(c.InstanceID); err != nil {
		return fmt.Errorf("%w: instance_id: %w", ErrInvalidToken, err)
	}
	if err := iid.ValidateProjectID(c.ProjectID); err != nil {
		return fmt.Errorf("%w: project_id: %w", ErrInvalidToken, err)
	}
	if err := iid.ValidateHostname(c.Hostname); err != nil {
		return fmt.Errorf("%w: hostname: %w", ErrInvalidToken, err)
	}
	for key, value := range c.Tags {
		if err := iid.ValidateTagKey(key); err != nil {
			return fmt.Errorf("%w: tags: %w", ErrInvalidToken, err)
		}
		if err := iid.ValidateTagValue(value); err != nil {
			return fmt.Errorf("%w: tags: %w", ErrInvalidToken, err)
		}
	}
	// ParseClaims already rejects an enrichment claim that is present but
	// empty: an empty value here is an absent claim
	for name, value := range map[string]string{
		iid.ClaimAvailabilityZone: c.AvailabilityZone,
		iid.ClaimFlavor:           c.Flavor,
		iid.ClaimUserID:           c.UserID,
		iid.ClaimProjectName:      c.ProjectName,
		iid.ClaimDomainID:         c.DomainID,
	} {
		if value == "" {
			continue
		}
		if err := iid.ValidateEnrichmentValue(value); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidToken, name, err)
		}
	}
	if len(c.Tags) > 0 {
		data, err := json.Marshal(c.Tags)
		if err != nil {
			return fmt.Errorf("%w: tags: %w", ErrInvalidToken, err)
		}
		if len(data) > iid.MaxTagsBytes {
			return fmt.Errorf("%w: tags of %d bytes, at most %d allowed", ErrInvalidToken, len(data), iid.MaxTagsBytes)
		}
	}
	return nil
}
