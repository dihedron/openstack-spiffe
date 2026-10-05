// Package jwks serves signing keys as an RFC 7517 JSON Web Key Set. The same
// handler serves a signer replica's own keys and the JWKS aggregator's merged
// set; the Key type converts between keystore.PublicKey and its JWK form in
// both directions, validating what it reads.
package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
)

const (
	minRSABits = 2048
	// p256CoordinateSize is the size of a P-256 coordinate (RFC 7518,
	// section 6.2.1.2: x and y are padded to the full coordinate size).
	p256CoordinateSize = 32
	// maxRSAExponent keeps the exponent within what crypto/rsa accepts.
	maxRSAExponent = 1<<31 - 1
)

// ErrInvalidKey is returned (wrapped) for a key that cannot be published or
// accepted as an openstack_iid signing key.
var ErrInvalidKey = errors.New("invalid signing key")

// Key is a JSON Web Key (RFC 7517) holding the public half of an RS256 or
// ES256 signing key. It has no members for private key material.
type Key struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	// Modulus and Exponent are the RSA public key (kty "RSA").
	Modulus  string `json:"n,omitempty"`
	Exponent string `json:"e,omitempty"`
	// Curve, X and Y are the EC public key (kty "EC").
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
}

// Set is a JSON Web Key Set (RFC 7517, section 5).
type Set struct {
	Keys []Key `json:"keys"`
}

// FromPublicKey returns the JWK form of a signing key: RS256 with an RSA key
// of at least 2048 bits, or ES256 with a P-256 key.
func FromPublicKey(k keystore.PublicKey) (Key, error) {
	if k.ID == "" {
		return Key{}, fmt.Errorf("%w: empty kid", ErrInvalidKey)
	}
	key := Key{KeyID: k.ID, Algorithm: k.Algorithm, Use: "sig"}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		if k.Algorithm != "RS256" {
			return Key{}, fmt.Errorf("%w: key %q is an RSA key but its algorithm is %q", ErrInvalidKey, k.ID, k.Algorithm)
		}
		if pub.N.BitLen() < minRSABits {
			return Key{}, fmt.Errorf("%w: key %q is a %d-bit RSA key, want at least %d bits", ErrInvalidKey, k.ID, pub.N.BitLen(), minRSABits)
		}
		key.KeyType = "RSA"
		key.Modulus = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		key.Exponent = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		if k.Algorithm != "ES256" {
			return Key{}, fmt.Errorf("%w: key %q is an EC key but its algorithm is %q", ErrInvalidKey, k.ID, k.Algorithm)
		}
		if pub.Curve != elliptic.P256() {
			return Key{}, fmt.Errorf("%w: key %q is on curve %s, want P-256", ErrInvalidKey, k.ID, pub.Curve.Params().Name)
		}
		point, err := pub.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return Key{}, fmt.Errorf("%w: key %q: %w", ErrInvalidKey, k.ID, err)
		}
		key.KeyType = "EC"
		key.Curve = "P-256"
		key.X = base64.RawURLEncoding.EncodeToString(point[1 : 1+p256CoordinateSize])
		key.Y = base64.RawURLEncoding.EncodeToString(point[1+p256CoordinateSize:])
	default:
		return Key{}, fmt.Errorf("%w: key %q has unsupported type %T", ErrInvalidKey, k.ID, k.Key)
	}
	return key, nil
}

// PublicKey validates the JWK and returns the key it holds. It accepts only
// signing keys (use "sig") for RS256 (RSA, at least 2048 bits) or ES256
// (a point on P-256), with the algorithm matching the key type.
func (k Key) PublicKey() (keystore.PublicKey, error) {
	if k.KeyID == "" {
		return keystore.PublicKey{}, fmt.Errorf("%w: empty kid", ErrInvalidKey)
	}
	if k.Use != "sig" {
		return keystore.PublicKey{}, fmt.Errorf("%w: key %q has use %q, want sig", ErrInvalidKey, k.KeyID, k.Use)
	}
	switch {
	case k.KeyType == "RSA" && k.Algorithm == "RS256":
		pub, err := k.rsaPublicKey()
		if err != nil {
			return keystore.PublicKey{}, fmt.Errorf("%w: key %q: %w", ErrInvalidKey, k.KeyID, err)
		}
		return keystore.PublicKey{ID: k.KeyID, Algorithm: k.Algorithm, Key: pub}, nil
	case k.KeyType == "EC" && k.Algorithm == "ES256":
		pub, err := k.ecPublicKey()
		if err != nil {
			return keystore.PublicKey{}, fmt.Errorf("%w: key %q: %w", ErrInvalidKey, k.KeyID, err)
		}
		return keystore.PublicKey{ID: k.KeyID, Algorithm: k.Algorithm, Key: pub}, nil
	default:
		return keystore.PublicKey{}, fmt.Errorf("%w: key %q has kty %q and alg %q, want RSA/RS256 or EC/ES256", ErrInvalidKey, k.KeyID, k.KeyType, k.Algorithm)
	}
}

func (k Key) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	modulus := new(big.Int).SetBytes(n)
	if modulus.BitLen() < minRSABits {
		return nil, fmt.Errorf("%d-bit modulus, want at least %d bits", modulus.BitLen(), minRSABits)
	}
	exponent := new(big.Int).SetBytes(e)
	if exponent.Cmp(big.NewInt(3)) < 0 || exponent.Cmp(big.NewInt(maxRSAExponent)) > 0 || exponent.Bit(0) == 0 {
		return nil, errors.New("exponent must be odd and between 3 and 2^31-1")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func (k Key) ecPublicKey() (*ecdsa.PublicKey, error) {
	if k.Curve != "P-256" {
		return nil, fmt.Errorf("curve %q, want P-256", k.Curve)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}
	if len(x) != p256CoordinateSize || len(y) != p256CoordinateSize {
		return nil, fmt.Errorf("coordinates are %d and %d bytes, want %d", len(x), len(y), p256CoordinateSize)
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("parsing point: %w", err)
	}
	return pub, nil
}
