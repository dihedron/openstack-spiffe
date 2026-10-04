package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// p256CoordinateSize is the size of a P-256 coordinate in a JWK (RFC 7518,
// section 6.2.1.2: x and y are padded to the full coordinate size).
const p256CoordinateSize = 32

// Thumbprint returns the RFC 7638 JWK thumbprint of a public key: the
// base64url-encoded SHA-256 of its required JWK members, serialized in
// lexicographic order without whitespace. It depends on the key material
// only, never on the kid or the algorithm, so it identifies the key itself.
func Thumbprint(k PublicKey) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	var canonical string
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		canonical = `{"e":"` + b64(big.NewInt(int64(pub.E)).Bytes()) + `","kty":"RSA","n":"` + b64(pub.N.Bytes()) + `"}`
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return "", fmt.Errorf("thumbprint of key %q: unsupported curve %s", k.ID, pub.Curve.Params().Name)
		}
		point, err := pub.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return "", fmt.Errorf("thumbprint of key %q: %w", k.ID, err)
		}
		x, y := point[1:1+p256CoordinateSize], point[1+p256CoordinateSize:]
		canonical = `{"crv":"P-256","kty":"EC","x":"` + b64(x) + `","y":"` + b64(y) + `"}`
	default:
		return "", fmt.Errorf("thumbprint of key %q: unsupported key type %T", k.ID, k.Key)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:]), nil
}
