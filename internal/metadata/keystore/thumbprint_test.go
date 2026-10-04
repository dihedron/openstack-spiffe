package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestThumbprintRFC7638Example(t *testing.T) {
	// RFC 7638, section 3.1
	n, err := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	if err != nil {
		t.Fatal(err)
	}
	key := PublicKey{ID: "2011-04-29", Algorithm: "RS256", Key: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}}
	got, err := Thumbprint(key)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("Thumbprint = %q, want %q", got, want)
	}
}

func TestThumbprintEC(t *testing.T) {
	// a key whose x coordinate has a leading zero byte: RFC 7518 requires
	// the full 32 bytes, so a minimal big-endian encoding would be wrong
	var priv *ecdsa.PrivateKey
	for {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if point, _ := k.PublicKey.Bytes(); point[1] == 0 {
			priv = k
			break
		}
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b64(point[1:33]) + `","y":"` + b64(point[33:]) + `"}`
	sum := sha256.Sum256([]byte(canonical))

	got, err := Thumbprint(PublicKey{ID: "k", Algorithm: "ES256", Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if want := b64(sum[:]); got != want {
		t.Fatalf("Thumbprint = %q, want %q (of %s)", got, want, canonical)
	}
}

func TestThumbprintIgnoresKIDAndAlgorithm(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, errA := Thumbprint(PublicKey{ID: "a", Algorithm: "ES256", Key: &k.PublicKey})
	b, errB := Thumbprint(PublicKey{ID: "b", Algorithm: "ES256", Key: &k.PublicKey})
	if errA != nil || errB != nil || a != b {
		t.Fatalf("thumbprints %q (%v) and %q (%v) differ for the same key", a, errA, b, errB)
	}
}

func TestThumbprintRejectsUnsupportedKeys(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"P-384": &k.PublicKey, "string": "not a key", "nil": nil} {
		if _, err := Thumbprint(PublicKey{ID: "k", Key: key}); err == nil {
			t.Errorf("%s: Thumbprint accepted it", name)
		}
	}
}
