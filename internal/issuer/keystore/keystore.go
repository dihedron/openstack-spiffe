// Package keystore manages the keys used to sign openstack_iid tokens. The
// KeyStore interface hides where the private keys live: the ephemeral backend
// keeps them in this process's memory, a Vault transit backend will keep them
// in Vault. Private key material never leaves a KeyStore: callers ask it to
// sign digests and read the public halves.
package keystore

import (
	"context"
	"crypto"
	"errors"
)

var (
	// ErrNoActiveKey is returned (wrapped) while no key is active yet, i.e.
	// until the first key has been published for the publish-ahead period.
	ErrNoActiveKey = errors.New("no active signing key")
	// ErrKeyNotActive is returned (wrapped) by Sign when the requested key is
	// unknown, not active yet or already retired. A caller racing a rotation
	// may get it for a kid Active returned a moment earlier, and should retry
	// with the kid Active returns now.
	ErrKeyNotActive = errors.New("signing key is not active")
)

// KeyInfo identifies a signing key.
type KeyInfo struct {
	// ID is the key's kid.
	ID string
	// Algorithm is the JWS algorithm the key signs with (RS256 or ES256).
	Algorithm string
}

// PublicKey is the public half of a signing key, as published in the JWKS.
type PublicKey struct {
	// ID is the key's kid.
	ID string
	// Algorithm is the JWS algorithm the key signs with (RS256 or ES256).
	Algorithm string
	// Key is the public key: *rsa.PublicKey or *ecdsa.PublicKey.
	Key crypto.PublicKey
}

// KeyStore holds the signing keys of one signer replica.
type KeyStore interface {
	// Active returns the key new tokens must be signed with; it fails with
	// ErrNoActiveKey until one is active.
	Active(ctx context.Context) (KeyInfo, error)
	// Sign signs a SHA-256 digest with the given key, which must be active,
	// and returns the signature in JWS encoding (RSASSA-PKCS1-v1_5 for RS256,
	// the 64-byte R || S concatenation for ES256).
	Sign(ctx context.Context, kid string, digest []byte) ([]byte, error)
	// PublicKeys returns the public halves of every key a verifier may need:
	// the one about to become active (published ahead), the active one and
	// those retired within the retention window, oldest first.
	PublicKeys(ctx context.Context) ([]PublicKey, error)
	// Check reports whether the store can sign right now; it backs the
	// readiness probe and fails until the first key has been published for
	// the publish-ahead period.
	Check(ctx context.Context) error
}
