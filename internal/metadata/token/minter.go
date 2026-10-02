// Package token mints openstack_iid tokens: it turns a Nova request into a
// claim set and signs it as a compact JWS with the key store's active key.
package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dihedron/openstack-spiffe/internal/metadata/claims"
	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// ErrKeyStoreUnavailable is returned (wrapped, together with the key store's
// own error) when no token can be signed because of the key store; the
// transport layer maps it to 503.
var ErrKeyStoreUnavailable = errors.New("key store unavailable")

// ErrTokenTooLarge is returned (wrapped) when a signed token exceeds
// iid.MaxTokenBytes, the most the SPIRE plugins accept; it is never issued.
var ErrTokenTooLarge = errors.New("token too large")

// signAttempts bounds how many times Mint asks for the active key: a second
// attempt covers a rotation landing between Active and Sign.
const signAttempts = 2

// ClaimsBuilder builds the claim set of a token; *claims.Builder implements it.
type ClaimsBuilder interface {
	Build(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (iid.Claims, error)
}

// Minter issues signed openstack_iid tokens. It holds no key material: every
// signature is delegated to the key store. It is safe for concurrent use as
// long as its key store and claims builder are.
type Minter struct {
	keys    keystore.KeyStore
	builder ClaimsBuilder
}

// NewMinter creates a Minter signing with the given key store the claims
// produced by the given builder.
func NewMinter(keys keystore.KeyStore, builder ClaimsBuilder) (*Minter, error) {
	if keys == nil {
		return nil, errors.New("creating minter: no key store")
	}
	if builder == nil {
		return nil, errors.New("creating minter: no claims builder")
	}
	return &Minter{keys: keys, builder: builder}, nil
}

// Mint builds the claims for the request (with the enrichment claims looked
// up for it, if any) and returns them as a compact JWS
// signed with the key store's active key, whose kid is in the header. It
// never returns a token alongside an error: invalid requests fail with
// claims.ErrInvalidRequest, key store failures with ErrKeyStoreUnavailable,
// and a token over iid.MaxTokenBytes with ErrTokenTooLarge.
func (m *Minter) Mint(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (string, error) {
	c, err := m.builder.Build(ctx, req, enrichment)
	if err != nil {
		return "", fmt.Errorf("minting token: %w", err)
	}
	// the builder already checked the custom claims, but enrichment claim
	// names are optional fields the JSON encoder cannot guard against a
	// collision, so check again right before signing
	if err := iid.ValidateCustomClaims(c.Custom); err != nil {
		slog.ErrorContext(ctx, "refusing to sign claims with reserved custom claim names", "project_id", req.ProjectID, "instance_id", req.InstanceID, "error", err)
		return "", fmt.Errorf("minting token: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("minting token: encoding claims: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	for attempt := 1; ; attempt++ {
		token, kid, err := m.sign(ctx, encodedPayload)
		if err == nil && len(token) > iid.MaxTokenBytes {
			// cannot happen with the claims builder's own caps: refuse rather
			// than hand out a token the SPIRE Server would reject
			slog.ErrorContext(ctx, "refusing to issue an oversized token", "project_id", req.ProjectID, "instance_id", req.InstanceID, "kid", kid, "bytes", len(token), "max_bytes", iid.MaxTokenBytes)
			return "", fmt.Errorf("minting token: %w: %d bytes, at most %d allowed", ErrTokenTooLarge, len(token), iid.MaxTokenBytes)
		}
		if err == nil {
			slog.InfoContext(ctx, "token issued", "project_id", req.ProjectID, "instance_id", req.InstanceID, "kid", kid, "jti", c.ID)
			return token, nil
		}
		if errors.Is(err, keystore.ErrKeyNotActive) && attempt < signAttempts {
			slog.DebugContext(ctx, "signing key rotated while signing, retrying", "project_id", req.ProjectID, "instance_id", req.InstanceID, "kid", kid)
			continue
		}
		slog.ErrorContext(ctx, "cannot sign token", "project_id", req.ProjectID, "instance_id", req.InstanceID, "kid", kid, "error", err)
		return "", fmt.Errorf("minting token: %w", err)
	}
}

// sign signs the encoded payload with the currently active key and returns
// the compact JWS and the kid used.
func (m *Minter) sign(ctx context.Context, encodedPayload string) (string, string, error) {
	active, err := m.keys.Active(ctx)
	if err != nil {
		return "", "", fmt.Errorf("%w: getting active key: %w", ErrKeyStoreUnavailable, err)
	}
	// both supported algorithms sign SHA-256 digests
	if active.Algorithm != "RS256" && active.Algorithm != "ES256" {
		return "", active.ID, fmt.Errorf("active key %q has unsupported algorithm %q", active.ID, active.Algorithm)
	}
	header, err := json.Marshal(iid.Header{Algorithm: active.Algorithm, KeyID: active.ID, Type: "JWT"})
	if err != nil {
		return "", active.ID, fmt.Errorf("encoding header: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := m.keys.Sign(ctx, active.ID, digest[:])
	if err != nil {
		return "", active.ID, fmt.Errorf("%w: %w", ErrKeyStoreUnavailable, err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), active.ID, nil
}
