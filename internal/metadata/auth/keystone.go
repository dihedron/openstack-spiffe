package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

// KeystoneValidator validates tokens with Keystone (GET /v3/auth/tokens),
// authenticated as the service's own user, which needs the permission to
// validate other users' tokens (by default, the "service" or "admin" role).
type KeystoneValidator struct {
	identity *gophercloud.ServiceClient
}

var _ TokenValidator = (*KeystoneValidator)(nil)

// NewKeystoneValidator creates a validator using the given identity v3
// client (see osclient.Client.Identity).
func NewKeystoneValidator(identity *gophercloud.ServiceClient) (*KeystoneValidator, error) {
	if identity == nil {
		return nil, errors.New("creating Keystone validator: no identity client")
	}
	return &KeystoneValidator{identity: identity}, nil
}

// Validate implements TokenValidator: a token Keystone does not find (404:
// unknown, expired or revoked) is ErrInvalidToken, any other failure
// ErrUnavailable.
func (v *KeystoneValidator) Validate(ctx context.Context, token string) (Identity, error) {
	result := tokens.Get(ctx, v.identity, token)
	if err := result.Err; err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return Identity{}, fmt.Errorf("%w: unknown to Keystone", ErrInvalidToken)
		}
		return Identity{}, fmt.Errorf("%w: validating token with Keystone: %w", ErrUnavailable, err)
	}
	t, err := result.ExtractToken()
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decoding Keystone token: %w", ErrUnavailable, err)
	}
	user, err := result.ExtractUser()
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decoding Keystone token user: %w", ErrUnavailable, err)
	}
	roles, err := result.ExtractRoles()
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decoding Keystone token roles: %w", ErrUnavailable, err)
	}
	identity := Identity{
		UserID:     user.ID,
		UserName:   user.Name,
		DomainID:   user.Domain.ID,
		DomainName: user.Domain.Name,
		ExpiresAt:  t.ExpiresAt,
	}
	for _, role := range roles {
		identity.Roles = append(identity.Roles, role.Name)
	}
	if identity.UserID == "" || identity.ExpiresAt.IsZero() {
		return Identity{}, fmt.Errorf("%w: Keystone token without user ID or expiry", ErrUnavailable)
	}
	return identity, nil
}
