// Package claims turns an authorized Nova DynamicJSON vendordata request into
// the claim set of an openstack_iid token.
package claims

import (
	"errors"
	"fmt"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// ErrInvalidRequest is returned (wrapped) when a Nova request is not
// acceptable for token issuance.
var ErrInvalidRequest = errors.New("invalid nova vendordata request")

// NovaRequest is the body Nova POSTs to a DynamicJSON vendordata target.
// Fields Nova sends that this service does not use (e.g. "user-data",
// "boot-roles") are deliberately not modelled, so they are ignored on decode
// and can never end up in a token or a log line.
type NovaRequest struct {
	// ProjectID is the project that owns the instance.
	ProjectID string `json:"project-id"`
	// InstanceID is the instance UUID.
	InstanceID string `json:"instance-id"`
	// ImageID is the boot image ID; empty for instances booted from volume.
	ImageID string `json:"image-id"`
	// Hostname is the instance hostname.
	Hostname string `json:"hostname"`
	// Metadata holds the user-supplied key/value pairs set at boot time.
	Metadata map[string]any `json:"metadata"`
}

// Validate checks that the request carries everything needed to issue a
// token, applying the field rules of the shared contract (package iid), which
// the SPIRE Server-side plugin applies again to the token's claims.
func (r NovaRequest) Validate() error {
	if err := iid.ValidateProjectID(r.ProjectID); err != nil {
		return fmt.Errorf("%w: project-id: %w", ErrInvalidRequest, err)
	}
	if err := iid.ValidateInstanceID(r.InstanceID); err != nil {
		return fmt.Errorf("%w: instance-id: %w", ErrInvalidRequest, err)
	}
	if err := iid.ValidateHostname(r.Hostname); err != nil {
		return fmt.Errorf("%w: hostname: %w", ErrInvalidRequest, err)
	}
	return nil
}
