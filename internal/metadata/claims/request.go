// Package claims turns an authorized Nova DynamicJSON vendordata request into
// the claim set of an openstack_iid token.
package claims

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"
)

// ErrInvalidRequest is returned (wrapped) when a Nova request is not
// acceptable for token issuance.
var ErrInvalidRequest = errors.New("invalid nova vendordata request")

const (
	maxProjectIDLength = 64
	maxHostnameLength  = 255
)

var (
	// canonical, lowercase UUID form as produced by Nova; alternative forms
	// (braces, URN prefix, uppercase) are rejected so that the same instance
	// can never appear under two different "sub" values.
	instanceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	projectIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

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

// Validate checks that the request carries everything needed to issue a token.
func (r NovaRequest) Validate() error {
	switch {
	case r.ProjectID == "":
		return fmt.Errorf("%w: missing project-id", ErrInvalidRequest)
	case len(r.ProjectID) > maxProjectIDLength:
		return fmt.Errorf("%w: project-id longer than %d characters", ErrInvalidRequest, maxProjectIDLength)
	case !projectIDPattern.MatchString(r.ProjectID):
		return fmt.Errorf("%w: project-id contains invalid characters", ErrInvalidRequest)
	case r.InstanceID == "":
		return fmt.Errorf("%w: missing instance-id", ErrInvalidRequest)
	case !instanceIDPattern.MatchString(r.InstanceID):
		return fmt.Errorf("%w: instance-id is not a canonical lowercase UUID", ErrInvalidRequest)
	case r.Hostname == "":
		return fmt.Errorf("%w: missing hostname", ErrInvalidRequest)
	case len(r.Hostname) > maxHostnameLength:
		return fmt.Errorf("%w: hostname longer than %d characters", ErrInvalidRequest, maxHostnameLength)
	case hasControlCharacters(r.Hostname):
		return fmt.Errorf("%w: hostname contains control characters", ErrInvalidRequest)
	}
	return nil
}

func hasControlCharacters(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
