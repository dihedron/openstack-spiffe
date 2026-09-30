package novalookup

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
)

// OpenStack is the Backend reading records from the Nova and Keystone APIs,
// with the service's own credentials.
type OpenStack struct {
	compute  *gophercloud.ServiceClient
	identity *gophercloud.ServiceClient
}

var _ Backend = (*OpenStack)(nil)

// NewOpenStack creates a backend from a compute client (with microversion
// 2.47 or later, see osclient.Client.Compute) and an identity v3 client.
func NewOpenStack(compute, identity *gophercloud.ServiceClient) (*OpenStack, error) {
	if compute == nil || identity == nil {
		return nil, errors.New("creating OpenStack lookup backend: missing compute or identity client")
	}
	return &OpenStack{compute: compute, identity: identity}, nil
}

// serverRecord is the part of a Nova server record the verifier uses;
// gophercloud's servers.Server lacks the availability zone extension.
type serverRecord struct {
	TenantID         string `json:"tenant_id"`
	UserID           string `json:"user_id"`
	Status           string `json:"status"`
	AvailabilityZone string `json:"OS-EXT-AZ:availability_zone"`
	Flavor           struct {
		OriginalName string `json:"original_name"`
	} `json:"flavor"`
}

// Server implements Backend (GET /servers/{id}).
func (o *OpenStack) Server(ctx context.Context, instanceID string) (Server, error) {
	// ExtractInto unwraps the "server" envelope itself
	var s serverRecord
	if err := servers.Get(ctx, o.compute, instanceID).ExtractInto(&s); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return Server{}, fmt.Errorf("server %s: %w", instanceID, ErrNotFound)
		}
		return Server{}, fmt.Errorf("getting server %s from Nova: %w", instanceID, err)
	}
	return Server{
		ProjectID:        s.TenantID,
		UserID:           s.UserID,
		Status:           s.Status,
		AvailabilityZone: s.AvailabilityZone,
		Flavor:           s.Flavor.OriginalName,
	}, nil
}

// Project implements Backend (GET /v3/projects/{id}).
func (o *OpenStack) Project(ctx context.Context, projectID string) (Project, error) {
	p, err := projects.Get(ctx, o.identity, projectID).Extract()
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return Project{}, fmt.Errorf("project %s: %w", projectID, ErrNotFound)
		}
		return Project{}, fmt.Errorf("getting project %s from Keystone: %w", projectID, err)
	}
	return Project{Name: p.Name, DomainID: p.DomainID}, nil
}
