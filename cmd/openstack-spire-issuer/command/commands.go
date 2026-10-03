package command

import (
	"github.com/dihedron/openstack-spiffe/cmd/openstack-spire-issuer/command/config"
	"github.com/dihedron/openstack-spiffe/cmd/openstack-spire-issuer/command/jwks"
	"github.com/dihedron/openstack-spiffe/cmd/openstack-spire-issuer/command/service"
	"github.com/dihedron/openstack-spiffe/internal/command/version"
)

// Commands is the set of root command groups.
type Commands struct {
	// Config operates on the signer and aggregator configuration files.
	Config config.Config `command:"config" alias:"cfg" description:"Operate on configuration files."`
	// JWKS runs the JWKS aggregator.
	JWKS jwks.JWKS `command:"jwks" description:"Run the JWKS aggregator."`
	// Service runs the OpenStack metadata signer.
	Service service.Service `command:"service" alias:"svc" description:"Run the OpenStack metadata signer."`
	// Version prints the program version information.
	Version version.Version `command:"version" alias:"v" description:"Print program version information."`
}
