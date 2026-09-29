package command

import (
	"github.com/dihedron/openstack-spiffe/cmd/openstack-spire-metadata/command/config"
	"github.com/dihedron/openstack-spiffe/internal/command/version"
)

// Commands is the set of root command groups.
type Commands struct {
	// Config operates on the signer and aggregator configuration files.
	Config config.Config `command:"config" alias:"cfg" description:"Operate on configuration files."`
	// Version prints the program version information.
	Version version.Version `command:"version" alias:"v" description:"Print program version information."`
}
