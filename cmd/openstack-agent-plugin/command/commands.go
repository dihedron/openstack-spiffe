package command

import (
	"github.com/dihedron/openstack-spiffe/internal/command/version"
)

// Commands is the set of root command groups.
type Commands struct {
	// Version prints the program version information.
	Version version.Version `command:"version" alias:"v" description:"Print program version information."`
}
