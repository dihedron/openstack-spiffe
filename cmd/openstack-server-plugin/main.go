package main

import (
	"log/slog"
	"os"

	"github.com/dihedron/openstack-spiffe/cmd/openstack-server-plugin/command"
	"github.com/dihedron/openstack-spiffe/internal/plugin/server/openstackiid"
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	// SPIRE Server starts the plugin without arguments
	if len(os.Args) == 1 {
		plugin := openstackiid.New()
		pluginmain.Serve(
			nodeattestorv1.NodeAttestorPluginServer(plugin),
			configv1.ConfigServiceServer(plugin),
		)
		return
	}

	defer cleanup()

	err := godotenv.Load()
	if err != nil {
		slog.Warn("error loading .env file", "error", err)
	}

	options := command.Commands{}
	if _, err := flags.NewParser(&options, flags.Default).Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		case *flags.Error:
			//fmt.Fprintf(os.Stderr, "error: %s (%T)\n", err, err)
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}
}
