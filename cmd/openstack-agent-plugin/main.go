package main

import (
	"log/slog"
	"os"

	"github.com/dihedron/openstack-spiffe/cmd/openstack-agent-plugin/command"
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

func main() {
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
