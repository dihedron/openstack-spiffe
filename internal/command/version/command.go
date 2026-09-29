package version

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/dihedron/openstack-spiffe/pkg/metadata"
	"github.com/joho/godotenv"
)

// Version is the command that prints information about the application
// or plugin to the console; it supports both compact and verbose mode.
type Version struct {
	// Verbose is the flag that indicates whether to print verbose information about the application.
	Verbose bool `short:"v" long:"verbose" description:"Print verbose information about the application."`
	// DotEnv is the optional path to the .env file.
	DotEnv *string `short:"D" long:"dotenv" description:"The path to the .env file." optional:"true" env:"OPENSTACK_SPIFFE_DOTENV"`
}

// Execute is the real implementation of the Version command.
func (cmd *Version) Execute(args []string) error {
	slog.Debug("running version command")
	if cmd.Verbose {
		metadata.PrintFull(os.Stdout)
		if cmd.DotEnv != nil {
			if err := godotenv.Load(*cmd.DotEnv); err != nil {
				slog.Error("error loading .env file", "error", err)
			}
			slog.Info("successfully loaded .env file", "path", *cmd.DotEnv)
			fmt.Printf("  - Environment               :\n")
			for _, env := range os.Environ() {
				if strings.HasPrefix(env, "OPENSTACK_SPIFFE_") {
					fmt.Printf("    - %s\n", env)
				}
			}
		}
	} else {
		metadata.Print(os.Stdout)
	}
	slog.Debug("command done")
	return nil
}
