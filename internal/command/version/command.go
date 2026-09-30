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
			} else {
				slog.Info("successfully loaded .env file", "path", *cmd.DotEnv)
			}
			fmt.Printf("  - Environment               :\n")
			for _, env := range os.Environ() {
				if line, ok := relevantEnv(env); ok {
					fmt.Printf("    - %s\n", line)
				}
			}
		}
	} else {
		metadata.Print(os.Stdout)
	}
	slog.Debug("command done")
	return nil
}

// relevantEnv reports whether an environment entry concerns the application
// (OPENSTACK_* settings and OS_* OpenStack credentials) and returns it for
// printing, with the values of secrets masked.
func relevantEnv(env string) (string, bool) {
	name, _, _ := strings.Cut(env, "=")
	if !strings.HasPrefix(name, "OPENSTACK_") && !strings.HasPrefix(name, "OS_") {
		return "", false
	}
	for _, secret := range []string{"PASSWORD", "SECRET", "TOKEN", "PASSCODE"} {
		if strings.Contains(name, secret) {
			return name + "=********", true
		}
	}
	return env, true
}
