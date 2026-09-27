package base

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// Command is the base command.
type Command struct {
	// Endpoint specifies the network endpoint for MidPoint API access.
	Endpoint string `short:"E" long:"endpoint" description:"The network endpoint for MidPoint API access." required:"true" env:"MIDPOINT_ENDPOINT"`
	// Username specifies the username for authentication.
	Username string `short:"U" long:"username" description:"The username for authentication." required:"true" env:"MIDPOINT_USERNAME"`
	// Password specifies the password for authentication.
	Password string `short:"P" long:"password" description:"The password for authentication." required:"true" env:"MIDPOINT_PASSWORD"`
	// Impersonate specifies the principal to use for impersonation in API calls.
	Impersonate *string `short:"I" long:"impersonate" description:"The principal to use for impersonation in API calls." optional:"true" env:"MIDPOINT_IMPERSONATE"`
	// Format specifies the output format.
	//lint:ignore SA5008 duplicate alias tags are legitimate
	Format string `short:"F" long:"format" description:"The format of the output." optional:"true" default:"yaml" choice:"text" choice:"json" choice:"yaml" choice:"none" env:"MIDPOINT_FORMAT"`
	// Debug enables debug mode.
	Debug bool `short:"D" long:"debug" description:"Enable debug mode." optional:"true" env:"MIDPOINT_DEBUG"`
	// Enable saving response to file.
	ResponseSavePath *string `long:"save-response-to-file" description:"Enable saving HTTP responses to the given file." optional:"true" env:"MIDPOINT_RESPONSE_SAVE_TO_FILE"`
}

func (cmd *Command) Write(stream io.Writer, object any) error {
	switch cmd.Format {
	case "yaml":
		data, err := yaml.Marshal(object)
		if err != nil {
			return err
		}
		fmt.Fprintf(stream, "%s", string(data))
	case "json":
		data, err := json.Marshal(
			object,
			json.OmitZeroStructFields(true),
			jsontext.WithIndent("  "),
		)
		if err != nil {
			return err
		}
		fmt.Fprintf(stream, "%s\n", string(data))
	case "text":
		fmt.Fprintf(stream, "%v\n", object)
	default:
		return nil
	}
	return nil
}
