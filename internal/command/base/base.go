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
	// Format specifies the output format.
	//lint:ignore SA5008 duplicate alias tags are legitimate
	Format string `short:"F" long:"format" description:"The format of the output." optional:"true" default:"yaml" choice:"text" choice:"json" choice:"yaml" choice:"none" env:"OPENSTACK_SPIFFE_FORMAT"`
	// Debug enables debug mode.
	Debug bool `short:"D" long:"debug" description:"Enable debug mode." optional:"true" env:"OPENSTACK_SPIFFE_DEBUG"`
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
