package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// Rate is a rate limit expressed as "<events>/<period>", e.g. "1/5s" (one
// event every five seconds) or "200/s".
type Rate struct {
	// Events is the number of events allowed per period (also the burst).
	Events int
	// Per is the period.
	Per time.Duration
}

// ParseRate parses a "<events>/<period>" string; the period is a Go duration,
// whose leading "1" may be omitted (e.g. "10/s").
func ParseRate(s string) (Rate, error) {
	events, period, ok := strings.Cut(s, "/")
	if !ok {
		return Rate{}, fmt.Errorf("rate %q: want <events>/<period>", s)
	}
	n, err := strconv.Atoi(strings.TrimSpace(events))
	if err != nil || n < 1 {
		return Rate{}, fmt.Errorf("rate %q: events must be a positive integer", s)
	}
	period = strings.TrimSpace(period)
	if period != "" && !unicode.IsDigit(rune(period[0])) {
		period = "1" + period
	}
	per, err := time.ParseDuration(period)
	if err != nil || per <= 0 {
		return Rate{}, fmt.Errorf("rate %q: period must be a positive duration", s)
	}
	return Rate{Events: n, Per: per}, nil
}

// String returns the "<events>/<period>" form of the rate.
func (r Rate) String() string {
	return fmt.Sprintf("%d/%s", r.Events, r.Per)
}

// MarshalText encodes the rate in its "<events>/<period>" form.
func (r Rate) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

// UnmarshalYAML decodes a rate from a YAML scalar. Errors are returned as
// *yaml.TypeError so that the decoder records them and carries on with the
// rest of the document.
func (r *Rate) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: rate must be a string like \"1/5s\"", node.Line)}}
	}
	rate, err := ParseRate(node.Value)
	if err != nil {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: %v", node.Line, err)}}
	}
	*r = rate
	return nil
}
