package syslog

import (
	"fmt"
	"strings"
)

// This file holds the parts of RFC 5424 the package needs: facilities,
// severities and the syntax rules of the header fields and structured data.

// Version is the syslog protocol version (RFC 5424, section 6.2.2).
const Version = 1

// Facility is the system component a message comes from (RFC 5424, section
// 6.2.1), with its numerical code as value.
type Facility uint8

// The facilities, by code. FacilityKern is reserved for the kernel and
// refused, so that a zero value cannot slip through unnoticed.
const (
	FacilityKern Facility = iota
	FacilityUser
	FacilityMail
	FacilityDaemon
	FacilityAuth
	FacilitySyslog
	FacilityLPR
	FacilityNews
	FacilityUUCP
	FacilityCron
	FacilityAuthpriv
	FacilityFTP
	FacilityNTP
	FacilityAudit
	FacilityAlert
	FacilityClock
	FacilityLocal0
	FacilityLocal1
	FacilityLocal2
	FacilityLocal3
	FacilityLocal4
	FacilityLocal5
	FacilityLocal6
	FacilityLocal7
)

// Validate checks that f is a facility a process may log with.
func (f Facility) Validate() error {
	switch {
	case f == FacilityKern:
		return fmt.Errorf("facility kern (0) is reserved for the kernel")
	case f > FacilityLocal7:
		return fmt.Errorf("facility %d not recognized", f)
	}
	return nil
}

// Severity is the importance of a message (RFC 5424, section 6.2.1), with
// its numerical code as value: the lower, the more severe.
type Severity uint8

// The severities, by code.
const (
	SeverityEmergency Severity = iota
	SeverityAlert
	SeverityCritical
	SeverityError
	SeverityWarning
	SeverityNotice
	SeverityInformational
	SeverityDebug
)

// Validate checks that s is a known severity.
func (s Severity) Validate() error {
	if s > SeverityDebug {
		return fmt.Errorf("severity %d not recognized", s)
	}
	return nil
}

// priority renders PRI (RFC 5424, section 6.2.1).
func priority(f Facility, s Severity) string {
	return fmt.Sprintf("<%d>", int(f)*8+int(s))
}

// validateHeaderField checks a header field (HOSTNAME, APP-NAME, PROCID,
// MSGID): at most max printable US-ASCII characters, and not the NILVALUE
// "-" itself, which stands for an empty field.
func validateHeaderField(name, value string, max int) error {
	if value == "-" {
		return fmt.Errorf("%s: %q is reserved", name, value)
	}
	return validatePrintASCII(name, value, max)
}

// validateSDName checks an SD-NAME (RFC 5424, section 6.3): 1 to 32
// printable US-ASCII characters other than '=', ' ', ']' and '"'.
func validateSDName(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s: empty", name)
	}
	if i := strings.IndexAny(value, `= ]"`); i >= 0 {
		return fmt.Errorf("%s %q: invalid character %q", name, value, value[i])
	}
	return validatePrintASCII(name, value, 32)
}

// validatePrintASCII checks that value holds at most max characters, all in
// the PRINTUSASCII range (33 to 126).
func validatePrintASCII(name, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s %q: longer than %d characters", name, value, max)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 {
			return fmt.Errorf("%s %q: character %q at position %d is not printable US-ASCII", name, value, value[i], i)
		}
	}
	return nil
}

// nilValue renders an empty header field as the NILVALUE "-".
func nilValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
