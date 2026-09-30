package auth

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// userIDPattern matches the user IDs Keystone generates: 32 hex digits (SQL
// backend) or 64 (IDs mapped from LDAP or federated identities).
var userIDPattern = regexp.MustCompile(`^([0-9a-f]{32}|[0-9a-f]{64})$`)

// AllowedUser is an entry of keystone.allowed_users: either a user ID, or a
// user name qualified by its domain (name or ID), since names are only
// unique within a domain.
type AllowedUser struct {
	// ID is the user ID; empty for name@domain entries.
	ID string
	// Name is the user name; empty for ID entries.
	Name string
	// Domain is the name or ID of the user's domain; empty for ID entries.
	Domain string
}

// ParseAllowedUser parses an allowlist entry: a Keystone user ID (32 or 64
// lowercase hex digits) or name@domain, split at the last '@' so that names
// may contain one. A bare name is rejected: it would match a user of that
// name in any domain.
func ParseAllowedUser(entry string) (AllowedUser, error) {
	if strings.TrimSpace(entry) != entry || strings.IndexFunc(entry, unicode.IsControl) >= 0 {
		return AllowedUser{}, fmt.Errorf("%q contains leading/trailing spaces or control characters", entry)
	}
	if i := strings.LastIndex(entry, "@"); i >= 0 {
		name, domain := entry[:i], entry[i+1:]
		if name == "" || domain == "" {
			return AllowedUser{}, fmt.Errorf("%q must have the form name@domain, with both parts non-empty", entry)
		}
		return AllowedUser{Name: name, Domain: domain}, nil
	}
	if !userIDPattern.MatchString(entry) {
		return AllowedUser{}, fmt.Errorf("%q is neither a user ID (32 or 64 lowercase hex digits) nor name@domain; user names are only unique within a domain, so qualify them (e.g. %s@Default)", entry, entry)
	}
	return AllowedUser{ID: entry}, nil
}

// Matches reports whether the identity is this user: same ID, or same name
// in a domain whose name or ID is Domain.
func (u AllowedUser) Matches(id Identity) bool {
	if u.ID != "" {
		return id.UserID == u.ID
	}
	return id.UserName == u.Name && (id.DomainName == u.Domain || id.DomainID == u.Domain)
}

// String returns the entry in its configuration form.
func (u AllowedUser) String() string {
	if u.ID != "" {
		return u.ID
	}
	return u.Name + "@" + u.Domain
}
