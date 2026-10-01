package auth

import (
	"strings"
	"testing"
)

func TestParseAllowedUser(t *testing.T) {
	tests := []struct {
		in   string
		want AllowedUser
	}{
		{"0123456789abcdef0123456789abcdef", AllowedUser{ID: "0123456789abcdef0123456789abcdef"}},
		{strings.Repeat("ab", 32), AllowedUser{ID: strings.Repeat("ab", 32)}},
		{"nova@Default", AllowedUser{Name: "nova", Domain: "Default"}},
		{"nova@default", AllowedUser{Name: "nova", Domain: "default"}},
		// LDAP names may contain '@': the domain follows the last one
		{"svc-nova@example.com@ldap", AllowedUser{Name: "svc-nova@example.com", Domain: "ldap"}},
	}
	for _, tt := range tests {
		got, err := ParseAllowedUser(tt.in)
		if err != nil {
			t.Fatalf("ParseAllowedUser(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseAllowedUser(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
		if got.String() != tt.in {
			t.Fatalf("String() = %q, want %q", got.String(), tt.in)
		}
	}
}

func TestParseAllowedUserRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"nova",                             // bare name: ambiguous across domains
		"0123456789ABCDEF0123456789ABCDEF", // IDs are lowercase hex
		"0123456789abcdef",                 // too short for an ID
		"@Default",
		"nova@",
		" nova@Default",
		"nova@Default\n",
	} {
		if got, err := ParseAllowedUser(in); err == nil {
			t.Fatalf("ParseAllowedUser(%q) = %+v, want an error", in, got)
		}
	}
}

func TestAllowedUserMatches(t *testing.T) {
	id := Identity{UserID: novaUserID, UserName: "nova", DomainID: "default", DomainName: "Default"}
	matching := []string{novaUserID, "nova@Default", "nova@default"}
	for _, entry := range matching {
		u, _ := ParseAllowedUser(entry)
		if !u.Matches(id) {
			t.Fatalf("%q does not match %+v", entry, id)
		}
	}
	notMatching := []string{
		"fedcba9876543210fedcba9876543210",
		"nova@Tenants",
		"Nova@Default", // names are compared exactly
		"glance@Default",
	}
	for _, entry := range notMatching {
		u, _ := ParseAllowedUser(entry)
		if u.Matches(id) {
			t.Fatalf("%q matches %+v", entry, id)
		}
	}
	// a user whose name equals an allowlisted ID-less entry's domain ID must
	// not match by accident
	if u, _ := ParseAllowedUser("nova@Default"); u.Matches(Identity{UserID: "x", UserName: "nova"}) {
		t.Fatal("matched a user without a domain")
	}
}
