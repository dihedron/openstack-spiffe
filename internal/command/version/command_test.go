package version

import "testing"

func TestRelevantEnv(t *testing.T) {
	tests := []struct {
		env, want string
		ok        bool
	}{
		{"OS_AUTH_URL=https://keystone:5000/v3", "OS_AUTH_URL=https://keystone:5000/v3", true},
		{"OS_PASSWORD=hunter2", "OS_PASSWORD=********", true},
		{"OS_APPLICATION_CREDENTIAL_SECRET=s3cr3t", "OS_APPLICATION_CREDENTIAL_SECRET=********", true},
		{"OPENSTACK_SPIRE_METADATA_LOG_LEVEL=debug", "OPENSTACK_SPIRE_METADATA_LOG_LEVEL=debug", true},
		{"HOME=/root", "", false},
		{"MIDPOINT_PASSWORD=x", "", false},
	}
	for _, tt := range tests {
		got, ok := relevantEnv(tt.env)
		if got != tt.want || ok != tt.ok {
			t.Errorf("relevantEnv(%q) = %q, %v; want %q, %v", tt.env, got, ok, tt.want, tt.ok)
		}
	}
}
