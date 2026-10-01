package config

import (
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		in   string
		want Rate
	}{
		{"1/5s", Rate{Events: 1, Per: 5 * time.Second}},
		{"200/1s", Rate{Events: 200, Per: time.Second}},
		{"10/s", Rate{Events: 10, Per: time.Second}},
		{"3/m", Rate{Events: 3, Per: time.Minute}},
		{" 5 / 2m ", Rate{Events: 5, Per: 2 * time.Minute}},
	}
	for _, tt := range tests {
		got, err := ParseRate(tt.in)
		if err != nil {
			t.Errorf("ParseRate(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseRate(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseRateInvalid(t *testing.T) {
	for _, in := range []string{"", "5", "/5s", "0/5s", "-1/5s", "x/5s", "1/", "1/0s", "1/-5s", "1/fortnight", "1/5s/2"} {
		if got, err := ParseRate(in); err == nil {
			t.Errorf("ParseRate(%q) = %+v, want error", in, got)
		}
	}
}

func TestRateString(t *testing.T) {
	if got := (Rate{Events: 1, Per: 5 * time.Second}).String(); got != "1/5s" {
		t.Errorf("String() = %q, want %q", got, "1/5s")
	}
}

func TestRateUnmarshalYAML(t *testing.T) {
	var v struct {
		R Rate `yaml:"r"`
	}
	if err := yaml.Unmarshal([]byte(`r: "1/5s"`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.R != (Rate{Events: 1, Per: 5 * time.Second}) {
		t.Fatalf("rate = %+v", v.R)
	}
	if err := yaml.Unmarshal([]byte(`r: "bogus"`), &v); err == nil {
		t.Fatalf("expected error for invalid rate")
	}
	if err := yaml.Unmarshal([]byte("r: [1, 2]"), &v); err == nil {
		t.Fatalf("expected error for non-scalar rate")
	}
}
