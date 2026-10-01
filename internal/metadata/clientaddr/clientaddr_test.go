package clientaddr

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newResolver(t *testing.T, proxies []string, header string) *Resolver {
	t.Helper()
	r, err := NewResolver(proxies, header)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func resolve(res *Resolver, remoteAddr string, headers map[string][]string) string {
	r := httptest.NewRequest(http.MethodPost, "/attest", nil)
	r.RemoteAddr = remoteAddr
	for name, values := range headers {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	addr := res.Resolve(r)
	if !addr.IsValid() {
		return "invalid"
	}
	return addr.String()
}

func TestNotProxiedIgnoresHeaders(t *testing.T) {
	res := newResolver(t, nil, "")
	got := resolve(res, "192.0.2.10:40000", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}})
	if got != "192.0.2.10" {
		t.Fatalf("client address %s, want the peer 192.0.2.10 (forged header ignored)", got)
	}
}

func TestUntrustedPeerIgnoresHeaders(t *testing.T) {
	res := newResolver(t, []string{"10.0.10.0/24"}, "")
	got := resolve(res, "192.0.2.10:40000", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}})
	if got != "192.0.2.10" {
		t.Fatalf("client address %s, want the untrusted peer 192.0.2.10", got)
	}
}

func TestTrustedProxy(t *testing.T) {
	res := newResolver(t, []string{"10.0.10.0/24", "10.0.20.5"}, "")
	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{"single address", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}}, "198.51.100.7"},
		{"client-prepended entries ignored", map[string][]string{"X-Forwarded-For": {"203.0.113.66, 198.51.100.7"}}, "198.51.100.7"},
		{"chain of trusted proxies skipped", map[string][]string{"X-Forwarded-For": {"203.0.113.66, 198.51.100.7, 10.0.20.5, 10.0.10.3"}}, "198.51.100.7"},
		{"several headers form one list", map[string][]string{"X-Forwarded-For": {"203.0.113.66", "198.51.100.7, 10.0.20.5"}}, "198.51.100.7"},
		{"spaces around entries", map[string][]string{"X-Forwarded-For": {" 198.51.100.7 ,10.0.20.5"}}, "198.51.100.7"},
		{"entry with port", map[string][]string{"X-Forwarded-For": {"198.51.100.7:4711"}}, "198.51.100.7"},
		{"IPv6 entry", map[string][]string{"X-Forwarded-For": {"2001:db8::7"}}, "2001:db8::7"},
		{"bracketed IPv6 entry with port", map[string][]string{"X-Forwarded-For": {"[2001:db8::7]:4711"}}, "2001:db8::7"},
		{"IPv4-mapped entry", map[string][]string{"X-Forwarded-For": {"::ffff:198.51.100.7"}}, "198.51.100.7"},
		{"missing header", nil, "10.0.10.3"},
		{"empty header", map[string][]string{"X-Forwarded-For": {""}}, "10.0.10.3"},
		{"only trusted proxies", map[string][]string{"X-Forwarded-For": {"10.0.20.5, 10.0.10.9"}}, "10.0.10.3"},
		{"malformed rightmost entry", map[string][]string{"X-Forwarded-For": {"198.51.100.7, unknown"}}, "10.0.10.3"},
		{"empty entry", map[string][]string{"X-Forwarded-For": {"198.51.100.7, "}}, "10.0.10.3"},
		// malformed entries left of the client address are never looked at
		{"malformed entry left of the client", map[string][]string{"X-Forwarded-For": {"garbage, 198.51.100.7"}}, "198.51.100.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(res, "10.0.10.3:40000", tt.headers); got != tt.want {
				t.Fatalf("client address %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCustomHeader(t *testing.T) {
	res := newResolver(t, []string{"10.0.10.0/24"}, "x-real-ip")
	headers := map[string][]string{"X-Real-Ip": {"198.51.100.7"}, "X-Forwarded-For": {"203.0.113.66"}}
	if got := resolve(res, "10.0.10.3:1", headers); got != "198.51.100.7" {
		t.Fatalf("client address %s, want 198.51.100.7 from X-Real-IP", got)
	}
}

func TestTrustedIPv6Proxy(t *testing.T) {
	res := newResolver(t, []string{"2001:db8:10::/48"}, "")
	got := resolve(res, "[2001:db8:10::1]:443", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}})
	if got != "198.51.100.7" {
		t.Fatalf("client address %s, want 198.51.100.7", got)
	}
}

func TestUnparseablePeer(t *testing.T) {
	res := newResolver(t, nil, "")
	if got := resolve(res, "not-an-address", nil); got != "invalid" {
		t.Fatalf("client address %s, want invalid", got)
	}
}

func TestParseTrustedProxy(t *testing.T) {
	valid := map[string]string{
		"10.0.10.0/24":    "10.0.10.0/24",
		"10.0.10.5":       "10.0.10.5/32",
		"2001:db8::/48":   "2001:db8::/48",
		"2001:db8::1":     "2001:db8::1/128",
		"10.0.10.7/24":    "10.0.10.0/24", // host bits masked
		"::ffff:10.0.0.1": "10.0.0.1/32",
		"0.0.0.0/0":       "0.0.0.0/0",
		"::/0":            "::/0",
	}
	for in, want := range valid {
		p, err := ParseTrustedProxy(in)
		if err != nil {
			t.Fatalf("ParseTrustedProxy(%q): %v", in, err)
		}
		if p.String() != want {
			t.Fatalf("ParseTrustedProxy(%q) = %s, want %s", in, p, want)
		}
	}
	for _, in := range []string{"", "proxy.internal", "10.0.10.0/33", "10.0.10.0/", " 10.0.10.5", "fe80::1%eth0"} {
		if _, err := ParseTrustedProxy(in); err == nil {
			t.Fatalf("ParseTrustedProxy(%q) accepted", in)
		}
	}
}

func TestValidateHeaderName(t *testing.T) {
	for _, name := range []string{"X-Forwarded-For", "x-real-ip", "True-Client-IP"} {
		if err := ValidateHeaderName(name); err != nil {
			t.Fatalf("ValidateHeaderName(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", "X Forwarded", "X-Forwarded-For:", "Forwarded\n"} {
		if err := ValidateHeaderName(name); err == nil {
			t.Fatalf("ValidateHeaderName(%q) accepted", name)
		}
	}
}

func TestNewResolverRejectsBadInput(t *testing.T) {
	if _, err := NewResolver([]string{"proxy.internal"}, ""); err == nil {
		t.Fatal("accepted a host name as trusted proxy")
	}
	if _, err := NewResolver(nil, "Bad Header"); err == nil {
		t.Fatal("accepted an invalid header name")
	}
}

func TestMiddlewareStoresTheAddress(t *testing.T) {
	res := newResolver(t, []string{"10.0.10.0/24"}, "")
	var got string
	h := res.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = String(r)
	}))
	r := httptest.NewRequest(http.MethodPost, "/attest", nil)
	r.RemoteAddr = "10.0.10.3:1"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "198.51.100.7" {
		t.Fatalf("String = %q, want 198.51.100.7", got)
	}
}

func TestFromWithoutMiddlewareUsesThePeer(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/attest", nil)
	r.RemoteAddr = "192.0.2.10:40000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	addr, ok := From(r)
	if !ok || addr.String() != "192.0.2.10" {
		t.Fatalf("From = %v, %v; want the peer 192.0.2.10", addr, ok)
	}
	r.RemoteAddr = "garbage"
	if _, ok := From(r); ok {
		t.Fatal("From accepted an unparseable peer")
	}
	if got := String(r); got != "garbage" {
		t.Fatalf("String = %q, want the raw peer", got)
	}
}
