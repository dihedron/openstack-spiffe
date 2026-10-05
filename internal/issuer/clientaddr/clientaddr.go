// Package clientaddr determines the address of the client behind a request,
// which keys the per-source rate limit and identifies the caller in logs.
// Without trusted proxies it is the TCP peer address; behind trusted reverse
// proxies or load balancers it is read from a forwarding header set by them.
package clientaddr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// DefaultHeader is the forwarding header read when none is configured.
const DefaultHeader = "X-Forwarded-For"

// ParseTrustedProxy parses a trusted proxy entry: an IP address or a CIDR
// range (host bits are masked). IPv4-mapped IPv6 addresses are normalized to
// IPv4; zoned addresses are rejected.
func ParseTrustedProxy(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR range", entry)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is neither an IP address nor a CIDR range", entry)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ValidateHeaderName checks that name is a valid HTTP header name (an RFC
// 9110 token).
func ValidateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name is empty")
	}
	for _, c := range []byte(name) {
		if !isTokenChar(c) {
			return fmt.Errorf("%q is not a valid HTTP header name", name)
		}
	}
	return nil
}

func isTokenChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
	}
}

// Resolver determines client addresses. It is safe for concurrent use.
type Resolver struct {
	proxies []netip.Prefix
	header  string
}

// NewResolver creates a Resolver trusting the given proxies (IP addresses or
// CIDR ranges; none means the service is not proxied) and reading the client
// address from header (empty means DefaultHeader) for requests they relay.
func NewResolver(trustedProxies []string, header string) (*Resolver, error) {
	if header == "" {
		header = DefaultHeader
	}
	if err := ValidateHeaderName(header); err != nil {
		return nil, fmt.Errorf("creating client address resolver: %w", err)
	}
	res := &Resolver{header: http.CanonicalHeaderKey(header)}
	for _, entry := range trustedProxies {
		p, err := ParseTrustedProxy(entry)
		if err != nil {
			return nil, fmt.Errorf("creating client address resolver: trusted proxy %w", err)
		}
		res.proxies = append(res.proxies, p)
	}
	return res, nil
}

// Resolve returns the client address of the request, or an invalid address
// if the TCP peer address cannot be parsed. For a request relayed by a
// trusted proxy, the forwarding header is read as a comma-separated list
// (several headers form one list) from the right, skipping trusted proxies:
// the first other address is the client's. Entries further left were
// supplied by the client and are never looked at. If the header is missing
// or malformed, or holds only trusted proxies, the proxy's own address is
// returned.
func (res *Resolver) Resolve(r *http.Request) netip.Addr {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok || !res.trusted(peer) {
		return peer
	}
	var entries []string
	for _, value := range r.Header.Values(res.header) {
		entries = append(entries, strings.Split(value, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		addr, ok := parseEntry(strings.TrimSpace(entries[i]))
		if !ok {
			slog.DebugContext(r.Context(), "malformed client address header from trusted proxy, using the proxy's address", "proxy", peer, "header", res.header)
			return peer
		}
		if !res.trusted(addr) {
			return addr
		}
	}
	slog.DebugContext(r.Context(), "no client address in header from trusted proxy, using the proxy's address", "proxy", peer, "header", res.header)
	return peer
}

// Middleware resolves the client address of each request once and stores it
// in the request context, where From and String find it.
func (res *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr := res.Resolve(r); addr.IsValid() {
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, addr))
		}
		next.ServeHTTP(w, r)
	})
}

func (res *Resolver) trusted(addr netip.Addr) bool {
	for _, p := range res.proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

type contextKey struct{}

// From returns the client address stored by Middleware or, without it, the
// TCP peer address (the non-proxied behaviour); false if neither is
// available.
func From(r *http.Request) (netip.Addr, bool) {
	if addr, ok := r.Context().Value(contextKey{}).(netip.Addr); ok {
		return addr, true
	}
	return peerAddr(r.RemoteAddr)
}

// String returns the client address as From does, or the raw peer address
// if it cannot be parsed, for logging.
func String(r *http.Request) string {
	if addr, ok := From(r); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

// Peer returns the TCP peer address, which differs from the client address
// when the request came through a trusted proxy.
func Peer(r *http.Request) (netip.Addr, bool) {
	return peerAddr(r.RemoteAddr)
}

func peerAddr(remoteAddr string) (netip.Addr, bool) {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr().Unmap().WithZone(""), true
}

// parseEntry parses a header entry: an IP address, optionally with a port
// (IPv6 then in brackets).
func parseEntry(entry string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(entry)
		if splitErr != nil {
			return netip.Addr{}, false
		}
		if addr, err = netip.ParseAddr(host); err != nil {
			return netip.Addr{}, false
		}
	}
	return addr.Unmap().WithZone(""), true
}
