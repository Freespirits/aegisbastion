// Package netguard is Discover's module-level egress control (doc 02 §6.3,
// retained per Ruling B.2): a dialer wrapper that hard-blocks
// RFC1918/loopback/link-local/reserved destinations and restricts ports —
// enforced regardless of token contents. Passive/CT workers only ever egress
// to public source APIs over 443 (DNS 53/853 permitted for resolution);
// credentialed-cloud workers egress to provider management endpoints over 443.
//
// The guard is a *worker-side* defense-in-depth layer: it never widens what a
// token allows, it only narrows where packets may go.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// blockedPrefixes are never dialed: loopback, link-local, RFC1918, ULA,
// CGNAT, multicast, unspecified, reserved, benchmarking and documentation
// ranges (doc 02 §6.3 "RFC1918/loopback/link-local/reserved").
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this host"
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT shared space
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (documentation)
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (documentation)
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3 (documentation)
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("fc00::/7"),        // unique local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
}

// Config tunes a Guard. The zero value is the doc 02 §6.3 default:
// HTTP(S)/DNS ports only, every non-public destination blocked.
type Config struct {
	// AllowedPorts — default {53, 853, 80, 443}.
	AllowedPorts []int
	// AllowPrivate — TEST/FIXTURE HOOK ONLY: permits loopback/private
	// destinations (fixture HTTP servers on 127.0.0.1). Never set in
	// deployed workers; connectors run fully offline in fixture mode instead.
	AllowPrivate bool
	// Resolver — DNS resolver for the rebinding check (nil = system).
	Resolver *net.Resolver
}

// Guard is an egress policy enforced at dial time.
type Guard struct {
	ports map[int]bool
	cfg   Config
}

// New builds a Guard.
func New(cfg Config) *Guard {
	g := &Guard{cfg: cfg, ports: map[int]bool{}}
	ports := cfg.AllowedPorts
	if len(ports) == 0 {
		ports = []int{53, 853, 80, 443}
	}
	for _, p := range ports {
		g.ports[p] = true
	}
	return g
}

// Blocked reports whether ip is a hard-blocked destination.
func (g *Guard) Blocked(ip netip.Addr) bool {
	if g.cfg.AllowPrivate {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// PortAllowed reports whether the destination port is in the egress set.
func (g *Guard) PortAllowed(port int) bool { return g.ports[port] }

// CheckAddr validates host:port without dialing: the port must be allowed and
// every resolved IP must be public (DNS-rebinding guard — resolution happens
// here and the same result feeds DialContext).
func (g *Guard) CheckAddr(ctx context.Context, host string, port int) error {
	if !g.PortAllowed(port) {
		return fmt.Errorf("netguard: port %d not in egress allowlist", port)
	}
	return g.checkIPsForHost(ctx, host)
}

func (g *Guard) checkIPsForHost(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if g.Blocked(ip) {
			return fmt.Errorf("netguard: destination %s is blocked (private/loopback/reserved)", ip)
		}
		return nil
	}
	resolver := g.cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a)
		if !ok {
			continue
		}
		if g.Blocked(ip) {
			return fmt.Errorf("netguard: %s resolves to blocked address %s", host, ip)
		}
	}
	return nil
}

// DialContext returns a dial function that enforces the guard at connect
// time (port allowlist + per-IP block, fail-closed).
func (g *Guard) DialContext(base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netguard: %w", err)
		}
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, fmt.Errorf("netguard: bad port in %q", addr)
		}
		if err := g.CheckAddr(ctx, host, port); err != nil {
			return nil, err
		}
		return base.DialContext(ctx, network, addr)
	}
}

// Transport wraps base (or http.DefaultTransport) so every connection it
// dials passes the guard. ResponseHeaderTimeout/idle settings mirror the
// platform default profile for I/O-bound enumeration.
func (g *Guard) Transport(base *http.Transport) *http.Transport {
	if base == nil {
		base = &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	base.DialContext = g.DialContext(nil)
	return base
}

// HTTPClient returns an *http.Client whose egress passes the guard.
func (g *Guard) HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Transport: g.Transport(nil), Timeout: timeout}
}
