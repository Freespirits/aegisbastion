// Package scope implements the canonicalized target matching of doc 01 §10.1
// (longest-prefix / exact-host) with the platform's prime directive:
// EXCLUSIONS ALWAYS WIN (doc 01 §5.4, doc 03 §9.2, doc 11 §3.1), and
// fail-closed behavior — a nil/empty scope or an unparseable target is a deny,
// never an allow.
//
// Matching rules (canonicalized targets, doc 01 §10.1):
//   - exact-host: a scope entry "acme.com" matches only the host "acme.com".
//   - wildcard: "*.acme.com" matches any host strictly under acme.com
//     (api.acme.com, a.b.acme.com) but NOT the apex "acme.com" — the RoE
//     examples list both forms explicitly, so wildcard does not imply apex.
//   - longest-prefix (CIDR): an IP target matches any CIDR entry containing it;
//     the most specific (longest-prefix) entry is reported as the deciding
//     rule. A CIDR target matches a CIDR entry when fully contained.
//   - IPs match IP entries exactly.
//   - URL targets are matched on their canonical host (scheme/port/path do not
//     widen or narrow scope).
//   - Hostname targets are matched syntactically; the SDK never resolves DNS
//     to force a CIDR match (schedule-time DNS re-resolution is a module-level
//     control, doc 06, not an SDK behavior).
//
// Exclusion entries use the same matching forms and are evaluated FIRST: any
// exclusion match denies, regardless of includes.
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ErrInvalidTarget marks an unparseable/unsound target string.
var ErrInvalidTarget = errors.New("scope: invalid target")

// Kind classifies a canonicalized target.
type Kind int

const (
	// KindHost is a DNS hostname (possibly from a URL).
	KindHost Kind = iota
	// KindIP is an IP literal.
	KindIP
	// KindURL is a URL; Host carries its canonical host.
	KindURL
	// KindCIDR is a CIDR block (rare as a probe target; matched by containment).
	KindCIDR
)

// Target is the canonical form of a target string (doc 01 §10.1:
// "evaluated against canonicalized targets").
type Target struct {
	// Raw is the input string.
	Raw string
	// Kind classifies the target.
	Kind Kind
	// Host is the canonical host: lowercase, no trailing dot, no port.
	Host string
	// IP is set when the target (or a URL's host) is an IP literal.
	IP netip.Addr
	// Prefix is set for KindCIDR.
	Prefix netip.Prefix
	// Canonical is the normalized comparison string (URL form preserved for
	// URLs; host/IP/CIDR otherwise).
	Canonical string
}

// String returns the canonical comparison form.
func (t Target) String() string { return t.Canonical }

// Canonicalize normalizes a target string:
//   - URLs: scheme and host lowercased, default port (80/443) stripped,
//     userinfo and fragment dropped, trailing dot stripped from host.
//   - IPs: parsed to netip.Addr (canonical rendering).
//   - CIDRs: parsed to netip.Prefix, masked.
//   - hosts: lowercased, trailing dot stripped, port stripped; restricted to
//     DNS-safe characters (fail-closed on anything else).
func Canonicalize(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, fmt.Errorf("%w: empty target", ErrInvalidTarget)
	}
	t := Target{Raw: raw}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return Target{}, fmt.Errorf("%w: unparseable URL %q", ErrInvalidTarget, raw)
		}
		host, err := canonicalHost(u.Host)
		if err != nil {
			return Target{}, err
		}
		t.Kind = KindURL
		t.Host = host
		if ip, err := netip.ParseAddr(host); err == nil {
			t.IP = ip
		}
		scheme := strings.ToLower(u.Scheme)
		port := u.Port()
		def := (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
		var b strings.Builder
		b.WriteString(scheme)
		b.WriteString("://")
		b.WriteString(host)
		if port != "" && !def {
			b.WriteString(":")
			b.WriteString(port)
		}
		if u.Path != "" && u.Path != "/" {
			b.WriteString(u.Path)
		}
		if u.RawQuery != "" {
			b.WriteString("?")
			b.WriteString(u.RawQuery)
		}
		t.Canonical = b.String()
		return t, nil
	}

	if ip, err := netip.ParseAddr(s); err == nil {
		t.Kind = KindIP
		t.IP = ip
		t.Host = ip.String()
		t.Canonical = ip.String()
		return t, nil
	}

	if p, err := netip.ParsePrefix(s); err == nil {
		t.Kind = KindCIDR
		t.Prefix = p.Masked()
		t.Canonical = t.Prefix.String()
		return t, nil
	}

	host, err := canonicalHost(s)
	if err != nil {
		return Target{}, err
	}
	t.Kind = KindHost
	t.Host = host
	if ip, err := netip.ParseAddr(host); err == nil {
		t.Kind = KindIP
		t.IP = ip
		t.Canonical = ip.String()
		return t, nil
	}
	t.Canonical = host
	return t, nil
}

// canonicalHost lowercases, strips a port and trailing dot, and validates the
// host character set (fail-closed).
func canonicalHost(h string) (string, error) {
	if strings.ContainsAny(h, "@/") {
		return "", fmt.Errorf("%w: host %q contains illegal characters", ErrInvalidTarget, h)
	}
	host := h
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		// host:port — SplitHostPort handles "a.b:8443"; bare IPv6 (contains
		// multiple colons) fails there and falls through as a host literal.
		if hh, pp, err := net.SplitHostPort(h); err == nil {
			if n, perr := strconv.Atoi(pp); perr != nil || n < 0 || n > 65535 {
				return "", fmt.Errorf("%w: invalid port in %q", ErrInvalidTarget, h)
			}
			host = hh
		} else if strings.Count(h, ":") == 1 {
			return "", fmt.Errorf("%w: bad host:port %q", ErrInvalidTarget, h)
		}
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidTarget)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host, nil // IP literal (incl. IPv6 without brackets)
	}
	for _, r := range host {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_'
		if !ok {
			return "", fmt.Errorf("%w: host %q has illegal character %q", ErrInvalidTarget, h, r)
		}
	}
	return host, nil
}
