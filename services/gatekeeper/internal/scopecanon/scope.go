// Package scopecanon implements doc 01 §10.1's canonicalized target matching:
// targets are canonicalized (URL → host, lowercased, port/trailing-dot
// stripped, IPs normalized) and matched against scope entries using
// longest-prefix/exact-host semantics; explicit exclusions ALWAYS WIN over
// every include form (docs 01 §5.4, 03 §9.2, 11 §3.1 agree).
package scopecanon

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Canonical normalizes a target string to its canonical host/IP/CIDR form:
//   - URLs ("https://shop.acme.com/path") reduce to their host
//   - "host:port" reduces to host
//   - case is folded, trailing dots stripped
//   - IPs are normalized via netip (203.0.113.010 -> 203.0.113.10 is NOT
//     accepted — non-canonical IPs are rejected by netip, which is the
//     fail-closed behavior we want)
//
// Returns the canonical form and true, or ("", false) when the target cannot
// be canonicalized (empty, unparseable).
func Canonical(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", false
	}
	// URL form: scheme://host[:port][/path…]
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil || u.Host == "" {
			return "", false
		}
		t = u.Host
	}
	// Strip userinfo if present (user@host).
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	// Strip port (host:port, [v6]:port).
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.TrimPrefix(t, "[")
	t = strings.TrimSuffix(t, "]")
	t = strings.ToLower(strings.TrimSuffix(t, "."))
	if t == "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(t); err == nil {
		return ip.String(), true
	}
	// Wildcard entries (scope side) are kept verbatim but canonicalized.
	if strings.HasPrefix(t, "*.") {
		rest := strings.TrimPrefix(t, "*.")
		if rest == "" || strings.ContainsAny(rest, " /") {
			return "", false
		}
		return "*." + rest, true
	}
	if strings.ContainsAny(t, " /") {
		// CIDR form (only valid on scope entries, but canonicalize here too).
		if p, err := netip.ParsePrefix(t); err == nil {
			return p.Masked().String(), true
		}
		return "", false
	}
	return t, true
}

// MatchEntry reports whether canonical target t matches a single canonical
// scope entry (domain, wildcard domain, host, IP, or CIDR).
// Semantics (doc 01 §10.1 longest-prefix/exact-host):
//   - "acme.com"   matches exactly host "acme.com"
//   - "*.acme.com" matches "acme.com" and every subdomain (longest suffix on
//     dot boundaries)
//   - "203.0.113.0/24" matches any contained IP
//   - "203.0.113.10" matches that exact IP (or host string)
func MatchEntry(scopeEntry, target string) bool {
	se, ok := Canonical(scopeEntry)
	if !ok {
		return false
	}
	tt, ok := Canonical(target)
	if !ok {
		return false
	}
	return matchCanonical(se, tt)
}

func matchCanonical(scopeEntry, target string) bool {
	// CIDR entry: only IPs match.
	if p, err := netip.ParsePrefix(scopeEntry); err == nil {
		ip, err := netip.ParseAddr(target)
		return err == nil && p.Contains(ip)
	}
	// Wildcard domain: apex + subdomains, dot-boundary only.
	if strings.HasPrefix(scopeEntry, "*.") {
		apex := strings.TrimPrefix(scopeEntry, "*.")
		return target == apex || strings.HasSuffix(target, "."+apex)
	}
	// Exact host/IP match.
	return scopeEntry == target
}

// Evaluate checks canonical target t against a scope's includes and excludes.
// Exclusions are evaluated FIRST and always win (Ruling A.5 / doc 01 §5.4).
// Returns (inScope, excluded).
func Evaluate(includes, excludes []string, target string) (inScope bool, excluded bool) {
	tt, ok := Canonical(target)
	if !ok {
		return false, false
	}
	for _, ex := range excludes {
		if matchCanonical(mustCanon(ex), tt) {
			return false, true
		}
	}
	for _, in := range includes {
		if matchCanonical(mustCanon(in), tt) {
			return true, false
		}
	}
	return false, false
}

func mustCanon(s string) string {
	c, _ := Canonical(s)
	return c
}
