// Package scope implements the platform's canonicalized scope matching
// (doc 01 §10.1: longest-prefix/exact-host; exclusions ALWAYS win — docs 01
// §5.4, 03 §9.2, 11 §3.1 agree). It is the shared library called out in doc 01
// §15 step 3: the dispatch path uses it for plan validation, and the platform
// agent SDK reuses the same code for per-request scope evaluation of
// scope-bound watch tokens (Ruling A).
//
// Matching rules (fail-closed: anything not matched is OUT of scope):
//
//   - Targets are canonicalized first (lowercase, scheme/port/path stripped,
//     trailing dot stripped) — "HTTPS://API.acme.com:8443/x" → "api.acme.com".
//   - Include domain "d"          matches host == d (exact host).
//   - Include wildcard "*.d"      matches proper subdomains of d (longest
//     suffix match); it does NOT match the apex d itself.
//   - Include CIDR "w.x.y.z/n"    matches IP targets inside the network.
//   - An include entry that is a literal IP matches that exact IP.
//   - Exclusion entries match hosts exactly, subdomains of an excluded host,
//     IPs literally, and IPs inside excluded CIDRs. Exclusions are evaluated
//     BEFORE includes and always win.
package scope

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Verdict is the result of checking one target against a scope.
type Verdict int

const (
	// OutOfScope — no include matched (fail-closed default).
	OutOfScope Verdict = iota
	// InScope — an include matched and no exclusion did.
	InScope
	// Excluded — an exclusion matched; always wins over includes.
	Excluded
)

func (v Verdict) String() string {
	switch v {
	case InScope:
		return "IN_SCOPE"
	case Excluded:
		return "EXCLUDED"
	default:
		return "OUT_OF_SCOPE"
	}
}

// Scope is an RoE target scope (doc 11 §3.1 Scope: domains, cidrs,
// explicit_excludes). Asset groups / cloud accounts are resolved by
// gatekeeper before evaluation and are not part of this matcher.
type Scope struct {
	// Domains — include entries: exact hosts, "*.suffix" wildcards, or
	// literal IPs.
	Domains []string
	// CIDRs — include networks.
	CIDRs []string
	// Excludes — hosts, IPs, or CIDRs; always win (doc 01 §5.4).
	Excludes []string
}

// Canonicalize normalizes a target string for matching: lowercase, scheme
// and path stripped (URL form), port stripped, trailing dot stripped.
// Returns the empty string for unparseable input (which never matches —
// fail-closed).
func Canonicalize(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	// URL form: strip scheme, path, query, fragment, userinfo, port.
	if i := strings.Index(t, "://"); i >= 0 {
		rest := t[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if k := strings.LastIndex(rest, "@"); k >= 0 {
			rest = rest[k+1:]
		}
		t = rest
	} else {
		// Host[:port] with a path but no scheme (e.g. "api.acme.com/path").
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
	}
	// Strip port (both "host:port" and "[v6]:port"); tolerate bare IPv6.
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.TrimPrefix(strings.TrimSuffix(t, "]"), "[")
	t = strings.TrimSuffix(strings.ToLower(t), ".")
	return t
}

// hostMatches reports whether canonical host h matches one domain entry:
// "*.d" matches proper subdomains of d; "d" matches exactly h == d.
func hostMatches(entry, h string) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if strings.HasPrefix(entry, "*.") {
		suffix := entry[2:]
		return strings.HasSuffix(h, "."+suffix)
	}
	return h == entry
}

// hostOrSubMatches reports whether h equals entry or is a subdomain of it.
// Used for exclusions (excluding a host also excludes everything under it —
// the safe direction when "exclusions always win").
func hostOrSubMatches(entry, h string) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	entry = strings.TrimPrefix(entry, "*.")
	return h == entry || strings.HasSuffix(h, "."+entry)
}

func parseCIDR(s string) (netip.Prefix, error) {
	return netip.ParsePrefix(strings.TrimSpace(s))
}

// Check evaluates one target against the scope. Exclusions are checked
// first and always win.
func (s *Scope) Check(target string) Verdict {
	h := Canonicalize(target)
	if h == "" {
		return OutOfScope
	}
	ip, ipErr := netip.ParseAddr(h)

	// --- exclusions first; they always win ---
	for _, ex := range s.Excludes {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		if strings.Contains(ex, "/") {
			if p, err := parseCIDR(ex); err == nil && ipErr == nil && p.Contains(ip) {
				return Excluded
			}
			continue
		}
		if exIP, err := netip.ParseAddr(ex); err == nil {
			if ipErr == nil && exIP == ip {
				return Excluded
			}
			continue
		}
		if ipErr != nil && hostOrSubMatches(ex, h) {
			return Excluded
		}
	}

	// --- includes ---
	for _, d := range s.Domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if dIP, err := netip.ParseAddr(d); err == nil {
			if ipErr == nil && dIP == ip {
				return InScope
			}
			continue
		}
		if ipErr != nil && hostMatches(d, h) {
			return InScope
		}
	}
	if ipErr == nil {
		for _, c := range s.CIDRs {
			if p, err := parseCIDR(c); err == nil && p.Contains(ip) {
				return InScope
			}
		}
	}
	return OutOfScope
}

// CheckAll evaluates every target; it returns the first non-InScope verdict
// with the offending target, or nil when all targets are in scope.
func (s *Scope) CheckAll(targets []string) error {
	for _, t := range targets {
		switch v := s.Check(t); v {
		case Excluded:
			return fmt.Errorf("target %q excluded by RoE (exclusions always win)", t)
		case OutOfScope:
			return fmt.Errorf("target %q outside RoE scope", t)
		}
	}
	return nil
}

// MatchCapabilityPattern matches a capability name against an RoE
// allowed_capabilities entry: "stress.*" matches any capability with the
// "stress." prefix; anything else must match exactly (doc 11 §3.1).
func MatchCapabilityPattern(pattern, name string) bool {
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	}
	return pattern == name
}
