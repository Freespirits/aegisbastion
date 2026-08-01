package scope

import (
	"net/netip"
	"strings"
)

// Scope is the canonical RoE target scope (doc 11 §3.1 as resolved by
// roe-service; the JSON form is schemas/gatekeeper/v1/scope-manifest.schema.json).
// ExplicitExcludes ALWAYS WIN over every include form.
type Scope struct {
	// Domains — exact hosts and wildcards ("acme.com", "*.acme.com").
	Domains []string `json:"domains"`
	// CIDRs — netblocks ("203.0.113.0/24").
	CIDRs []string `json:"cidrs"`
	// CloudAccounts — cloud account/subscription ids (not probe targets;
	// carried for completeness, they never match a network target).
	CloudAccounts []string `json:"cloud_accounts,omitempty"`
	// AssetGroupIDs — data-platform asset groups (resolved by gatekeeper;
	// never matched syntactically by the SDK).
	AssetGroupIDs []string `json:"asset_group_ids,omitempty"`
	// ExplicitExcludes — hard exclusions (hosts, IPs, CIDRs); always win.
	ExplicitExcludes []string `json:"explicit_excludes"`
}

// Decision is the outcome of evaluating one canonicalized target against a
// scope. Allowed=false is a hard deny — callers must not contact the target.
type Decision struct {
	// Allowed is true only when an include matched AND no exclusion matched.
	Allowed bool
	// Excluded is true when an exclusion entry matched (takes precedence).
	Excluded bool
	// Rule is the scope entry that decided the outcome.
	Rule string
	// Reason is a human/machine explanation for audit payloads.
	Reason string
}

// Evaluate checks target against the scope using doc 01 §10.1 canonicalized
// matching. Fail-closed: a nil scope, an unparseable target, or no matching
// include all deny.
func (s *Scope) Evaluate(target string) Decision {
	if s == nil {
		return Decision{Reason: "no scope to evaluate against (fail-closed)"}
	}
	t, err := Canonicalize(target)
	if err != nil {
		return Decision{Reason: "target not canonicalizable: " + err.Error()}
	}

	// Exclusions FIRST — they always win (doc 01 §5.4/§10.1, doc 03 §9.2,
	// doc 11 §3.1).
	best := -1
	var rule string
	for _, ex := range s.ExplicitExcludes {
		if ok, specificity := matchEntry(ex, t); ok && specificity > best {
			best = specificity
			rule = ex
		}
	}
	if best >= 0 {
		return Decision{
			Excluded: true,
			Rule:     rule,
			Reason:   "target matched explicit_excludes entry " + rule + " (exclusions always win)",
		}
	}

	best = -1
	rule = ""
	for _, dom := range s.Domains {
		if ok, specificity := matchEntry(dom, t); ok && specificity > best {
			best = specificity
			rule = dom
		}
	}
	for _, c := range s.CIDRs {
		if ok, specificity := matchEntry(c, t); ok && specificity > best {
			best = specificity
			rule = c
		}
	}
	if best < 0 {
		return Decision{Reason: "target not in scope (no include matched)"}
	}
	return Decision{Allowed: true, Rule: rule, Reason: "target in scope via " + rule}
}

// matchEntry matches one scope entry against a canonicalized target and
// returns (matched, specificity) — specificity lets the caller pick the
// longest-prefix / most exact deciding rule. Entry forms:
//   - "*.suffix"  → any host strictly under suffix
//   - CIDR        → IP targets contained in it (specificity = prefix bits);
//     CIDR targets fully contained in it
//   - IP literal  → exact IP equality (specificity = 129, above any CIDR)
//   - host        → exact-host equality (specificity = 128+len)
func matchEntry(entry string, t Target) (bool, int) {
	e := strings.TrimSpace(entry)
	if e == "" {
		return false, -1
	}

	if rest, ok := strings.CutPrefix(e, "*."); ok {
		suffix := strings.TrimSuffix(strings.ToLower(rest), ".")
		if t.Host != "" && t.Host != suffix && strings.HasSuffix(t.Host, "."+suffix) {
			return true, 64 + len(suffix)
		}
		return false, -1
	}

	if p, err := netip.ParsePrefix(e); err == nil {
		p = p.Masked()
		if t.Kind == KindCIDR {
			if p.Bits() <= t.Prefix.Bits() && p.Contains(t.Prefix.Addr()) {
				return true, p.Bits()
			}
			return false, -1
		}
		if t.IP.IsValid() && p.Contains(t.IP) {
			return true, p.Bits()
		}
		return false, -1
	}

	if ip, err := netip.ParseAddr(e); err == nil {
		if t.IP.IsValid() && t.IP == ip {
			return true, 129
		}
		return false, -1
	}

	host := strings.TrimSuffix(strings.ToLower(e), ".")
	if t.Host != "" && t.Host == host {
		return true, 128 + len(host)
	}
	return false, -1
}
