// Canonicalization rules for assets (doc 02 §4.2):
//   - Domains: IDNA→punycode, lowercase, trailing dot stripped, leading "*."
//     stripped (wildcard recorded as attribute wildcard:true on the parent).
//   - IPs: normalized via inet semantics (netip); v4/v6 stored as text; never
//     merged across families.
//   - CIDRs: masked network form.
//   - Certs: keyed by SHA-256 of DER (hex).
//   - Cloud resources: keyed by ARN/resource-id, lowercased provider.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalizeDomain normalizes a domain/subdomain per doc 02 §4.2. It
// returns the canonical value and whether the input was a wildcard ("*.x").
// The wildcard marker belongs on the PARENT asset as attributes
// {"wildcard": true} — the returned value never keeps the "*." prefix.
func CanonicalizeDomain(raw string) (value string, wildcard bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false, fmt.Errorf("empty domain")
	}
	if strings.HasPrefix(s, "*.") {
		wildcard = true
		s = strings.TrimPrefix(s, "*.")
	}
	s = strings.TrimSuffix(s, ".")
	// IDNA → punycode (A-label), lowercased.
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", false, fmt.Errorf("idna: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", false, fmt.Errorf("domain %q invalid length", raw)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", false, fmt.Errorf("domain %q has invalid label", raw)
		}
	}
	return ascii, wildcard, nil
}

// IsSubdomainOf reports whether host is strictly under parent (both
// canonical). The apex itself is not a subdomain of itself.
func IsSubdomainOf(host, parent string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))
	return host != parent && strings.HasSuffix(host, "."+parent)
}

// ParentDomain returns the eTLD+1-agnostic parent (drops the leftmost
// label). Used only for depth bookkeeping, not public-suffix logic.
func ParentDomain(host string) string {
	if i := strings.Index(host, "."); i >= 0 && i+1 < len(host) {
		return host[i+1:]
	}
	return host
}

// CanonicalizeIP normalizes an IP literal to its canonical text form
// (doc 02 §4.2 — v4/v6 never merged across families).
func CanonicalizeIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("ip %q: %w", raw, err)
	}
	if ip.Is4In6() {
		ip = ip.Unmap() // canonical v4 text for mapped forms
	}
	return ip.String(), nil
}

// CanonicalizeCIDR normalizes a CIDR to its masked network form.
func CanonicalizeCIDR(raw string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("cidr %q: %w", raw, err)
	}
	return p.Masked().String(), nil
}

// CertKeyFromDER keys a certificate asset by SHA-256 of its DER (doc 02 §4.2).
func CertKeyFromDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// CanonicalizeCloudResource normalizes a cloud resource key (ARN or
// provider-native resource id): trimmed, provider prefix preserved. The
// attributes.cloud.provider field is mandatory (doc 02 §4.2) — enforced by
// the reducer, not here.
func CanonicalizeCloudResource(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty cloud resource id")
	}
	return s, nil
}

// CanonicalizeASN normalizes "AS64500" / "64500" → "AS64500".
func CanonicalizeASN(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "AS")
	if s == "" {
		return "", fmt.Errorf("empty asn")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("asn %q not numeric", raw)
		}
	}
	return "AS" + s, nil
}

// ClassifyDomainAsset decides whether a discovered hostname is the seed apex
// (type domain) or a subdomain of it (type subdomain) — or neither, in which
// case ok=false (the reducer quarantines it).
func ClassifyDomainAsset(host, apex string) (AssetType, bool) {
	if host == apex {
		return AssetDomain, true
	}
	if IsSubdomainOf(host, apex) {
		return AssetSubdomain, true
	}
	return "", false
}
