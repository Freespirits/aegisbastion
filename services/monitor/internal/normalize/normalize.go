// Package normalize implements the normalization rules of doc 03 §6.3 — the
// transformations that make consecutive observations comparable: canonical
// headers (volatile values dropped), body tokenization + SimHash-64, PII
// redaction before raw upload (doc 03 §9.5), and the module-owned technology
// fingerprint ruleset v1.
package normalize

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"html"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Headers (doc 03 §6.3): lowercase keys; drop volatile values; sort.
// ---------------------------------------------------------------------------

// volatileHeaders are never stored (doc 03 §6.3 volatile list; doc 03 §9.5:
// set-cookie and authorization/cookie values never stored).
var volatileHeaders = map[string]bool{
	"date": true, "expires": true, "set-cookie": true, "x-request-id": true,
	"cf-ray": true, "cookie": true, "authorization": true,
	"x-amz-date": true, "x-amz-request-id": true, "x-amz-id-2": true,
}

// CanonicalHeaders lowercases header keys, drops volatile/per-request values,
// and returns a deterministic map (JSON objects serialize sorted under JCS).
func CanonicalHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if drop, ok := volatileHeaders[lk]; ok && drop {
			continue
		}
		if strings.HasPrefix(lk, "x-amz-") {
			continue // x-amz-* timestamps (doc 03 §6.3)
		}
		vals := make([]string, 0, len(vs))
		for _, v := range vs {
			vals = append(vals, strings.TrimSpace(v))
		}
		sort.Strings(vals)
		out[lk] = strings.Join(vals, ", ")
	}
	return out
}

// ---------------------------------------------------------------------------
// Body normalization + SimHash-64 (doc 03 §6.3, §10 "Content similarity").
// ---------------------------------------------------------------------------

// stripPatterns remove CSRF nonces/tokens and analytics beacons before
// tokenization (default configurable regex list, doc 03 §6.3).
var stripPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)nonce="[^"]*"`),
	regexp.MustCompile(`(?i)nonce='[^']*'`),
	regexp.MustCompile(`(?i)name="csrf[^"]*"\s+content="[^"]*"`),
	regexp.MustCompile(`(?i)name="_?csrf[^"]*"\s+value="[^"]*"`),
	regexp.MustCompile(`(?i)__VIEWSTATE[^>]*value="[^"]*"`),
	regexp.MustCompile(`(?i)(utm_[a-z]+|_ga|_gid|fbclid|gclid)=[A-Za-z0-9._-]+`),
	regexp.MustCompile(`(?i)<script[^>]*(?:google-analytics|googletagmanager|gtag)[^>]*>.*?</script>`),
}

var (
	scriptStyleRe = regexp.MustCompile(`(?is)<(script|style|noscript)[^>]*>.*?</(script|style|noscript)>`)
	tagRe         = regexp.MustCompile(`(?s)<[^>]+>`)
	tokenRe       = regexp.MustCompile(`[a-z0-9]{2,}`)
	spaceRe       = regexp.MustCompile(`\s+`)
)

// TokenizeBody reduces an HTML body to normalized comparison tokens: strip
// non-content blocks and volatile tokens, drop tags, unescape entities,
// lowercase, split on word boundaries.
func TokenizeBody(body []byte) []string {
	s := string(body)
	for _, re := range stripPatterns {
		s = re.ReplaceAllString(s, " ")
	}
	s = scriptStyleRe.ReplaceAllString(s, " ")
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.ToLower(s)
	toks := tokenRe.FindAllString(s, -1)
	return toks
}

// SimHash64 computes a 64-bit SimHash over tokens (doc 03 §10: cheap, stable
// against reordering, tunable hamming thresholds).
func SimHash64(tokens []string) uint64 {
	var v [64]int32
	for _, tok := range tokens {
		h := fnv.New64a()
		_, _ = h.Write([]byte(tok))
		sum := h.Sum64()
		for i := 0; i < 64; i++ {
			if sum&(1<<uint(i)) != 0 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// SimHashHex renders a SimHash-64 as 16 lowercase hex chars (SnapshotDocument
// body_simhash form).
func SimHashHex(h uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h)
	return fmt.Sprintf("%x", b[:])
}

// HammingDistance counts differing bits between two SimHash-64 values.
func HammingDistance(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		n += int(x & 1)
		x >>= 1
	}
	return n
}

// ---------------------------------------------------------------------------
// PII redaction (doc 03 §9.5): email, card-track, JWT shapes — applied to raw
// bodies BEFORE MinIO upload; hits set pii_classification on alert events.
// ---------------------------------------------------------------------------

// PIIPattern pairs a redaction class with its detector.
type PIIPattern struct {
	Class string
	Re    *regexp.Regexp
}

// DefaultPIIPatterns is the configurable default redaction set.
var DefaultPIIPatterns = []PIIPattern{
	{"pii:email", regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)},
	{"pci:card_track", regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
	{"pii:jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}`)},
}

// RedactPII applies patterns to body, replacing hits with "<redacted:class>"
// and returning the redacted body plus the distinct hit classes (used for
// pii_classification, doc 03 §9.5).
func RedactPII(body []byte, patterns []PIIPattern) ([]byte, []string) {
	if len(patterns) == 0 {
		patterns = DefaultPIIPatterns
	}
	out := body
	seen := map[string]bool{}
	var classes []string
	for _, p := range patterns {
		if p.Re.Match(out) {
			out = p.Re.ReplaceAll(out, []byte("<redacted:"+p.Class+">"))
			if !seen[p.Class] {
				seen[p.Class] = true
				classes = append(classes, p.Class)
			}
		}
	}
	return out, classes
}

// ---------------------------------------------------------------------------
// Technology fingerprint ruleset v1 (module-owned, Wappalyzer-style,
// doc 03 §6.1). Header/marker rules only — no active probing.
// ---------------------------------------------------------------------------

// Tech is one technology fingerprint entry (Wappalyzer-style, module-owned
// ruleset v1). snapshot.Tech mirrors it for the persisted document form.
type Tech struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"` // sure|likely
}

// TechRule detects one technology from headers and/or body markers.
type TechRule struct {
	Name       string
	Header     string // canonical header name to match (empty = body marker)
	Contains   string // case-insensitive substring; empty = presence-only
	VersionRe  *regexp.Regexp
	Confidence string // sure|likely
	BodyMarker string // case-insensitive body substring (used when Header == "")
}

// TechRulesV1 is the shipped module-owned ruleset.
var TechRulesV1 = []TechRule{
	{Name: "nginx", Header: "server", Contains: "nginx", Confidence: "sure"},
	{Name: "apache", Header: "server", Contains: "apache", VersionRe: regexp.MustCompile(`(?i)apache/?([0-9.]+)`), Confidence: "sure"},
	{Name: "iis", Header: "server", Contains: "microsoft-iis", VersionRe: regexp.MustCompile(`(?i)microsoft-iis/?([0-9.]+)`), Confidence: "sure"},
	{Name: "cloudflare", Header: "server", Contains: "cloudflare", Confidence: "sure"},
	{Name: "envoy", Header: "server", Contains: "envoy", Confidence: "sure"},
	{Name: "php", Header: "x-powered-by", Contains: "php", VersionRe: regexp.MustCompile(`(?i)php/?([0-9.]+)`), Confidence: "sure"},
	{Name: "asp.net", Header: "x-powered-by", Contains: "asp.net", Confidence: "sure"},
	{Name: "express", Header: "x-powered-by", Contains: "express", Confidence: "sure"},
	{Name: "next.js", Header: "x-powered-by", Contains: "next.js", Confidence: "sure"},
	{Name: "wordpress", BodyMarker: "wp-content/", Confidence: "likely"},
	{Name: "wordpress", Header: "x-pingback", Confidence: "likely"},
	{Name: "react", BodyMarker: "data-reactroot", Confidence: "likely"},
	{Name: "react", BodyMarker: "__react", Confidence: "likely"},
	{Name: "jquery", BodyMarker: "jquery", Confidence: "likely"},
	{Name: "phpmyadmin", BodyMarker: "phpmyadmin", Confidence: "sure"},
	{Name: "drupal", BodyMarker: "drupal-settings-json", Confidence: "likely"},
	{Name: "kubernetes", Header: "x-kubernetes-pf-flowschema-uid", Confidence: "sure"},
}

// FingerprintTech applies the ruleset to canonical headers + raw body and
// returns the sorted, deduplicated technology list.
func FingerprintTech(headers map[string]string, body []byte) []Tech {
	type key struct{ name, version string }
	found := map[key]Tech{}
	for _, r := range TechRulesV1 {
		var hay string
		if r.Header != "" {
			v, ok := headers[r.Header]
			if !ok {
				continue
			}
			hay = v
			if r.Contains != "" && !strings.Contains(strings.ToLower(hay), r.Contains) {
				continue
			}
		} else {
			if len(body) == 0 || !strings.Contains(strings.ToLower(string(body)), r.BodyMarker) {
				continue
			}
		}
		t := Tech{Name: r.Name, Confidence: r.Confidence}
		if r.VersionRe != nil {
			if m := r.VersionRe.FindStringSubmatch(hay); len(m) > 1 {
				t.Version = m[1]
			}
		}
		k := key{t.Name, t.Version}
		if prev, ok := found[k]; !ok || prev.Confidence != "sure" {
			found[k] = t
		}
	}
	out := make([]Tech, 0, len(found))
	for _, t := range found {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
