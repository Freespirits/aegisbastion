// Package normalize is the Detect Normalizer/Dedup (doc 04 §7.2, D8):
// adapter RawResults become findings with a deterministic dedup fingerprint,
// duplicates merge within a run (occurrences++), and cross-run dedup consults
// the known-fingerprints view (09 query API; the local cache at MVP).
//
//	fingerprint = sha256( scope_key | normalized_target | port/scheme |
//	                      normalized_path | vuln_identity )
//
// where vuln_identity = CVE when present else source:template_id, and
// normalized_path collapses ID/nonce segments (per-route templating rules).
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// VulnIdentity renders the dedup identity of a candidate: the CVE when known,
// else source:template_id (doc 04 §7.2).
func VulnIdentity(r scanner.RawResult) string {
	if r.CVE != "" {
		return strings.ToUpper(r.CVE)
	}
	return r.Adapter + ":" + r.CheckID
}

// Fingerprint computes the doc 04 §7.2 dedup key ("sha256:<hex>").
func Fingerprint(scopeKey, target, matchedAt, vulnIdentity string) string {
	scheme, host, port, path := splitTarget(target, matchedAt)
	h := sha256.New()
	for _, part := range []string{
		strings.ToLower(strings.TrimSpace(scopeKey)),
		strings.ToLower(host),
		scheme + "/" + port,
		NormalizePath(path),
		strings.ToLower(strings.TrimSpace(vulnIdentity)),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// splitTarget reduces (target, matchedAt) to canonical scheme/host/port/path
// fingerprint components. matchedAt wins when it carries a concrete URL or
// host:port; target is the fallback base.
func splitTarget(target, matchedAt string) (scheme, host, port, path string) {
	raw := strings.TrimSpace(matchedAt)
	if raw == "" {
		raw = strings.TrimSpace(target)
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		scheme = strings.ToLower(u.Scheme)
		host = strings.ToLower(u.Hostname())
		port = u.Port()
		path = u.Path
	} else {
		// host[:port][/path] or "1.2.3.4:443/tcp" (nmap form).
		s := raw
		if i := strings.IndexAny(s, "/"); i >= 0 {
			path = s[i:]
			s = s[:i]
		}
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
		} else {
			host = s
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
	}
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	if path == "" {
		path = "/"
	}
	return scheme, host, port, path
}

var (
	// numericSeg collapses pure-ID segments ("/users/123" → "/users/{id}").
	numericSeg = regexp.MustCompile(`^\d{2,}$`)
	// hexSeg collapses long hex/uuid-ish nonce segments.
	hexSeg = regexp.MustCompile(`(?i)^[0-9a-f]{8,}(-[0-9a-f]{4,})*$`)
	// ulidSeg collapses ULID/token-shaped segments.
	ulidSeg = regexp.MustCompile(`(?i)^[0-9a-z]{16,}$`)
)

// NormalizePath applies the per-route templating rules (doc 04 §7.2):
// ID/nonce path segments collapse so re-scans of different object URLs dedup
// onto one finding.
func NormalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case numericSeg.MatchString(s):
			segs[i] = "{id}"
		case hexSeg.MatchString(s):
			segs[i] = "{hex}"
		case ulidSeg.MatchString(s) && strings.IndexAny(s, ".-_") < 0:
			segs[i] = "{tok}"
		}
	}
	out := strings.Join(segs, "/")
	if len(out) > 1 {
		out = strings.TrimSuffix(out, "/")
	}
	return out
}

// KnownView is the cross-run known-fingerprints view (doc 04 §4.3: the 09
// query API in production; the local cache at MVP).
type KnownView interface {
	// Lookup returns the known finding for a fingerprint (found=false when
	// this is a first sighting).
	Lookup(fingerprint string) (findingID string, occurrences uint64, found bool, err error)
	// Record merges one sighting (insert or last_seen/occurrences update).
	Record(fingerprint, findingID string) error
}

// Dedup merges occurrences within one task run and consults the KnownView for
// cross-run dedup (doc 04 §7.2). Safe for concurrent use.
type Dedup struct {
	mu   sync.Mutex
	seen map[string]*Entry
	view KnownView // nil → run-local dedup only
}

// Entry is one deduped fingerprint within the run.
type Entry struct {
	Fingerprint string
	FindingID   string // carries the cross-run finding id when already known
	Occurrences uint64
	Known       bool // seen in a prior run (update last_seen, don't respam)
}

// NewDedup builds a run deduper over the (optional) cross-run view.
func NewDedup(view KnownView) *Dedup {
	return &Dedup{seen: map[string]*Entry{}, view: view}
}

// Merge registers one candidate sighting. It returns the entry for the
// fingerprint and whether this candidate is a duplicate already merged in
// this run (the caller publishes only when dup=false; doc 04 §12: findings
// already published are not re-published — idempotent on fingerprint).
func (d *Dedup) Merge(fingerprint, newFindingID string) (entry *Entry, dup bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.seen[fingerprint]; ok {
		e.Occurrences++
		return e, true, nil
	}
	e := &Entry{Fingerprint: fingerprint, FindingID: newFindingID, Occurrences: 1}
	if d.view != nil {
		id, occ, found, verr := d.view.Lookup(fingerprint)
		if verr != nil {
			return nil, false, fmt.Errorf("normalize: known-fingerprint lookup: %w", verr)
		}
		if found {
			e.FindingID = id
			e.Occurrences = occ + 1
			e.Known = true
		}
		if rerr := d.view.Record(fingerprint, e.FindingID); rerr != nil {
			return nil, false, fmt.Errorf("normalize: known-fingerprint record: %w", rerr)
		}
	}
	d.seen[fingerprint] = e
	return e, false, nil
}

// Len reports how many distinct fingerprints the run produced.
func (d *Dedup) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
