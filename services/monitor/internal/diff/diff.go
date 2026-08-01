// Package diff is the M4 diff engine (doc 03 §7): pure, independently
// testable functions that turn a (previous, current) snapshot pair into
// typed, severity-classified change candidates per doc 03 §7.2. No I/O, no
// clock (Now is injected), no bus — the executor owns persistence and
// emission.
package diff

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/normalize"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// Severity / confidence wire values (doc 03 §7.5).
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"

	ConfConfirmed = "confirmed"
	ConfProbable  = "probable"
	ConfPossible  = "possible"
)

// Followup is an advisory commander-replanning hint (doc 03 §5.1).
type Followup struct {
	Capability string
	Reason     string
}

// Change is one typed change candidate. Silent changes update the snapshot
// store but emit no event (doc 03 §7.2 sub-threshold rule — prevents
// dynamic-content alert fatigue).
type Change struct {
	Type       string
	Severity   string
	Confidence string
	Summary    string
	DiffKind   string
	Before     map[string]any
	After      map[string]any
	// DiffKey discriminates same-type diffs on one asset (e.g. record_type,
	// rule_id); feeds the 24 h fingerprint (doc 03 §5.1).
	DiffKey   string
	RuleID    string
	Followups []Followup
	Silent    bool
}

// Options parameterizes classification.
type Options struct {
	// Now drives expiry computations (doc 03 §12: ±5 min leeway applied by
	// the probe already; diff compares whole days).
	Now time.Time
	// Criticality of the asset (doc 03 §7.2: large content swings are high
	// only on critical assets).
	Criticality string
	// Passive marks passive-feed-derived observations (R0 mode): diffs are
	// emitted at confidence probable (doc 03 §5.3) until an authorized probe
	// confirms.
	Passive bool
}

// Snapshots diffs one (prev, curr) pair of the same probe type. prev may be
// nil (first observation — no change events; the snapshot is simply stored).
func Snapshots(prev, curr *snapshot.Document, opts Options) []Change {
	if curr == nil || prev == nil || curr.Status != snapshot.StatusOK {
		return nil
	}
	var out []Change
	switch curr.ProbeType {
	case snapshot.ProbeDNS:
		out = DNS(prev.Data.DNS, curr.Data.DNS, opts)
	case snapshot.ProbeTLS:
		out = TLS(prev.Data.TLS, curr.Data.TLS, opts)
	case snapshot.ProbeHTTP:
		out = HTTP(prev.Data.HTTP, curr.Data.HTTP, opts)
	case snapshot.ProbeTCPPort:
		out = TCP(prev.Data.TCP, curr.Data.TCP, opts)
	}
	for i := range out {
		if opts.Passive && out[i].Confidence == ConfConfirmed {
			out[i].Confidence = ConfProbable
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// DNS (doc 03 §7.2)
// ---------------------------------------------------------------------------

// DNS diffs normalized DNS observations. Quorum confidence flows from the
// probe: 3-of-3 or 2-of-3-with-timeout → confirmed; active disagreement →
// possible (doc 03 §6.3/§12).
func DNS(prev, curr *snapshot.DNSData, opts Options) []Change {
	if prev == nil || curr == nil {
		return nil
	}
	conf := ConfConfirmed
	if curr.Quorum.Agreeing < curr.Quorum.Resolvers && len(curr.Quorum.Disagreed) > 0 {
		conf = ConfPossible
	}
	var out []Change

	// Per-type record-set diffs. NS is its own change_type and always ≥ high.
	types := map[string]bool{}
	for t := range prev.Records {
		types[t] = true
	}
	for t := range curr.Records {
		types[t] = true
	}
	sortedTypes := make([]string, 0, len(types))
	for t := range types {
		sortedTypes = append(sortedTypes, t)
	}
	sort.Strings(sortedTypes)

	for _, rt := range sortedTypes {
		added, removed := setDiff(prev.Records[rt], curr.Records[rt])
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		before := map[string]any{"record_type": rt, "records": prev.Records[rt]}
		after := map[string]any{"record_type": rt, "records": curr.Records[rt],
			"added": added, "removed": removed}
		switch {
		case rt == "NS":
			out = append(out, Change{
				Type: "dns.ns_changed", Severity: SevHigh, Confidence: conf,
				Summary:  fmt.Sprintf("nameserver set changed: +%d -%d", len(added), len(removed)),
				DiffKind: "dns_records", Before: before, After: after, DiffKey: "NS",
				Followups: []Followup{{Capability: "detect.scan",
					Reason: "NS change may indicate domain transfer or hijack"}},
			})
		case len(prev.Records[rt]) == 0:
			out = append(out, Change{
				Type: "dns.new_records", Severity: SevInfo, Confidence: conf,
				Summary:  fmt.Sprintf("new %s records appeared: %s", rt, strings.Join(added, ", ")),
				DiffKind: "dns_records", Before: before, After: after, DiffKey: rt,
			})
		default:
			sev := SevLow
			if len(curr.Records[rt]) == 0 {
				sev = SevMedium // record type vanished entirely
			}
			out = append(out, Change{
				Type: "dns.records_changed", Severity: sev, Confidence: conf,
				Summary:  fmt.Sprintf("%s records changed: +%d -%d", rt, len(added), len(removed)),
				DiffKind: "dns_records", Before: before, After: after, DiffKey: rt,
			})
		}
	}

	// Dangling CNAME (doc 03 §7.2): critical + alertable when the target
	// matches a known takeable service; medium otherwise.
	if d := curr.Dangling; d != nil {
		sev, summary := SevMedium, fmt.Sprintf("CNAME target %s is dangling (%s)", d.Target, d.Reason)
		var fu []Followup
		if d.TakeableService != "" {
			sev = SevCritical
			summary = fmt.Sprintf("dangling CNAME %s points at takeable service %s — subdomain takeover risk",
				d.Target, d.TakeableService)
			fu = append(fu, Followup{Capability: "detect.scan",
				Reason: "subdomain takeover: register or remove the dangling record"})
		}
		out = append(out, Change{
			Type: "dns.dangling_cname", Severity: sev, Confidence: conf,
			Summary: summary, DiffKind: "dns_dangling_cname",
			Before: map[string]any{"cname_chain": prev.CNAMEChain},
			After: map[string]any{"target": d.Target, "takeable_service": d.TakeableService,
				"reason": d.Reason},
			DiffKey: "cname:" + d.Target, RuleID: "", Followups: fu,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// TLS (doc 03 §7.2) — single-probe facts (expiry) are 1-shot confirmed.
// ---------------------------------------------------------------------------

// TLSVersionRank orders protocol versions for downgrade detection.
func TLSVersionRank(v string) int {
	switch v {
	case "1.3":
		return 4
	case "1.2":
		return 3
	case "1.1":
		return 2
	case "1.0":
		return 1
	default:
		return 0
	}
}

// TLS diffs normalized TLS observations.
func TLS(prev, curr *snapshot.TLSData, opts Options) []Change {
	if prev == nil || curr == nil {
		return nil
	}
	var out []Change

	// Leaf replacement (doc 03 §7.2): same CA + validity continuity → info;
	// CA change or self-signed appearing → high.
	if prev.Leaf.FingerprintSHA256 != curr.Leaf.FingerprintSHA256 {
		sev := SevInfo
		why := "same issuer, validity continuity"
		sameCA := prev.Leaf.Issuer == curr.Leaf.Issuer
		continuity := curr.Leaf.NotBefore <= prev.Leaf.NotAfter
		switch {
		case curr.Leaf.SelfSigned && !prev.Leaf.SelfSigned:
			sev, why = SevHigh, "certificate became self-signed"
		case !sameCA:
			sev, why = SevHigh, "issuing CA changed"
		case !continuity:
			sev, why = SevLow, "validity gap between old and new certificate"
		}
		out = append(out, Change{
			Type: "tls.cert_changed", Severity: sev, Confidence: ConfConfirmed,
			Summary:  fmt.Sprintf("TLS certificate replaced (%s)", why),
			DiffKind: "tls_cert",
			Before: map[string]any{"not_after": prev.Leaf.NotAfter,
				"fingerprint_sha256": prev.Leaf.FingerprintSHA256, "issuer": prev.Leaf.Issuer},
			After: map[string]any{"not_after": curr.Leaf.NotAfter,
				"fingerprint_sha256": curr.Leaf.FingerprintSHA256, "issuer": curr.Leaf.Issuer},
			DiffKey: "leaf",
		})
	}

	// Expiry facts (1-shot; doc 03 §7.1). Alertable only at expired (§5.3).
	switch {
	case curr.DaysToExpiry <= 0 && prev.DaysToExpiry > 0:
		out = append(out, Change{
			Type: "tls.cert_expired", Severity: SevHigh, Confidence: ConfConfirmed,
			Summary:   "TLS certificate has expired",
			DiffKind:  "tls_cert",
			Before:    map[string]any{"not_after": prev.Leaf.NotAfter},
			After:     map[string]any{"not_after": curr.Leaf.NotAfter, "days_to_expiry": strconv.Itoa(curr.DaysToExpiry)},
			DiffKey:   "expired",
			Followups: []Followup{{Capability: "detect.scan", Reason: "expired certificate — clients see warnings; verify renewal automation"}},
		})
	case curr.DaysToExpiry <= 14 && prev.DaysToExpiry > 14:
		sev := SevMedium
		if curr.DaysToExpiry <= 7 {
			sev = SevHigh
		}
		out = append(out, Change{
			Type: "tls.cert_expiring", Severity: sev, Confidence: ConfConfirmed,
			Summary: fmt.Sprintf("TLS certificate expires in %d days (was %d)",
				curr.DaysToExpiry, prev.DaysToExpiry),
			DiffKind: "tls_cert",
			Before:   map[string]any{"not_after": prev.Leaf.NotAfter},
			After:    map[string]any{"not_after": curr.Leaf.NotAfter, "days_to_expiry": strconv.Itoa(curr.DaysToExpiry)},
			DiffKey:  "expiring",
		})
	}

	// Negotiated protocol weakened.
	if TLSVersionRank(curr.Negotiated.Version) < TLSVersionRank(prev.Negotiated.Version) {
		sev := SevMedium
		if TLSVersionRank(curr.Negotiated.Version) <= 2 {
			sev = SevHigh // ≤ TLS 1.1 negotiated (EXP-005 territory)
		}
		out = append(out, Change{
			Type: "tls.protocol_downgrade", Severity: sev, Confidence: ConfConfirmed,
			Summary: fmt.Sprintf("negotiated TLS version weakened %s → %s",
				prev.Negotiated.Version, curr.Negotiated.Version),
			DiffKind: "tls_negotiated",
			Before:   map[string]any{"version": prev.Negotiated.Version, "cipher": prev.Negotiated.Cipher},
			After:    map[string]any{"version": curr.Negotiated.Version, "cipher": curr.Negotiated.Cipher},
			DiffKey:  "version",
		})
	}

	// Hostname match flapping to false.
	if prev.HostnameMatch && !curr.HostnameMatch {
		out = append(out, Change{
			Type: "tls.hostname_mismatch", Severity: SevHigh, Confidence: ConfConfirmed,
			Summary:  "presented certificate no longer matches the host",
			DiffKind: "tls_cert",
			Before:   map[string]any{"sans": prev.Leaf.SANs, "hostname_match": "true"},
			After:    map[string]any{"sans": curr.Leaf.SANs, "hostname_match": "false"},
			DiffKey:  "hostname",
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP (doc 03 §7.2)
// ---------------------------------------------------------------------------

// securityHeaders is the tracked security-relevant header set for
// http.headers_changed (server + the browser security headers).
var securityHeaders = []string{
	"server", "strict-transport-security", "content-security-policy",
	"x-frame-options", "x-content-type-options", "referrer-policy",
	"permissions-policy", "cross-origin-opener-policy",
}

// parkedMarkers identify parked/held pages (doc 03 §7.2 status-class
// transition "any→parked/held page signature").
var parkedMarkers = []string{
	"domain parked", "parked free", "this domain is for sale", "buy this domain",
	"parkingcrew", "sedoparking", "godaddy", "hugedomains", "afternic",
}

// StatusClass buckets HTTP statuses for class-transition diffing.
func StatusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	case status > 0:
		return "1xx"
	default:
		return "none"
	}
}

func parkedSignature(title string, body []byte) bool {
	hay := strings.ToLower(title)
	for _, m := range parkedMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// HTTP diffs normalized HTTP observations.
func HTTP(prev, curr *snapshot.HTTPData, opts Options) []Change {
	if prev == nil || curr == nil {
		return nil
	}
	var out []Change

	// Status class transitions (200→200 never emits).
	prevClass, currClass := StatusClass(prev.Status), StatusClass(curr.Status)
	prevParked := parkedSignature(prev.Title, nil)
	currParked := parkedSignature(curr.Title, nil)
	if prevClass != currClass || prevParked != currParked {
		sev := SevLow
		switch {
		case currParked && !prevParked:
			sev = SevMedium
		case currClass == "5xx" && prevClass == "2xx":
			sev = SevHigh
		case currClass == "4xx" && prevClass == "2xx":
			sev = SevMedium
		case currClass == "2xx":
			sev = SevLow // recovery
		default:
			sev = SevLow
		}
		summary := fmt.Sprintf("HTTP status class changed %s → %s (%d → %d)",
			prevClass, currClass, prev.Status, curr.Status)
		if currParked && !prevParked {
			summary = fmt.Sprintf("page now shows a parked/held signature (status %d)", curr.Status)
		}
		out = append(out, Change{
			Type: "http.status_changed", Severity: sev, Confidence: ConfConfirmed,
			Summary: summary, DiffKind: "http_status",
			Before:  map[string]any{"status": strconv.Itoa(prev.Status), "class": prevClass},
			After:   map[string]any{"status": strconv.Itoa(curr.Status), "class": currClass, "parked": strconv.FormatBool(currParked)},
			DiffKey: "status",
		})
	}

	// Title.
	if prev.Title != curr.Title && prevClass == "2xx" && currClass == "2xx" {
		out = append(out, Change{
			Type: "http.title_changed", Severity: SevLow, Confidence: ConfConfirmed,
			Summary: "page title changed", DiffKind: "http_title",
			Before:  map[string]any{"title": prev.Title},
			After:   map[string]any{"title": curr.Title},
			DiffKey: "title",
		})
	}

	// Content (SimHash hamming / size delta; sub-threshold stays silent,
	// doc 03 §7.2 — prevents dynamic-content alert fatigue).
	if prev.BodySimHash != "" && curr.BodySimHash != "" && prev.BodySimHash != curr.BodySimHash {
		dist := simhashDistance(prev.BodySimHash, curr.BodySimHash)
		sizeDelta := 0.0
		if prev.BodySize > 0 {
			sizeDelta = float64(abs(curr.BodySize-prev.BodySize)) / float64(prev.BodySize)
		}
		sev := ""
		switch {
		case dist > 24:
			sev = SevMedium
			if isCritical(opts.Criticality) {
				sev = SevHigh
			}
		case dist > 12 || sizeDelta > 0.40:
			sev = SevMedium
		}
		change := Change{
			Type: "http.content_changed", Confidence: ConfConfirmed,
			Summary: fmt.Sprintf("page content changed (simhash distance %d, size delta %.0f%%)",
				dist, sizeDelta*100),
			DiffKind: "http_content",
			Before:   map[string]any{"body_simhash": prev.BodySimHash, "body_size": strconv.Itoa(prev.BodySize)},
			After:    map[string]any{"body_simhash": curr.BodySimHash, "body_size": strconv.Itoa(curr.BodySize)},
			DiffKey:  "content",
		}
		if sev == "" {
			change.Silent = true
			change.Severity = SevInfo
		} else {
			change.Severity = sev
		}
		out = append(out, change)
	}

	// Headers: added/removed keys and security-set value changes emit; other
	// value churn stays silent (dynamic-content fatigue rule).
	{
		var addedKeys, removedKeys, changedSec []string
		for k, v := range curr.HeadersCanonical {
			pv, ok := prev.HeadersCanonical[k]
			if !ok {
				addedKeys = append(addedKeys, k)
			} else if pv != v && isSecurityHeader(k) {
				changedSec = append(changedSec, k)
			}
		}
		for k := range prev.HeadersCanonical {
			if _, ok := curr.HeadersCanonical[k]; !ok {
				removedKeys = append(removedKeys, k)
			}
		}
		sort.Strings(addedKeys)
		sort.Strings(removedKeys)
		sort.Strings(changedSec)
		if len(addedKeys)+len(removedKeys)+len(changedSec) > 0 {
			out = append(out, Change{
				Type: "http.headers_changed", Severity: SevLow, Confidence: ConfConfirmed,
				Summary: fmt.Sprintf("HTTP headers changed (+%d -%d ~%d security)",
					len(addedKeys), len(removedKeys), len(changedSec)),
				DiffKind: "http_headers",
				Before:   map[string]any{"removed": removedKeys},
				After:    map[string]any{"added": addedKeys, "security_changed": changedSec},
				DiffKey:  "headers",
			})
		}
	}

	// Technology set.
	addedTech, removedTech := techDiff(prev.Tech, curr.Tech)
	if len(addedTech) > 0 {
		out = append(out, Change{
			Type: "http.tech_added", Severity: SevLow, Confidence: ConfConfirmed,
			Summary:  "technology detected: " + strings.Join(addedTech, ", "),
			DiffKind: "http_tech",
			Before:   map[string]any{"tech": techNames(prev.Tech)},
			After:    map[string]any{"tech": techNames(curr.Tech), "added": addedTech},
			DiffKey:  "tech_added:" + strings.Join(addedTech, ","),
		})
	}
	if len(removedTech) > 0 {
		out = append(out, Change{
			Type: "http.tech_removed", Severity: SevInfo, Confidence: ConfConfirmed,
			Summary:  "technology no longer detected: " + strings.Join(removedTech, ", "),
			DiffKind: "http_tech",
			Before:   map[string]any{"tech": techNames(prev.Tech)},
			After:    map[string]any{"tech": techNames(curr.Tech), "removed": removedTech},
			DiffKey:  "tech_removed:" + strings.Join(removedTech, ","),
		})
	}

	// Redirect target.
	prevTgt, currTgt := redirectTarget(prev), redirectTarget(curr)
	if prevTgt != currTgt {
		out = append(out, Change{
			Type: "http.redirect_target_changed", Severity: SevMedium, Confidence: ConfConfirmed,
			Summary:  fmt.Sprintf("redirect destination changed %s → %s", prevTgt, currTgt),
			DiffKind: "http_redirect",
			Before:   map[string]any{"final_url": prev.FinalURL, "chain": prev.RedirectChain},
			After:    map[string]any{"final_url": curr.FinalURL, "chain": curr.RedirectChain},
			DiffKey:  "redirect",
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// TCP (Later producer; diff complete for the change_type enum, doc 03 §7.2)
// ---------------------------------------------------------------------------

// portClasses map admin/db ports to their severity class (doc 03 §7.2).
var adminPorts = map[int]bool{22: true, 3389: true, 5900: true}
var dbPorts = map[int]bool{3306: true, 5432: true, 27017: true, 6379: true}

// TCP diffs tri-state port observations against the previous expectation.
func TCP(prev, curr *snapshot.TCPData, opts Options) []Change {
	if prev == nil || curr == nil {
		return nil
	}
	prevState := map[int]string{}
	for _, p := range prev.Ports {
		prevState[p.Port] = p.State
	}
	var out []Change
	for _, p := range curr.Ports {
		was, ok := prevState[p.Port]
		if !ok || was == p.State {
			continue
		}
		switch {
		case p.State == "open" && was != "open":
			sev := SevMedium
			cls := "standard"
			if adminPorts[p.Port] {
				sev, cls = SevHigh, "admin"
			} else if dbPorts[p.Port] {
				sev, cls = SevHigh, "db"
			}
			out = append(out, Change{
				Type: "port.opened", Severity: sev, Confidence: ConfConfirmed,
				Summary:  fmt.Sprintf("port %d opened (class %s, was %s)", p.Port, cls, was),
				DiffKind: "port_state",
				Before:   map[string]any{"port": strconv.Itoa(p.Port), "state": was},
				After:    map[string]any{"port": strconv.Itoa(p.Port), "state": p.State, "class": cls},
				DiffKey:  "port:" + strconv.Itoa(p.Port),
				Followups: []Followup{{Capability: "detect.scan",
					Reason: "new open port — validate exposed service"}},
			})
		case p.State != "open" && was == "open":
			out = append(out, Change{
				Type: "port.closed", Severity: SevLow, Confidence: ConfConfirmed,
				Summary:  fmt.Sprintf("port %d closed (now %s)", p.Port, p.State),
				DiffKind: "port_state",
				Before:   map[string]any{"port": strconv.Itoa(p.Port), "state": was},
				After:    map[string]any{"port": strconv.Itoa(p.Port), "state": p.State},
				DiffKey:  "port:" + strconv.Itoa(p.Port),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func setDiff(prev, curr []string) (added, removed []string) {
	p := map[string]bool{}
	for _, v := range prev {
		p[v] = true
	}
	c := map[string]bool{}
	for _, v := range curr {
		c[v] = true
		if !p[v] {
			added = append(added, v)
		}
	}
	for _, v := range prev {
		if !c[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func simhashDistance(a, b string) int {
	av, err1 := strconv.ParseUint(a, 16, 64)
	bv, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil {
		return 64
	}
	return normalize.HammingDistance(av, bv)
}

func isSecurityHeader(k string) bool {
	for _, s := range securityHeaders {
		if s == k {
			return true
		}
	}
	return false
}

func techNames(ts []snapshot.Tech) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		if t.Version != "" {
			out = append(out, t.Name+"/"+t.Version)
		} else {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

func techDiff(prev, curr []snapshot.Tech) (added, removed []string) {
	return setDiff(techNames(prev), techNames(curr))
}

func redirectTarget(d *snapshot.HTTPData) string {
	if len(d.RedirectChain) == 0 {
		return ""
	}
	return d.FinalURL
}

func isCritical(c string) bool { return c == "high" || c == "critical" }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
