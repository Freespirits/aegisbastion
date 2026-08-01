package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// Exposure ruleset v1 (doc 03 §7.4 — exposure_rules/v1, 25 rules).
//
// Rules are data-driven, versioned definitions evaluated over the asset's
// latest snapshot set; they never scan deeper than snapshots allow — anything
// requiring active validation becomes a suggested_followups entry for Detect
// (attached by the caller, which also owns the CLOSED→OPEN→CLOSED state
// machine in monitor.exposure_state).
// ---------------------------------------------------------------------------

// RuleSetVersion is the shipped ruleset bundle id (doc 03 §7.4).
const RuleSetVersion = "exposure_rules/v1"

// Finding is one exposure rule hit.
type Finding struct {
	RuleID   string
	Severity string
	Title    string
	Detail   string
	Evidence map[string]any
}

// ExposureRule is one rule definition.
type ExposureRule struct {
	ID       string
	Severity string
	Title    string
	// Applies reports the hit; detail/evidence enrich the event.
	Applies func(in *Input) (hit bool, detail string, evidence map[string]any)
}

// ExposureV1 is the versioned v1 bundle (25 rules, doc 03 §7.4).
var ExposureV1 = []ExposureRule{
	{
		ID: "EXP-001", Severity: "critical",
		Title: "dangling CNAME to takeable service",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.DNS == nil || in.DNS.Dangling == nil || in.DNS.Dangling.TakeableService == "" {
				return false, "", nil
			}
			d := in.DNS.Dangling
			return true, fmt.Sprintf("CNAME target %s is dangling and matches takeable service %s — subdomain takeover risk",
				d.Target, d.TakeableService), map[string]any{"target": d.Target, "service": d.TakeableService}
		},
	},
	{
		ID: "EXP-002", Severity: "high",
		Title: "admin/login surface on internet-facing asset",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status < 200 || in.HTTP.Status >= 300 {
				return false, "", nil
			}
			t := strings.ToLower(in.HTTP.Title)
			for _, m := range []string{"admin", "login", "log in", "sign in", "signin", "dashboard", "console", "phpmyadmin"} {
				if strings.Contains(t, m) {
					return true, fmt.Sprintf("page title %q matches admin/login signature %q", in.HTTP.Title, m),
						map[string]any{"title": in.HTTP.Title, "marker": m}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-003", Severity: "high",
		Title: "TLS certificate expired or hostname mismatch",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS == nil {
				return false, "", nil
			}
			if in.TLS.DaysToExpiry <= 0 && in.TLS.Leaf.NotAfter != "" {
				return true, fmt.Sprintf("certificate expired %d days ago", -in.TLS.DaysToExpiry),
					map[string]any{"not_after": in.TLS.Leaf.NotAfter, "days_to_expiry": strconv.Itoa(in.TLS.DaysToExpiry)}
			}
			if !in.TLS.HostnameMatch {
				return true, "presented certificate does not match the host",
					map[string]any{"sans": in.TLS.Leaf.SANs}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-004", Severity: "high",
		Title: "admin/db-class port open",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TCP == nil {
				return false, "", nil
			}
			admin := map[int]string{22: "ssh", 3389: "rdp", 5900: "vnc",
				3306: "mysql", 5432: "postgres", 27017: "mongodb", 6379: "redis"}
			for _, p := range in.TCP.Ports {
				if svc, ok := admin[p.Port]; ok && p.State == "open" {
					return true, fmt.Sprintf("%s port %d open", svc, p.Port),
						map[string]any{"port": strconv.Itoa(p.Port), "service": svc}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-005", Severity: "medium",
		Title: "TLS protocol ≤ 1.1 negotiated",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS == nil {
				return false, "", nil
			}
			v := in.TLS.Negotiated.Version
			if v == "1.0" || v == "1.1" {
				return true, "negotiated TLS " + v,
					map[string]any{"version": v, "cipher": in.TLS.Negotiated.Cipher}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-006", Severity: "medium",
		Title: "security headers absent on login-bearing page",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status < 200 || in.HTTP.Status >= 300 {
				return false, "", nil
			}
			t := strings.ToLower(in.HTTP.Title)
			login := strings.Contains(t, "login") || strings.Contains(t, "log in") ||
				strings.Contains(t, "sign in") || strings.Contains(t, "signin")
			if !login {
				return false, "", nil
			}
			var missing []string
			for _, h := range []string{"content-security-policy", "x-frame-options", "x-content-type-options"} {
				if _, ok := in.HTTP.HeadersCanonical[h]; !ok {
					missing = append(missing, h)
				}
			}
			if len(missing) > 0 {
				return true, "login page missing security headers: " + strings.Join(missing, ", "),
					map[string]any{"missing": missing}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-007", Severity: "medium",
		Title: "HSTS missing where baseline required",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || !in.BaselineRequiresHSTS {
				return false, "", nil
			}
			if strings.HasPrefix(in.HTTP.FinalURL, "https://") && in.HTTP.Status > 0 {
				if _, ok := in.HTTP.HeadersCanonical["strict-transport-security"]; !ok {
					return true, "strict-transport-security absent on HTTPS page",
						map[string]any{"final_url": in.HTTP.FinalURL}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-008", Severity: "medium",
		Title: "technology with known-EOL version",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil {
				return false, "", nil
			}
			for _, t := range in.HTTP.Tech {
				if eolTech(t.Name, t.Version) {
					return true, fmt.Sprintf("%s %s is end-of-life", t.Name, t.Version),
						map[string]any{"tech": t.Name, "version": t.Version}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-009", Severity: "high",
		Title: "known-risky stack newly detected",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.PrevHTTP == nil {
				return false, "", nil
			}
			prev := map[string]bool{}
			for _, t := range in.PrevHTTP.Tech {
				prev[t.Name] = true
			}
			for _, t := range in.HTTP.Tech {
				if !prev[t.Name] && riskyTech(t.Name) {
					return true, "risky technology appeared: " + t.Name,
						map[string]any{"tech": t.Name}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-010", Severity: "low",
		Title: "new asset on high-criticality scope without owner tag",
		Applies: func(in *Input) (bool, string, map[string]any) {
			crit := in.Criticality == "high" || in.Criticality == "critical"
			if in.NewAsset && crit && in.OwnerTag == "" {
				return true, "new high-criticality asset has no inventory owner tag",
					map[string]any{"identifier": in.Identifier}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-011", Severity: "low",
		Title: "server header discloses exact version",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil {
				return false, "", nil
			}
			srv := in.HTTP.HeadersCanonical["server"]
			if srv != "" && strings.ContainsAny(srv, "0123456789") && strings.Contains(srv, "/") {
				return true, "server header discloses version: " + srv,
					map[string]any{"server": srv}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-012", Severity: "medium",
		Title: "directory listing exposed",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status < 200 || in.HTTP.Status >= 300 {
				return false, "", nil
			}
			if strings.HasPrefix(strings.ToLower(in.HTTP.Title), "index of /") {
				return true, "directory listing page: " + in.HTTP.Title,
					map[string]any{"title": in.HTTP.Title}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-013", Severity: "medium",
		Title: "default install/welcome page exposed",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status < 200 || in.HTTP.Status >= 300 {
				return false, "", nil
			}
			t := strings.ToLower(in.HTTP.Title)
			for _, m := range []string{"apache2 ubuntu default page", "iis windows server",
				"welcome to nginx", "default web site page", "test page for the"} {
				if strings.Contains(t, m) {
					return true, "default install page: " + in.HTTP.Title,
						map[string]any{"title": in.HTTP.Title}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-014", Severity: "medium",
		Title: "debug/error page signature",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status == 0 {
				return false, "", nil
			}
			t := strings.ToLower(in.HTTP.Title)
			for _, m := range []string{"whoops", "stack trace", "traceback", "debug", "exception"} {
				if strings.Contains(t, m) {
					return true, "debug/error page title: " + in.HTTP.Title,
						map[string]any{"title": in.HTTP.Title}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-015", Severity: "medium",
		Title: "self-signed certificate on internet-facing asset",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS != nil && in.TLS.Leaf.SelfSigned {
				return true, "certificate is self-signed",
					map[string]any{"issuer": in.TLS.Leaf.Issuer, "subject_cn": in.TLS.Leaf.SubjectCN}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-016", Severity: "info",
		Title: "certificate validity exceeds 398 days",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS == nil || in.TLS.DaysToExpiry <= 398 {
				return false, "", nil
			}
			return true, fmt.Sprintf("certificate has %d days of validity remaining", in.TLS.DaysToExpiry),
				map[string]any{"days_to_expiry": strconv.Itoa(in.TLS.DaysToExpiry)}
		},
	},
	{
		ID: "EXP-017", Severity: "medium",
		Title: "weak TLS cipher negotiated",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS == nil {
				return false, "", nil
			}
			c := strings.ToUpper(in.TLS.Negotiated.Cipher)
			for _, w := range []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"} {
				if strings.Contains(c, w) {
					return true, "weak cipher negotiated: " + in.TLS.Negotiated.Cipher,
						map[string]any{"cipher": in.TLS.Negotiated.Cipher}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-018", Severity: "low",
		Title: "certificate expires within 7 days",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS != nil && in.TLS.Leaf.NotAfter != "" && in.TLS.DaysToExpiry > 0 && in.TLS.DaysToExpiry <= 7 {
				return true, fmt.Sprintf("certificate expires in %d days", in.TLS.DaysToExpiry),
					map[string]any{"not_after": in.TLS.Leaf.NotAfter}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-019", Severity: "medium",
		Title: "dangling CNAME (no known takeable service)",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.DNS == nil || in.DNS.Dangling == nil || in.DNS.Dangling.TakeableService != "" {
				return false, "", nil
			}
			return true, "CNAME target " + in.DNS.Dangling.Target + " is dangling",
				map[string]any{"target": in.DNS.Dangling.Target}
		},
	},
	{
		ID: "EXP-020", Severity: "info",
		Title: "single nameserver (DNS single point of failure)",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.DNS != nil && len(in.DNS.Records["NS"]) == 1 {
				return true, "only one NS record: " + in.DNS.Records["NS"][0],
					map[string]any{"ns": in.DNS.Records["NS"]}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-021", Severity: "low",
		Title: "no SPF record on apex domain",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.DNS == nil || !isApex(in.Identifier) {
				return false, "", nil
			}
			for _, txt := range in.DNS.Records["TXT"] {
				if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
					return false, "", nil
				}
			}
			if len(in.DNS.Records["MX"]) > 0 || len(in.DNS.Records["A"]) > 0 {
				return true, "apex has no SPF TXT record", map[string]any{"identifier": in.Identifier}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-022", Severity: "info",
		Title: "wildcard certificate served",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.TLS == nil {
				return false, "", nil
			}
			for _, san := range in.TLS.Leaf.SANs {
				if strings.HasPrefix(san, "*.") {
					return true, "wildcard certificate in use: " + san,
						map[string]any{"san": san}
				}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-023", Severity: "medium",
		Title: "plain HTTP serves content (no HTTPS redirect)",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil {
				return false, "", nil
			}
			if strings.HasPrefix(in.HTTP.FinalURL, "http://") && in.HTTP.Status >= 200 && in.HTTP.Status < 300 {
				return true, "content served over plain HTTP without redirect",
					map[string]any{"final_url": in.HTTP.FinalURL, "status": strconv.Itoa(in.HTTP.Status)}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-024", Severity: "medium",
		Title: "CORS wildcard origin with credentials",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil {
				return false, "", nil
			}
			acao := in.HTTP.HeadersCanonical["access-control-allow-origin"]
			acac := strings.ToLower(in.HTTP.HeadersCanonical["access-control-allow-credentials"])
			if acao == "*" && acac == "true" {
				return true, "CORS allows any origin with credentials",
					map[string]any{"access-control-allow-origin": acao}
			}
			return false, "", nil
		},
	},
	{
		ID: "EXP-025", Severity: "high",
		Title: "admin panel technology exposed",
		Applies: func(in *Input) (bool, string, map[string]any) {
			if in.HTTP == nil || in.HTTP.Status < 200 || in.HTTP.Status >= 400 {
				return false, "", nil
			}
			for _, t := range in.HTTP.Tech {
				switch t.Name {
				case "phpmyadmin":
					return true, "phpMyAdmin exposed", map[string]any{"tech": t.Name}
				}
			}
			return false, "", nil
		},
	},
}

// EvaluateExposure runs the v1 ruleset over the input (doc 03 §7.4).
func EvaluateExposure(in *Input) []Finding {
	var out []Finding
	for _, r := range ExposureV1 {
		hit, detail, evidence := r.Applies(in)
		if !hit {
			continue
		}
		out = append(out, Finding{
			RuleID: r.ID, Severity: r.Severity, Title: r.Title,
			Detail: detail, Evidence: evidence,
		})
	}
	return out
}

// eolVersions is the rule-maintained known-EOL list (doc 03 §7.4 EXP-008).
var eolVersions = map[string][]string{
	"php":       {"5.", "7.0", "7.1", "7.2", "7.3", "8.0"},
	"apache":    {"2.0", "2.2"},
	"iis":       {"5.", "6.", "7.0", "7.5"},
	"jquery":    {"1.", "2."},
	"wordpress": {"3.", "4."},
	"drupal":    {"7.", "8."},
}

func eolTech(name, version string) bool {
	prefixes, ok := eolVersions[name]
	if !ok || version == "" {
		return false
	}
	for _, p := range prefixes {
		if strings.HasPrefix(version, p) {
			return true
		}
	}
	return false
}

// riskyTech is the known-risky stack list for EXP-009 (doc 03 §7.4).
func riskyTech(name string) bool {
	switch name {
	case "phpmyadmin", "kubernetes":
		return true
	}
	return false
}

// isApex heuristically identifies apex domains (two labels).
func isApex(identifier string) bool {
	identifier = strings.TrimSuffix(strings.ToLower(identifier), ".")
	if strings.Contains(identifier, "/") {
		return false
	}
	return strings.Count(identifier, ".") == 1
}

// ---------------------------------------------------------------------------
// RuleInput assembly from stored snapshots
// ---------------------------------------------------------------------------

// InputFromSnapshots builds the engine Input from the current snapshot set
// (nil docs tolerated — rules skip missing data).
func InputFromSnapshots(assetID, identifier, criticality string, docs map[string]*snapshot.Document) *Input {
	in := &Input{AssetID: assetID, Identifier: identifier, Criticality: criticality}
	if d := docs[snapshot.ProbeDNS]; d != nil {
		in.DNS = d.Data.DNS
	}
	if d := docs[snapshot.ProbeTLS]; d != nil {
		in.TLS = d.Data.TLS
	}
	if d := docs[snapshot.ProbeHTTP]; d != nil {
		in.HTTP = d.Data.HTTP
	}
	if d := docs[snapshot.ProbeTCPPort]; d != nil {
		in.TCP = d.Data.TCP
	}
	return in
}
