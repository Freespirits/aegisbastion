// Package rules is the M5 Drift & Exposure Engine (doc 03 §7.3/§7.4):
// baseline rule evaluation and the versioned exposure ruleset
// (exposure_rules/v1, 25 rules).
//
// Deviation note (recorded in the service README): doc 03 §10 specifies
// OPA/Rego for M5. Ruling B re-scoped doc 01's OPA use and the ratified
// Phase-0 gatekeeper ships a hard-coded pipeline ("no custom OPA yet", doc 00
// §3), so the "aligns with doc 01 AuthZ" rationale no longer applies at
// MVP-A. This package implements the exact v1 rule semantics as data-driven,
// versioned rule definitions behind a small Engine interface; a Rego
// evaluator can replace the evaluator without touching callers, rules, or
// state tables.
package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// Input is the evaluation context: the asset plus its latest snapshot set.
type Input struct {
	AssetID      string
	Identifier   string
	Criticality  string
	RegisteredAt string
	// NewAsset marks a just-discovered asset (EXP-010).
	NewAsset bool
	// OwnerTag is the inventory owner tag ("" = untagged, EXP-010).
	OwnerTag string
	// BaselineRequiresHSTS is set when an active baseline mandates HSTS
	// (EXP-007).
	BaselineRequiresHSTS bool
	DNS                  *snapshot.DNSData
	TLS                  *snapshot.TLSData
	HTTP                 *snapshot.HTTPData
	PrevHTTP             *snapshot.HTTPData // previous http observation (tech_added rules)
	TCP                  *snapshot.TCPData
}

// ---------------------------------------------------------------------------
// Baselines (doc 03 §7.3)
// ---------------------------------------------------------------------------

// BaselineRule is one typed baseline expectation (doc 03 §7.3). Type is one
// of http_header | http_redirect | tech_allowlist | port_set | captured
// (captured = generated from current snapshots by monitor.baseline.set).
type BaselineRule struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	Expect   map[string]any `json:"expect"`
}

// ParseBaselineRule decodes a monitor.baselines config row.
func ParseBaselineRule(raw []byte) (*BaselineRule, error) {
	var r BaselineRule
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("rules: baseline config: %w", err)
	}
	return &r, nil
}

// Violation describes a failed baseline expectation.
type Violation struct {
	RuleID   string
	Severity string
	Detail   string
	Observed map[string]any
}

// EvaluateBaseline checks one rule against the input; nil = compliant.
func EvaluateBaseline(r *BaselineRule, in *Input) *Violation {
	switch r.Type {
	case "http_header":
		return evalHTTPHeader(r, in)
	case "http_redirect":
		return evalHTTPRedirect(r, in)
	case "tech_allowlist":
		return evalTechAllowlist(r, in)
	case "port_set":
		return evalPortSet(r, in)
	case "captured":
		return evalCaptured(r, in)
	default:
		return nil
	}
}

func evalHTTPHeader(r *BaselineRule, in *Input) *Violation {
	if in.HTTP == nil || in.HTTP.Status == 0 {
		return nil
	}
	header, _ := r.Expect["header"].(string)
	wantPresent, _ := r.Expect["present"].(bool)
	_, present := in.HTTP.HeadersCanonical[strings.ToLower(header)]
	if wantPresent && !present {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail:   fmt.Sprintf("required header %q absent", header),
			Observed: map[string]any{"header": header, "present": "false"}}
	}
	if !wantPresent && present {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail:   fmt.Sprintf("forbidden header %q present", header),
			Observed: map[string]any{"header": header, "present": "true"}}
	}
	return nil
}

func evalHTTPRedirect(r *BaselineRule, in *Input) *Violation {
	if in.HTTP == nil || in.HTTP.Status == 0 {
		return nil
	}
	want, _ := r.Expect["http_to_https"].(bool)
	if want && strings.HasPrefix(in.HTTP.FinalURL, "http://") &&
		in.HTTP.Status >= 200 && in.HTTP.Status < 400 {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail:   "plain HTTP serves content without redirecting to HTTPS",
			Observed: map[string]any{"final_url": in.HTTP.FinalURL, "status": fmt.Sprint(in.HTTP.Status)}}
	}
	return nil
}

func evalTechAllowlist(r *BaselineRule, in *Input) *Violation {
	if in.HTTP == nil {
		return nil
	}
	allowed := stringSet(expectStrings(r.Expect["allowed"]))
	var bad []string
	for _, t := range in.HTTP.Tech {
		if _, ok := allowed[t.Name]; !ok {
			bad = append(bad, t.Name)
		}
	}
	if len(bad) > 0 {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail:   "technology outside allowlist: " + strings.Join(bad, ", "),
			Observed: map[string]any{"unapproved": bad}}
	}
	return nil
}

func evalPortSet(r *BaselineRule, in *Input) *Violation {
	if in.TCP == nil {
		return nil
	}
	allowed := map[int]bool{}
	for _, p := range expectNumbers(r.Expect["allowed"]) {
		allowed[p] = true
	}
	var bad []string
	for _, p := range in.TCP.Ports {
		if p.State == "open" && !allowed[p.Port] {
			bad = append(bad, fmt.Sprint(p.Port))
		}
	}
	if len(bad) > 0 {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail:   "open ports outside baseline set: " + strings.Join(bad, ", "),
			Observed: map[string]any{"unapproved_ports": bad}}
	}
	return nil
}

// evalCaptured checks a baseline captured by monitor.baseline.set from
// current snapshots: headers present at capture must persist, tech must stay
// within the captured set, and the HTTPS posture must not regress.
func evalCaptured(r *BaselineRule, in *Input) *Violation {
	var problems []string
	observed := map[string]any{}
	if in.HTTP != nil && in.HTTP.Status > 0 {
		for _, h := range expectStrings(r.Expect["headers_required"]) {
			if _, ok := in.HTTP.HeadersCanonical[h]; !ok {
				problems = append(problems, "header "+h+" no longer present")
			}
		}
		allowed := stringSet(expectStrings(r.Expect["tech_allowed"]))
		for _, t := range in.HTTP.Tech {
			if _, ok := allowed[t.Name]; !ok {
				problems = append(problems, "tech "+t.Name+" not in captured set")
			}
		}
		if v, _ := r.Expect["https_required"].(bool); v && strings.HasPrefix(in.HTTP.FinalURL, "http://") {
			problems = append(problems, "regressed to plain HTTP")
		}
		observed["status"] = fmt.Sprint(in.HTTP.Status)
	}
	if len(problems) > 0 {
		return &Violation{RuleID: r.ID, Severity: r.Severity,
			Detail: strings.Join(problems, "; "), Observed: observed}
	}
	return nil
}

// CaptureBaseline builds a "captured" rule from the current snapshot set
// (monitor.baseline.set, doc 03 §4.2 — capture current state as the
// declared-good, operator-approved drift reference).
func CaptureBaseline(baselineID, assetID string, severity string, in *Input) *BaselineRule {
	expect := map[string]any{}
	if in.HTTP != nil && in.HTTP.Status > 0 {
		var required []string
		for _, h := range []string{"strict-transport-security", "content-security-policy",
			"x-frame-options", "x-content-type-options"} {
			if _, ok := in.HTTP.HeadersCanonical[h]; ok {
				required = append(required, h)
			}
		}
		expect["headers_required"] = required
		var tech []string
		for _, t := range in.HTTP.Tech {
			tech = append(tech, t.Name)
		}
		expect["tech_allowed"] = tech
		expect["https_required"] = strings.HasPrefix(in.HTTP.FinalURL, "https://")
	}
	if severity == "" {
		severity = "medium"
	}
	return &BaselineRule{
		ID:       baselineID + ":" + assetID,
		Type:     "captured",
		Severity: severity,
		Expect:   expect,
	}
}

func expectStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if s, ok := v.([]string); ok {
			return s
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func expectNumbers(v any) []int {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, e := range arr {
		switch n := e.(type) {
		case float64:
			out = append(out, int(n))
		case int:
			out = append(out, n)
		case json.Number:
			var i int
			_, _ = fmt.Sscan(n.String(), &i)
			out = append(out, i)
		}
	}
	return out
}

func stringSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}
