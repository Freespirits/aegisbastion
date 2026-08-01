package coordinator

import (
	"net"
	"net/url"
	"strings"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/risk"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// parseProxyURL parses the task proxy URL (panics only on wiring bugs — the
// proxy produced it).
func parseProxyURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic("coordinator: bad proxy url " + raw)
	}
	return u
}

// capSeverity enforces the doc 04 §6 severity ceilings: NOT_VALIDATABLE is
// capped at medium until a validator exists; the security-header class is
// the weakest validator class and caps at informational.
func capSeverity(severity string, verdict ave.Verdict, vulnClass string) string {
	if vulnClass == scanner.ClassSecurityHeader {
		return "informational"
	}
	if verdict == ave.VerdictNotValidatable && severityRank(severity) > severityRank("medium") {
		return "medium"
	}
	return severity
}

// cvssForSeverity maps the CVSS band onto a base score for risk-v1 when the
// scanner supplies no numeric CVSS (fixture/raw adapters report bands, doc
// 04 §4.3 severity is "CVSS-derived"). Band midpoints keep scoring
// deterministic without inventing precision.
func cvssForSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.0
	default:
		return 0.0
	}
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational", "info":
		return 1
	default:
		return 0
	}
}

func severityProto(s string) detectv1.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return detectv1.Severity_SEVERITY_CRITICAL
	case "high":
		return detectv1.Severity_SEVERITY_HIGH
	case "medium":
		return detectv1.Severity_SEVERITY_MEDIUM
	case "low":
		return detectv1.Severity_SEVERITY_LOW
	default:
		return detectv1.Severity_SEVERITY_INFORMATIONAL
	}
}

func verdictProto(v ave.Verdict) detectv1.ValidationVerdict {
	switch v {
	case ave.VerdictConfirmed:
		return detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED
	case ave.VerdictNotReproducible:
		return detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_REPRODUCIBLE
	case ave.VerdictNotValidatable:
		return detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_VALIDATABLE
	default:
		return detectv1.ValidationVerdict_VALIDATION_VERDICT_INCONCLUSIVE
	}
}

func statusProto(v ave.Verdict) detectv1.FindingStatus {
	switch v {
	case ave.VerdictConfirmed:
		return detectv1.FindingStatus_FINDING_STATUS_CONFIRMED
	case ave.VerdictNotReproducible:
		return detectv1.FindingStatus_FINDING_STATUS_SUPPRESSED
	default:
		return detectv1.FindingStatus_FINDING_STATUS_OPEN
	}
}

func validatorVersion(r *ave.Result) string {
	if strings.HasPrefix(r.Method, "evs.") {
		return "evs-0.1.0"
	}
	return ave.Version
}

func intelVersion(m *risk.Mirror) string {
	if m == nil {
		return ""
	}
	return m.Version()
}

// evidenceString reads a scanner-evidence string (exposure/criticality hints
// from Discover labels when present).
func evidenceString(raw scanner.RawResult, key string) string {
	if raw.Evidence == nil {
		return ""
	}
	if v, ok := raw.Evidence[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// hostOf reduces a target to its host portion (asset_ref construction).
func hostOf(target string) string {
	s := target
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}
