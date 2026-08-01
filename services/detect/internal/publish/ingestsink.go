package publish

import (
	"context"
	"strings"
	"time"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"
)

// FindingSink persists one completed finding to the system-of-record path
// (data platform Ingest API, or the local fallback store at MVP).
type FindingSink interface {
	StoreFinding(ctx context.Context, fr *detectv1.FindingReport, scopeToken string) error
}

// IngestSink is the data-platform Ingest API sink (doc 09 §2.2).
type IngestSink struct {
	Client   *IngestClient
	TenantID string
}

// NewIngestSink builds the sink.
func NewIngestSink(client *IngestClient, tenantID string) *IngestSink {
	return &IngestSink{Client: client, TenantID: tenantID}
}

// StoreFinding implements FindingSink.
func (s *IngestSink) StoreFinding(ctx context.Context, fr *detectv1.FindingReport, scopeToken string) error {
	return s.Client.IngestFindings(ctx, fr.GetTaskId(), scopeToken, []FindingIngest{FindingToIngest(fr)})
}

// FindingToIngest converts a FindingReport into the ingest wire form.
func FindingToIngest(fr *detectv1.FindingReport) FindingIngest {
	return FindingIngest{
		FindingID:   fr.GetFindingId(),
		AssetType:   assetType(fr.GetTarget()),
		AssetValue:  assetValue(fr.GetTarget()),
		Module:      "detect",
		CheckID:     fr.GetVulnerability().GetTemplateId(),
		Title:       fr.GetVulnerability().GetTitle(),
		Severity:    SeverityString(fr.GetSeverity()),
		State:       StateString(fr.GetValidation().GetVerdict()),
		Fingerprint: strings.TrimPrefix(fr.GetFingerprint(), "sha256:"),
		Validation: map[string]any{
			"verdict":           VerdictString(fr.GetValidation().GetVerdict()),
			"method":            fr.GetValidation().GetMethod(),
			"evidence_refs":     fr.GetValidation().GetEvidenceRefs(),
			"validator_version": fr.GetValidation().GetValidatorVersion(),
			"confidence":        fr.GetValidation().GetConfidence(),
			"target":            fr.GetTarget(),
			"vuln_class_source": fr.GetVulnerability().GetSource(),
		},
		Risk:        fr.GetRisk().GetFactors().AsMap(),
		EvidenceRef: firstRef(fr.GetValidation().GetEvidenceRefs()),
		Occurrence:  int(fr.GetOccurrences()),
		FirstSeen:   ts(fr.GetFirstSeen()),
		LastSeen:    ts(fr.GetLastSeen()),
		TaskID:      fr.GetTaskId(),
		Compliance: map[string]any{
			"roe_id":     fr.GetRoeId(),
			"mission_id": fr.GetMissionId(),
		},
	}
}

// SeverityString maps the proto band to the store text form (info|low|…).
func SeverityString(s detectv1.Severity) string {
	switch s {
	case detectv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	case detectv1.Severity_SEVERITY_HIGH:
		return "high"
	case detectv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case detectv1.Severity_SEVERITY_LOW:
		return "low"
	default:
		return "info"
	}
}

// VerdictString maps the proto verdict to the doc 04 §4.3 text form.
func VerdictString(v detectv1.ValidationVerdict) string {
	switch v {
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED:
		return "CONFIRMED"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_REPRODUCIBLE:
		return "NOT_REPRODUCIBLE"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_INCONCLUSIVE:
		return "INCONCLUSIVE"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_VALIDATABLE:
		return "NOT_VALIDATABLE"
	default:
		return "INCONCLUSIVE"
	}
}

// StateString proposes the doc 04 §7.3 lifecycle state from the verdict
// (persisted by 09 / the fallback store — Detect proposes, never owns).
func StateString(v detectv1.ValidationVerdict) string {
	switch v {
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED:
		return "confirmed_open"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_REPRODUCIBLE:
		return "false_positive"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_VALIDATABLE:
		return "triaged"
	default:
		return "validating"
	}
}

func assetType(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return "subdomain"
	}
	if strings.Contains(target, "/") {
		return "netblock"
	}
	return "ip"
}

func assetValue(target string) string {
	v := target
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

func firstRef(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0]
}

func ts(t interface{ AsTime() time.Time }) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return t.AsTime()
}
