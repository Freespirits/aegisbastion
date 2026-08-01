package store

import (
	"context"
	"time"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ids"
)

// FallbackSink persists findings to detect.findings_fallback (doc 04 §13 MVP
// fallback until the data platform ships; mirrors dp.findings so migration
// is a copy). It satisfies publish.FindingSink without an import cycle.
type FallbackSink struct {
	St       *Store
	TenantID string
}

// NewFallbackSink builds the sink.
func NewFallbackSink(st *Store, tenantID string) *FallbackSink {
	return &FallbackSink{St: st, TenantID: tenantID}
}

// StoreFinding implements the FindingSink contract.
func (s *FallbackSink) StoreFinding(ctx context.Context, fr *detectv1.FindingReport, _ string) error {
	validation := map[string]any{
		"verdict":           verdictString(fr.GetValidation().GetVerdict()),
		"method":            fr.GetValidation().GetMethod(),
		"evidence_refs":     fr.GetValidation().GetEvidenceRefs(),
		"validator_version": fr.GetValidation().GetValidatorVersion(),
		"confidence":        fr.GetValidation().GetConfidence(),
		// Carried so detect.revalidate can re-aim validators from the
		// fallback store alone (doc 04 §4.1).
		"target":     fr.GetTarget(),
		"matched_at": fr.GetTarget(),
		"vuln_class": fr.GetVulnerability().GetSource(),
		"check_id":   fr.GetVulnerability().GetTemplateId(),
	}
	risk := map[string]any{
		"score":          fr.GetRisk().GetScore(),
		"tier":           fr.GetRisk().GetTier(),
		"scorer_version": fr.GetRisk().GetScorerVersion(),
	}
	for k, v := range fr.GetRisk().GetFactors().AsMap() {
		risk[k] = v
	}
	return s.St.UpsertFinding(ctx, FindingRow{
		TenantID:    s.TenantID,
		FindingID:   ids.UUIDv5(fr.GetFindingId()),
		CheckID:     fr.GetVulnerability().GetTemplateId(),
		Title:       fr.GetVulnerability().GetTitle(),
		Severity:    severityString(fr.GetSeverity()),
		State:       stateString(fr.GetValidation().GetVerdict()),
		Fingerprint: fr.GetFingerprint(),
		Validation:  validation,
		Risk:        risk,
		EvidenceRef: firstRef(fr.GetValidation().GetEvidenceRefs()),
		Occurrence:  int(fr.GetOccurrences()),
		FirstSeen:   ts(fr.GetFirstSeen()),
		LastSeen:    ts(fr.GetLastSeen()),
		TaskID:      fr.GetTaskId(),
		Compliance: map[string]any{
			"roe_id":     fr.GetRoeId(),
			"mission_id": fr.GetMissionId(),
		},
	})
}

func verdictString(v detectv1.ValidationVerdict) string {
	switch v {
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED:
		return "CONFIRMED"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_REPRODUCIBLE:
		return "NOT_REPRODUCIBLE"
	case detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_VALIDATABLE:
		return "NOT_VALIDATABLE"
	default:
		return "INCONCLUSIVE"
	}
}

func severityString(s detectv1.Severity) string {
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

func stateString(v detectv1.ValidationVerdict) string {
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
