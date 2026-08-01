package publish

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/risk"
)

//go:embed alert-event.schema.json
var alertSchemaJSON []byte

// AlertSource is the CloudEvents source for detect.alert (doc 05 §5.2).
const AlertSource = "//aegisbastion/detect"

// AlertType is the CloudEvents type for AlertEvent v1.
const AlertType = "com.aegisbastion.alert.v1"

var (
	schemaOnce sync.Once
	schemaComp *jsonschema.Schema
	schemaErr  error
)

// alertSchema compiles the embedded AlertEvent v1 JSON schema exactly once.
// The embedded copy is verified against the canonical repo schema
// (schemas/alert/v1/alert-event.schema.json) by TestEmbeddedSchemaMatchesCanonical.
func alertSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(alertSchemaJSON)))
		if err != nil {
			schemaErr = fmt.Errorf("alert schema unmarshal: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		// Assert formats so occurred_at (date-time) and reference URIs are
		// actually checked, not just shaped (doc 05 §5.2).
		c.AssertFormat()
		if err := c.AddResource("alert-event.schema.json", doc); err != nil {
			schemaErr = err
			return
		}
		schemaComp, schemaErr = c.Compile("alert-event.schema.json")
	})
	return schemaComp, schemaErr
}

// ValidateAlertEvent validates one AlertEvent v1 document (decoded JSON
// value) against the canonical schema. Exported for tests and for the
// negative-path wiring checks (doc 04 §14 acceptance test 4).
func ValidateAlertEvent(v any) error {
	sch, err := alertSchema()
	if err != nil {
		return err
	}
	return sch.Validate(v)
}

// ShouldAlert implements the Ruling C8 inclusion rule: only
// validation.verdict = CONFIRMED findings at or above the configured
// risk-tier threshold (default P2) map to detect.alert; INCONCLUSIVE /
// NOT_VALIDATABLE never alert (zero-false-positive contract, doc 04 §4.3).
func ShouldAlert(fr *detectv1.FindingReport, tierThreshold string) bool {
	if fr.GetValidation().GetVerdict() != detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED {
		return false
	}
	tier := fr.GetRisk().GetTier()
	if tier == "" || tierThreshold == "" {
		return false
	}
	return risk.TierAtOrAbove(tier, tierThreshold)
}

// AlertMapper is the D11 producer-side mapping (doc 04 §4.3, Ruling C8).
type AlertMapper struct {
	OrgID         string
	TierThreshold string
	// Now is the clock (tests).
	Now func() time.Time
}

// NewAlertMapper builds the mapper. tierThreshold is validated by config
// (P1..P5); empty defaults to P2 (doc 04 §4.3).
func NewAlertMapper(orgID, tierThreshold string) *AlertMapper {
	if tierThreshold == "" {
		tierThreshold = "P2"
	}
	return &AlertMapper{
		OrgID:         orgID,
		TierThreshold: tierThreshold,
		Now:           func() time.Time { return time.Now().UTC() },
	}
}

// Map converts one FindingReport into the AlertEvent v1 + CloudEvents 1.0
// envelope, validates the AlertEvent against the canonical schema (a
// mapping bug must never put a malformed event on herald's input contract),
// and returns the envelope bytes for the bus. tokenJTI is the task's
// gatekeeper Scope Token jti (MANDATORY, doc 05 §5.2).
func (m *AlertMapper) Map(fr *detectv1.FindingReport, tokenJTI string) ([]byte, string, error) {
	if tokenJTI == "" {
		return nil, "", fmt.Errorf("alert map: authorization_token_id (task token jti) is mandatory")
	}
	eventID := "evt_" + ulid.Make().String()
	occurred := m.Now()
	if fr.GetValidation().GetValidatedAt() != nil {
		occurred = fr.GetValidation().GetValidatedAt().AsTime()
	}

	alert := map[string]any{
		"schema_version":         "1.0",
		"event_id":               eventID,
		"org_id":                 m.OrgID,
		"source_module":          "detect",
		"source_event_id":        fr.GetFindingId(),
		"authorization_token_id": tokenJTI,
		"title":                  alertTitle(fr),
		"description":            alertDescription(fr),
		"severity":               alertSeverity(fr.GetSeverity()),
		"confidence":             "confirmed", // mapping only runs for CONFIRMED
		"category":               "vuln",
		"fingerprint_hint":       fr.GetFingerprint(),
		"asset":                  alertAsset(fr),
		"evidence": map[string]any{
			"scanner":    fr.GetVulnerability().GetSource(),
			"proof":      fr.GetValidation().GetEvidenceRefs(),
			"references": fr.GetVulnerability().GetReferences(),
		},
		"pii_classification": "none", // Detect canaries are synthetic (doc 04 §10.5)
		"occurred_at":        occurred.UTC().Format(time.RFC3339),
		"labels":             alertLabels(fr),
	}

	// Schema gate: a malformed AlertEvent must never reach detect.alert.
	var decoded any
	raw, err := json.Marshal(alert)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, "", err
	}
	if err := ValidateAlertEvent(decoded); err != nil {
		return nil, "", fmt.Errorf("alert map: AlertEvent v1 schema validation failed (dropping, fix the mapper): %w", err)
	}

	envelope := map[string]any{
		"specversion":     "1.0",
		"id":              eventID,
		"source":          AlertSource,
		"type":            AlertType,
		"subject":         fr.GetFingerprint(),
		"time":            occurred.UTC().Format(time.RFC3339),
		"datacontenttype": "application/json",
		"data":            alert,
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", err
	}
	return out, eventID, nil
}

// PublishAlert maps (when ShouldAlert passes) and publishes one detect.alert
// message. Returns (published, error). Nats-Msg-Id = "alert-<finding_id>"
// (idempotent on finding, doc 04 §12).
func (m *AlertMapper) PublishAlert(ctx context.Context, pub interface {
	PublishMsg(ctx context.Context, msg *nats.Msg) error
}, fr *detectv1.FindingReport, tokenJTI string) (bool, error) {
	if !ShouldAlert(fr, m.TierThreshold) {
		return false, nil
	}
	payload, _, err := m.Map(fr, tokenJTI)
	if err != nil {
		return false, err
	}
	msg := nats.NewMsg(SubjectAlert)
	msg.Header.Set(nats.MsgIdHdr, "alert-"+fr.GetFindingId())
	msg.Header.Set("Content-Type", "application/cloudevents+json")
	msg.Data = payload
	if err := pub.PublishMsg(ctx, msg); err != nil {
		return false, fmt.Errorf("alert map: publish %s: %w", SubjectAlert, err)
	}
	return true, nil
}

func alertTitle(fr *detectv1.FindingReport) string {
	title := fr.GetVulnerability().GetTitle()
	if title == "" {
		title = fr.GetVulnerability().GetId()
	}
	if title == "" {
		title = "detect finding"
	}
	return title
}

func alertDescription(fr *detectv1.FindingReport) string {
	return fmt.Sprintf("CONFIRMED %s on %s (risk %s score %d, validator %s, task %s)",
		fr.GetVulnerability().GetId(), fr.GetTarget(),
		fr.GetRisk().GetTier(), fr.GetRisk().GetScore(),
		fr.GetValidation().GetMethod(), fr.GetTaskId())
}

// alertSeverity maps the CVSS band onto the AlertEvent enum
// (informational → info; doc 05 §5.2).
func alertSeverity(s detectv1.Severity) string {
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

// alertAsset builds the AlertEvent asset block (doc 04 §4.3 mapping:
// asset.identifier ← target).
func alertAsset(fr *detectv1.FindingReport) map[string]any {
	target := fr.GetTarget()
	identifier := target
	host := target
	if h, rest, ok := strings.Cut(target, "://"); ok && rest != "" {
		_ = h
		host = rest
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host != "" {
		identifier = host
	}
	kind := "domain"
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		kind = "ip"
	}
	assetID := fr.GetAssetRef()
	if assetID == "" {
		assetID = "asset:detect:" + fr.GetFingerprint()
	}
	return map[string]any{
		"asset_id":   assetID,
		"kind":       kind,
		"identifier": identifier,
	}
}

func alertLabels(fr *detectv1.FindingReport) map[string]string {
	labels := map[string]string{
		"risk_tier":  fr.GetRisk().GetTier(),
		"risk_score": fmt.Sprint(fr.GetRisk().GetScore()),
		"validator":  fr.GetValidation().GetMethod(),
	}
	if id := fr.GetVulnerability().GetId(); strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		labels["cve"] = strings.ToUpper(id)
	}
	return labels
}
