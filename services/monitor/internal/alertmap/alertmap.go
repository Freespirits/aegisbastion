// Package alertmap implements the doc 03 §5.3 monitor.alert mapping: a
// MonitorChange becomes AlertEvent v1 (schemas/alert/v1/alert-event.schema.json)
// inside a CloudEvents 1.0 JSON envelope (source //aegisbastion/monitor, type
// com.aegisbastion.alert.v1) when the change is in the alertable set, at or above
// the watch's alert_threshold, and at confidence confirmed/probable (doc 03
// §7.5: only confirmed/probable reach monitor.alert).
package alertmap

import (
	"encoding/json"
	"fmt"
	"time"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/ctypes"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
)

// MaxPayloadBytes is the doc 05 §5.2 alert payload cap (64 KiB — full diffs
// stay in snapshots; evidence carries summary + snapshot_refs).
const MaxPayloadBytes = 64 << 10

// DedupWindowSeconds aligns Alert's dedup with Monitor's 24 h window
// (doc 03 §5.3: fingerprint_hint = fingerprint).
const DedupWindowSeconds = 86400

// Params are the watch/mapping inputs for ShouldAlert + Map.
type Params struct {
	// AlertThreshold is the watch's minimum mapped severity ("info"…"critical").
	AlertThreshold string
	// TokenJTI is the active watch token's jti ("tok_…") — mandatory for
	// confirmed active-scan exposure alerts (doc 05 §5.2, doc 03 §5.3).
	TokenJTI string
	// ROEID is carried on passive-derived alerts instead of the token
	// (doc 03 §5.3 — the AlertEvent schema has no roe_id field, so it travels
	// in labels alongside labels.source=passive_feed).
	ROEID string
	// Passive marks passive-feed-derived changes (R0 mode).
	Passive bool
	// PIIClassification comes from redaction hits (doc 03 §9.5);
	// "none" when empty.
	PIIClassification string
}

// AlertEvent is AlertEvent v1 (schemas/alert/v1/alert-event.schema.json).
// additionalProperties:false on the schema — keep the field set exact.
type AlertEvent struct {
	SchemaVersion        string            `json:"schema_version"`
	EventID              string            `json:"event_id"`
	OrgID                string            `json:"org_id"`
	SourceModule         string            `json:"source_module"`
	SourceEventID        string            `json:"source_event_id"`
	EngagementID         string            `json:"engagement_id,omitempty"`
	AuthorizationTokenID string            `json:"authorization_token_id,omitempty"`
	FingerprintHint      string            `json:"fingerprint_hint,omitempty"`
	Title                string            `json:"title"`
	Description          string            `json:"description,omitempty"`
	Severity             string            `json:"severity"`
	Confidence           string            `json:"confidence"`
	Category             string            `json:"category"`
	Asset                AlertAsset        `json:"asset"`
	Evidence             *AlertEvidence    `json:"evidence,omitempty"`
	PIIClassification    string            `json:"pii_classification,omitempty"`
	OccurredAt           string            `json:"occurred_at"`
	DedupWindowSeconds   int               `json:"dedup_window_seconds,omitempty"`
	RenotifyEvery        int               `json:"renotify_every,omitempty"`
	RequiresAck          bool              `json:"requires_ack,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
}

// AlertAsset is the AlertEvent asset block.
type AlertAsset struct {
	AssetID     string `json:"asset_id"`
	Kind        string `json:"kind"`
	Identifier  string `json:"identifier"`
	Criticality string `json:"criticality,omitempty"`
	OwnerGroup  string `json:"owner_group,omitempty"`
}

// AlertEvidence is the compact evidence block (≤ 64 KiB total payload).
type AlertEvidence struct {
	Scanner    string   `json:"scanner,omitempty"`
	Proof      any      `json:"proof,omitempty"`
	References []string `json:"references,omitempty"`
}

// CloudEvent is the CloudEvents 1.0 JSON-mode envelope
// (schemas/alert/v1/cloudevents-alert-envelope.schema.json).
type CloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject,omitempty"`
	Time            string          `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	Data            json.RawMessage `json:"data"`
}

// ShouldAlert applies doc 03 §5.3 + §7.5: change_type in the alertable set
// (asset.new only on high/critical-criticality scope), severity at or above
// the watch threshold, and confidence confirmed/probable only.
func ShouldAlert(mc *monitorv1.MonitorChange, p Params) bool {
	changeType := events.ChangeTypeString(mc.GetChangeType())
	criticality := mc.GetAsset().GetCriticality()
	if !ctypes.AlertableFor(changeType, criticality) {
		return false
	}
	conf := events.ConfidenceString(mc.GetConfidence())
	if conf != "confirmed" && conf != "probable" {
		return false
	}
	threshold := p.AlertThreshold
	if threshold == "" {
		threshold = "medium"
	}
	return events.SeverityRank(events.SeverityString(mc.GetSeverity())) >= events.SeverityRank(threshold)
}

// Map converts a MonitorChange into the CloudEvents-wrapped AlertEvent v1
// wire bytes ready for the monitor.alert subject. Errors when the result
// would exceed the 64 KiB payload cap.
func Map(mc *monitorv1.MonitorChange, p Params, now time.Time) ([]byte, string, error) {
	changeType := events.ChangeTypeString(mc.GetChangeType())
	entry, _ := ctypes.Lookup(changeType)

	confidence := events.ConfidenceString(mc.GetConfidence())
	if p.Passive && confidence == "confirmed" {
		// Passive-derived alerts are probable until an authorized probe
		// confirms (doc 03 §5.3).
		confidence = "probable"
	}

	labels := map[string]string{}
	for k, v := range mc.GetLabels() {
		labels[k] = v
	}
	tokenID := ""
	if p.Passive {
		labels["source"] = "passive_feed"
		if p.ROEID != "" {
			labels["roe_id"] = p.ROEID
		}
	} else {
		if _, ok := labels["source"]; !ok {
			labels["source"] = "active_probe"
		}
		tokenID = p.TokenJTI
	}
	pii := p.PIIClassification
	if pii == "" {
		pii = "none"
	}

	description := ""
	if mc.GetDiff() != nil {
		description = fmt.Sprintf("change_type=%s diff_kind=%s",
			changeType, mc.GetDiff().GetFields()["kind"].GetStringValue())
	}

	occurred := mc.GetOccurredAt().AsTime()
	if occurred.IsZero() {
		occurred = now.UTC()
	}

	eventID := events.NewID("evt")
	ae := AlertEvent{
		SchemaVersion:        "1.0",
		EventID:              eventID,
		OrgID:                mc.GetOrgId(),
		SourceModule:         "monitor",
		SourceEventID:        mc.GetEventId(),
		AuthorizationTokenID: tokenID,
		FingerprintHint:      mc.GetFingerprint(),
		Title:                mc.GetSummary(),
		Description:          description,
		Severity:             events.SeverityString(mc.GetSeverity()),
		Confidence:           confidence,
		Category:             entry.Category,
		Asset: AlertAsset{
			AssetID:     mc.GetAsset().GetAssetId(),
			Kind:        assetKindString(mc.GetAsset().GetKind()),
			Identifier:  mc.GetAsset().GetIdentifier(),
			Criticality: mc.GetAsset().GetCriticality(),
		},
		Evidence: &AlertEvidence{
			Scanner: "monitor",
			Proof: map[string]any{
				"change_type": changeType,
				"snapshot_refs": map[string]string{
					"before": mc.GetSnapshotRefs().GetBefore(),
					"after":  mc.GetSnapshotRefs().GetAfter(),
				},
			},
		},
		PIIClassification:  pii,
		OccurredAt:         occurred.UTC().Format(time.RFC3339),
		DedupWindowSeconds: DedupWindowSeconds,
		Labels:             labels,
	}
	data, err := json.Marshal(ae)
	if err != nil {
		return nil, "", fmt.Errorf("alertmap: marshal alert event: %w", err)
	}
	ce := CloudEvent{
		SpecVersion:     "1.0",
		ID:              eventID,
		Source:          "//aegisbastion/monitor",
		Type:            "com.aegisbastion.alert.v1",
		Subject:         "asset/" + mc.GetAsset().GetAssetId(),
		Time:            now.UTC().Format(time.RFC3339),
		DataContentType: "application/json",
		Data:            data,
	}
	out, err := json.Marshal(ce)
	if err != nil {
		return nil, "", fmt.Errorf("alertmap: marshal cloudevent: %w", err)
	}
	if len(out) > MaxPayloadBytes {
		return nil, "", fmt.Errorf("alertmap: payload %d bytes exceeds 64 KiB cap", len(out))
	}
	return out, eventID, nil
}

func assetKindString(k monitorv1.AssetKind) string {
	switch k {
	case monitorv1.AssetKind_ASSET_KIND_DOMAIN:
		return "domain"
	case monitorv1.AssetKind_ASSET_KIND_SUBDOMAIN:
		return "subdomain"
	case monitorv1.AssetKind_ASSET_KIND_IP:
		return "ip"
	case monitorv1.AssetKind_ASSET_KIND_CLOUD_RESOURCE:
		return "cloud-resource"
	}
	return "domain"
}
