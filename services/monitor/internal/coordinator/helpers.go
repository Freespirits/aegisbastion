package coordinator

import (
	"crypto/sha256"
	"fmt"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/alertmap"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/ctlog"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/diff"
)

// deterministicAssetID renders the stable uuid-shaped id used for
// feed-derived watch assets (mirrors executor.deterministicUUID).
func deterministicAssetID(identifier string) string {
	h := sha256.Sum256([]byte("aegisbastion.monitor.asset|" + identifier))
	h[6] = (h[6] & 0x0f) | 0x80
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// diffChangeAssetNew builds the asset.new change candidate for an in-scope
// feed candidate (passive — confidence probable per doc 03 §5.3/§7.5).
func diffChangeAssetNew(cand ctlog.Candidate) diff.Change {
	return diff.Change{
		Type:       "asset.new",
		Severity:   diff.SevLow,
		Confidence: diff.ConfProbable,
		Summary:    fmt.Sprintf("new %s observed via %s: %s", cand.Kind, cand.Source["type"], cand.Name),
		DiffKind:   "asset_lifecycle",
		Before:     map[string]any{},
		After: map[string]any{
			"identifier": cand.Name,
			"source":     cand.Source["detail"],
		},
		DiffKey: "new:" + cand.Name,
		Followups: []diff.Followup{{
			Capability: "detect.scan",
			Reason:     "new asset — consider baseline exposure scan",
		}},
	}
}

// alertParamsPassive builds the alert mapping params for passive-derived
// changes (RoE id instead of token jti, doc 03 §5.3).
func alertParamsPassive(roeID string) alertmap.Params {
	return alertmap.Params{
		AlertThreshold: "medium",
		ROEID:          roeID,
		Passive:        true,
	}
}
