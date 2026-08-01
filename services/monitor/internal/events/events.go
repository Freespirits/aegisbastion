// Package events builds the module's public event contracts (doc 03 §5):
// MonitorChange v1 (monitor.changes) and NewAssetCandidate v1
// (monitor.assets.new) as protobuf payloads for the doc 01 §8.2 envelope,
// plus the shared fingerprint / enum-mapping helpers. The monitor.alert
// (AlertEvent v1 / CloudEvents) mapping lives in internal/alertmap.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/ctypes"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/diff"
)

// SchemaVersion is the contract version of every MonitorChange /
// NewAssetCandidate the module emits (doc 03 §5.1/§5.4).
const SchemaVersion = "1.0"

// NewID mints a prefixed ULID event id ("chg_", "nac_", "evt_", "snp_"…).
func NewID(prefix string) string { return prefix + "_" + ulid.Make().String() }

// Fingerprint computes the 24 h dedup key of doc 03 §5.1:
// sha256(mission|asset|change_type|diff_key), rendered "fp_<32 hex>".
func Fingerprint(missionID, assetID, changeType, diffKey string) string {
	sum := sha256.Sum256([]byte(missionID + "|" + assetID + "|" + changeType + "|" + diffKey))
	return "fp_" + hex.EncodeToString(sum[:16])
}

// ---------------------------------------------------------------------------
// enum mappings
// ---------------------------------------------------------------------------

// SeverityProto maps the wire severity string to the proto enum.
func SeverityProto(s string) monitorv1.Severity {
	switch s {
	case diff.SevInfo:
		return monitorv1.Severity_SEVERITY_INFO
	case diff.SevLow:
		return monitorv1.Severity_SEVERITY_LOW
	case diff.SevMedium:
		return monitorv1.Severity_SEVERITY_MEDIUM
	case diff.SevHigh:
		return monitorv1.Severity_SEVERITY_HIGH
	case diff.SevCritical:
		return monitorv1.Severity_SEVERITY_CRITICAL
	}
	return monitorv1.Severity_SEVERITY_UNSPECIFIED
}

// SeverityString maps the proto enum back to the wire string.
func SeverityString(s monitorv1.Severity) string {
	switch s {
	case monitorv1.Severity_SEVERITY_INFO:
		return diff.SevInfo
	case monitorv1.Severity_SEVERITY_LOW:
		return diff.SevLow
	case monitorv1.Severity_SEVERITY_MEDIUM:
		return diff.SevMedium
	case monitorv1.Severity_SEVERITY_HIGH:
		return diff.SevHigh
	case monitorv1.Severity_SEVERITY_CRITICAL:
		return diff.SevCritical
	}
	return ""
}

// SeverityRank orders severities (threshold comparisons, doc 03 §5.3).
func SeverityRank(s string) int {
	switch s {
	case diff.SevInfo:
		return 1
	case diff.SevLow:
		return 2
	case diff.SevMedium:
		return 3
	case diff.SevHigh:
		return 4
	case diff.SevCritical:
		return 5
	}
	return 0
}

// ConfidenceProto maps the wire confidence string to the proto enum.
func ConfidenceProto(c string) monitorv1.Confidence {
	switch c {
	case diff.ConfConfirmed:
		return monitorv1.Confidence_CONFIDENCE_CONFIRMED
	case diff.ConfProbable:
		return monitorv1.Confidence_CONFIDENCE_PROBABLE
	case diff.ConfPossible:
		return monitorv1.Confidence_CONFIDENCE_POSSIBLE
	}
	return monitorv1.Confidence_CONFIDENCE_UNSPECIFIED
}

// ConfidenceString maps the proto enum back to the wire string.
func ConfidenceString(c monitorv1.Confidence) string {
	switch c {
	case monitorv1.Confidence_CONFIDENCE_CONFIRMED:
		return diff.ConfConfirmed
	case monitorv1.Confidence_CONFIDENCE_PROBABLE:
		return diff.ConfProbable
	case monitorv1.Confidence_CONFIDENCE_POSSIBLE:
		return diff.ConfPossible
	}
	return ""
}

// ProbeTypeProto maps the probe_type string to the proto enum.
func ProbeTypeProto(p string) monitorv1.ProbeType {
	switch p {
	case "dns":
		return monitorv1.ProbeType_PROBE_TYPE_DNS
	case "tls":
		return monitorv1.ProbeType_PROBE_TYPE_TLS
	case "http":
		return monitorv1.ProbeType_PROBE_TYPE_HTTP
	case "tcp_port":
		return monitorv1.ProbeType_PROBE_TYPE_TCP_PORT
	}
	return monitorv1.ProbeType_PROBE_TYPE_UNSPECIFIED
}

// AssetKindProto maps the wire asset kind to the proto enum.
func AssetKindProto(k string) monitorv1.AssetKind {
	switch k {
	case "domain":
		return monitorv1.AssetKind_ASSET_KIND_DOMAIN
	case "subdomain":
		return monitorv1.AssetKind_ASSET_KIND_SUBDOMAIN
	case "ip":
		return monitorv1.AssetKind_ASSET_KIND_IP
	case "cloud-resource":
		return monitorv1.AssetKind_ASSET_KIND_CLOUD_RESOURCE
	}
	return monitorv1.AssetKind_ASSET_KIND_UNSPECIFIED
}

// ChangeTypeString maps the proto enum to the doc 03 §5.2 wire string.
func ChangeTypeString(ct monitorv1.ChangeType) string {
	if e, ok := ctypes.LookupProto(ct); ok {
		return e.Type
	}
	return ""
}

// ---------------------------------------------------------------------------
// structpb payload normalization
// ---------------------------------------------------------------------------

// StructPB builds a structpb.Struct from a diff payload map. Diff and rules
// payloads use Go types structpb.NewValue rejects outright ([]string,
// map[string]string, and nests thereof — e.g. dns added/removed record lists,
// rule evidence), so they are normalized to []any / map[string]any first.
func StructPB(m map[string]any) (*structpb.Struct, error) {
	return structpb.NewStruct(normalizePBMap(m))
}

func normalizePBMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = normalizePB(v)
	}
	return out
}

func normalizePB(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return normalizePBMap(t)
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = val
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = val
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizePB(val)
		}
		return out
	default:
		return v
	}
}

// ---------------------------------------------------------------------------
// MonitorChange construction
// ---------------------------------------------------------------------------

// AssetCtx identifies the asset a change concerns.
type AssetCtx struct {
	AssetID     string
	Kind        string // domain|subdomain|ip|cloud-resource
	Identifier  string
	Criticality string
}

// ChangeCtx carries the event-enrichment context around one detected change.
type ChangeCtx struct {
	MissionID string
	ROEID     string
	OrgID     string
	Asset     AssetCtx
	// Detector identifies the confirming probe (doc 03 §5.1).
	ProbeType string
	WorkerID  string
	WatchID   string
	// SnapshotRefs pair the before/after snapshots ("snp_…"; empty allowed).
	SnapshotBefore string
	SnapshotAfter  string
	// FirstSeen is the first time this fingerprint was observed (dedup window).
	FirstSeen time.Time
	// OccurredAt is the detection time of the confirming probe.
	OccurredAt time.Time
	// Labels merge into MonitorChange.labels (e.g. {"surface":"external",
	// "source":"active_probe"|"passive_feed"}).
	Labels map[string]string
}

// NewChange builds MonitorChange v1 from a diff.Change candidate (doc 03
// §5.1). Silent candidates are rejected by the caller before this point.
func NewChange(ctx ChangeCtx, c diff.Change) (*monitorv1.MonitorChange, error) {
	entry, ok := ctypes.Lookup(c.Type)
	if !ok {
		return nil, fmt.Errorf("events: unknown change_type %q", c.Type)
	}
	diffStruct, err := StructPB(map[string]any{
		"kind":    c.DiffKind,
		"before":  c.Before,
		"after":   c.After,
		"rule_id": c.RuleID,
	})
	if err != nil {
		return nil, fmt.Errorf("events: diff struct: %w", err)
	}
	var followups []*monitorv1.SuggestedFollowup
	for _, f := range c.Followups {
		followups = append(followups, &monitorv1.SuggestedFollowup{
			Capability: f.Capability, Reason: f.Reason,
		})
	}
	occurred := ctx.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	firstSeen := ctx.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = occurred
	}
	mc := &monitorv1.MonitorChange{
		SchemaVersion: SchemaVersion,
		EventId:       NewID("chg"),
		MissionId:     ctx.MissionID,
		RoeId:         ctx.ROEID,
		OrgId:         ctx.OrgID,
		Asset: &monitorv1.MonitoredAsset{
			AssetId:     ctx.Asset.AssetID,
			Kind:        AssetKindProto(ctx.Asset.Kind),
			Identifier:  ctx.Asset.Identifier,
			Criticality: ctx.Asset.Criticality,
		},
		ChangeType: entry.Proto,
		Severity:   SeverityProto(c.Severity),
		Confidence: ConfidenceProto(c.Confidence),
		Summary:    c.Summary,
		Diff:       diffStruct,
		SnapshotRefs: &monitorv1.SnapshotRefs{
			Before: ctx.SnapshotBefore,
			After:  ctx.SnapshotAfter,
		},
		Fingerprint: Fingerprint(ctx.MissionID, ctx.Asset.AssetID, c.Type, c.DiffKey),
		FirstSeenAt: timestamppb.New(firstSeen.UTC()),
		OccurredAt:  timestamppb.New(occurred),
		Detector: &monitorv1.Detector{
			ProbeType: ProbeTypeProto(ctx.ProbeType),
			WorkerId:  ctx.WorkerID,
			WatchId:   ctx.WatchID,
		},
		SuggestedFollowups: followups,
		Labels:             ctx.Labels,
	}
	return mc, nil
}

// ---------------------------------------------------------------------------
// NewAssetCandidate construction (doc 03 §5.4)
// ---------------------------------------------------------------------------

// CandidateCtx carries the context for one new-asset candidate.
type CandidateCtx struct {
	MissionID  string
	ROEID      string
	Kind       string // domain|subdomain|ip
	Identifier string
	// Source, e.g. {"type":"ct_log","detail":"log:…, cert cn=…, first_seen …"}.
	Source     map[string]any
	ScopeMatch monitorv1.ScopeMatch
	Confidence string
}

// NewCandidate builds NewAssetCandidate v1.
func NewCandidate(ctx CandidateCtx) (*monitorv1.NewAssetCandidate, error) {
	src, err := structpb.NewStruct(ctx.Source)
	if err != nil {
		return nil, fmt.Errorf("events: source struct: %w", err)
	}
	conf := ctx.Confidence
	if conf == "" {
		conf = diff.ConfProbable
	}
	return &monitorv1.NewAssetCandidate{
		SchemaVersion: SchemaVersion,
		EventId:       NewID("nac"),
		MissionId:     ctx.MissionID,
		RoeId:         ctx.ROEID,
		Candidate: &monitorv1.CandidateAsset{
			Kind:       AssetKindProto(ctx.Kind),
			Identifier: ctx.Identifier,
		},
		Source:     src,
		ScopeMatch: ctx.ScopeMatch,
		Confidence: ConfidenceProto(conf),
	}, nil
}
