// Package consumers feeds the data platform from the canonical bus
// (Ruling C3). Three durables mirror module output into the stores:
//
//	detect.findings           (DETECT_FINDINGS)  FindingReport → dp.findings
//	monitor.assets.new        (MONITOR_EVENTS)   NewAssetCandidate → dp.assets
//	hub.discover.asset.changed (DISCOVER_EVENTS) AssetChange JSON → dp.assets
//
// All writes flow through the ingest Engine (one transactional, idempotent
// path): the envelope event_id becomes the idempotency key, so at-least-once
// redelivery is a no-op. Batches synthesized here are marked Internal — the
// REST-only Scope Token re-verification (doc 09 §2.2) is skipped because the
// bus events carry no token material; their authorization was enforced at
// dispatch (PEP-1) and per-target by the module SDKs (PEP-2), per Ruling B.
package consumers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"
	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/ingest"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// Streams/subjects (deploy/jetstream-bootstrap).
const (
	streamDetectFindings  = "DETECT_FINDINGS"
	subjectDetectFindings = "detect.findings"

	streamMonitorEvents  = "MONITOR_EVENTS"
	subjectMonitorAssets = "monitor.assets.new"

	streamDiscoverEvents = "DISCOVER_EVENTS"
	subjectDiscoverAsset = "hub.discover.asset.changed"
)

// Consumers holds the durable subscriptions.
type Consumers struct {
	st   *store.Store
	eng  *ingest.Engine
	js   nats.JetStreamContext
	log  *slog.Logger
	subs []*nats.Subscription
}

// New builds the consumer set.
func New(st *store.Store, eng *ingest.Engine, js nats.JetStreamContext, log *slog.Logger) *Consumers {
	return &Consumers{st: st, eng: eng, js: js, log: log}
}

// Start attaches all durable consumers.
func (c *Consumers) Start() error {
	if _, err := c.subscribe(streamDetectFindings, subjectDetectFindings, "dp-detect-findings", c.handleDetectFinding); err != nil {
		return err
	}
	if _, err := c.subscribe(streamMonitorEvents, subjectMonitorAssets, "dp-monitor-assets-new", c.handleMonitorAsset); err != nil {
		return err
	}
	if _, err := c.subscribe(streamDiscoverEvents, subjectDiscoverAsset, "dp-discover-asset-changed", c.handleDiscoverAsset); err != nil {
		return err
	}
	return nil
}

// Close drains subscriptions.
func (c *Consumers) Close() {
	for _, s := range c.subs {
		_ = s.Drain()
	}
}

func (c *Consumers) subscribe(stream, subject, durable string, h func(msg *nats.Msg) error) (*nats.Subscription, error) {
	sub, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		if err := h(msg); err != nil {
			if isPoison(err) {
				c.log.Error("poison event; terminating redelivery",
					"subject", subject, "err", err)
				_ = msg.Term()
				return
			}
			c.log.Warn("event handling failed; redelivering",
				"subject", subject, "err", err)
			_ = msg.NakWithDelay(5 * time.Second)
			return
		}
		_ = msg.Ack()
	},
		nats.Durable(durable),
		nats.BindStream(stream),
		nats.ManualAck(),
		nats.AckWait(30*time.Second),
		nats.MaxDeliver(12),
	)
	if err != nil {
		return nil, fmt.Errorf("consume %s on %s: %w", subject, stream, err)
	}
	c.subs = append(c.subs, sub)
	c.log.Info("consumer started", "stream", stream, "subject", subject, "durable", durable)
	return sub, nil
}

// poisonError marks permanent failures (contract/tenant violations — no
// amount of redelivery helps).
type poisonError struct{ err error }

func (e *poisonError) Error() string { return e.err.Error() }

func poison(err error) error { return &poisonError{err} }
func isPoison(err error) bool {
	_, ok := err.(*poisonError)
	return ok
}

// ---------------------------------------------------------------------------
// detect.findings → dp.findings (doc 04 §4.3; canonical stream, Ruling C8)
// ---------------------------------------------------------------------------

func (c *Consumers) handleDetectFinding(msg *nats.Msg) error {
	env, err := unmarshalEnvelope(msg.Data)
	if err != nil {
		return poison(err)
	}
	var fr detectv1.FindingReport
	if err := env.GetPayload().UnmarshalTo(&fr); err != nil {
		return poison(fmt.Errorf("payload is not a FindingReport (%s): %w", env.GetType(), err))
	}

	// Tenant resolution: the finding's asset must already be in the
	// inventory (detect targets originate from dp reads via commanders) —
	// its row identifies the owning tenant. MVP-A fallback: exactly one
	// active tenant (doc 00 §4 one-tenant cohort). Multi-tenant deployments
	// with an unknown asset are dropped, never misattributed (fail-closed).
	assetType, assetValue := parseAssetRef(fr.GetAssetRef())
	if assetValue == "" {
		assetValue = canonicalHost(fr.GetTarget())
	}
	tenantID, resolvedType, resolvedValue, err := c.resolveTenantByAsset(assetValue)
	if err != nil {
		return err
	}
	if resolvedType == "" {
		resolvedType = assetType
	}
	if resolvedValue == "" {
		resolvedValue = assetValue
	}
	if tenantID == "" {
		return poison(fmt.Errorf("cannot resolve tenant for asset_ref %q (asset unknown; several or zero active tenants)", fr.GetAssetRef()))
	}

	sev := mapSeverity(fr.GetSeverity())
	validation := map[string]any{
		"status":  "unvalidated",
		"verdict": fr.GetValidation().GetVerdict().String(),
		"method":  fr.GetValidation().GetMethod(),
	}
	if fr.GetValidation().GetVerdict() == detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED {
		validation["status"] = "runtime_validated"
	}
	if refs := fr.GetValidation().GetEvidenceRefs(); len(refs) > 0 {
		validation["evidence_refs"] = refs
	}
	if ts := fr.GetValidation().GetValidatedAt(); ts != nil {
		validation["validated_at"] = ts.AsTime().UTC().Format(time.RFC3339Nano)
	}
	risk := map[string]any{
		"score":          fr.GetRisk().GetScore(),
		"tier":           fr.GetRisk().GetTier(),
		"scorer_version": fr.GetRisk().GetScorerVersion(),
	}
	if f := fr.GetRisk().GetFactors(); f != nil {
		risk["factors"] = f.AsMap()
	}
	checkID := fr.GetVulnerability().GetId()
	if checkID == "" {
		checkID = fr.GetVulnerability().GetTemplateId()
	}
	title := fr.GetVulnerability().GetTitle()
	if title == "" {
		title = checkID
	}
	var evidenceRef string
	if refs := fr.GetValidation().GetEvidenceRefs(); len(refs) > 0 {
		evidenceRef = refs[0]
	}

	b := &ingest.Batch{
		IdempotencyKey: "detect.findings:" + env.GetEventId(),
		TaskID:         fr.GetTaskId(),
		Internal:       true,
		Findings: []ingest.FindingIn{{
			AssetType:   resolvedType,
			AssetValue:  resolvedValue,
			Module:      store.ModuleDetect,
			CheckID:     checkID,
			Title:       title,
			Severity:    sev,
			State:       mapFindingStatus(fr.GetStatus()),
			Fingerprint: strings.TrimPrefix(fr.GetFingerprint(), "sha256:"),
			Validation:  validation,
			Risk:        risk,
			EvidenceRef: evidenceRef,
			Occurrence:  int(fr.GetOccurrences()),
			TaskID:      fr.GetTaskId(),
		}},
	}
	if ts := fr.GetFirstSeen(); ts != nil {
		t := ts.AsTime().UTC()
		b.Findings[0].FirstSeen = &t
	}
	if ts := fr.GetLastSeen(); ts != nil {
		t := ts.AsTime().UTC()
		b.Findings[0].LastSeen = &t
	}
	// The referenced asset must exist for the finding FK; stub it as a
	// candidate when the tenant was resolved without an inventory row.
	if resolvedValue != "" {
		b.Assets = []ingest.AssetIn{{
			Type: resolvedType, Value: resolvedValue, RoeID: fr.GetRoeId(),
			Source: "detect.findings",
		}}
	}

	actor := store.Actor{Type: "service", ID: "dp-consumer-detect"}
	if _, prob := c.eng.Apply(context.Background(), actor, tenantID, b); prob != nil {
		if prob.Reason == "INTERNAL" {
			return fmt.Errorf("apply detect finding: %s", prob.Detail)
		}
		return poison(fmt.Errorf("apply detect finding: %s: %s", prob.Reason, prob.Detail))
	}
	return nil
}

// ---------------------------------------------------------------------------
// monitor.assets.new → dp.assets (doc 03 §5.4: "Discover/Data Platform
// consume it to expand inventory")
// ---------------------------------------------------------------------------

func (c *Consumers) handleMonitorAsset(msg *nats.Msg) error {
	env, err := unmarshalEnvelope(msg.Data)
	if err != nil {
		return poison(err)
	}
	var nac monitorv1.NewAssetCandidate
	if err := env.GetPayload().UnmarshalTo(&nac); err != nil {
		return poison(fmt.Errorf("payload is not a NewAssetCandidate (%s): %w", env.GetType(), err))
	}

	// Scope discipline (doc 03 §9.4): excluded candidates are never stored;
	// out-of-scope ones are quarantined, in-scope ones enter as candidates.
	var status string
	switch nac.GetScopeMatch() {
	case monitorv1.ScopeMatch_SCOPE_MATCH_EXCLUDED:
		c.log.Info("dropping excluded asset candidate",
			"identifier", nac.GetCandidate().GetIdentifier())
		return nil
	case monitorv1.ScopeMatch_SCOPE_MATCH_OUT_OF_SCOPE:
		status = store.StatusQuarantined
	default:
		status = store.StatusCandidate
	}

	typ, err := mapAssetKind(nac.GetCandidate().GetKind())
	if err != nil {
		return poison(err)
	}
	value := nac.GetCandidate().GetIdentifier()
	if value == "" {
		return poison(fmt.Errorf("candidate carries no identifier"))
	}

	// Tenant: candidates are new, so no inventory row can resolve them.
	// MVP-A: the single-active-tenant cohort; otherwise fail-closed drop.
	tenantID, err := c.singleTenant()
	if err != nil {
		return err
	}
	if tenantID == "" {
		return poison(fmt.Errorf("cannot attribute candidate %q: zero or several active tenants", value))
	}

	b := &ingest.Batch{
		IdempotencyKey: "monitor.assets.new:" + env.GetEventId(),
		Internal:       true,
		Assets: []ingest.AssetIn{{
			Type: typ, Value: value, Status: status, RoeID: nac.GetRoeId(),
			Source: "monitor.assets.new",
		}},
	}
	if src := nac.GetSource(); src != nil {
		b.Assets[0].Attributes = map[string]any{"candidate_source": src.AsMap()}
	}
	actor := store.Actor{Type: "service", ID: "dp-consumer-monitor"}
	if _, prob := c.eng.Apply(context.Background(), actor, tenantID, b); prob != nil {
		if prob.Reason == "INTERNAL" {
			return fmt.Errorf("apply monitor candidate: %s", prob.Detail)
		}
		return poison(fmt.Errorf("apply monitor candidate: %s: %s", prob.Reason, prob.Detail))
	}
	return nil
}

// ---------------------------------------------------------------------------
// hub.discover.asset.changed → dp.assets (doc 02 §3.1; tolerant JSON — the
// discover module owns the exact shape; unknown fields are ignored)
// ---------------------------------------------------------------------------

type discoverAssetChanged struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	TenantID      string `json:"tenant_id"`
	Change        string `json:"change"` // new|reactivated|attribute_changed|expired
	Asset         struct {
		Type       string         `json:"type"`
		Value      string         `json:"value"`
		Attributes map[string]any `json:"attributes"`
		Confidence *float64       `json:"confidence"`
	} `json:"asset"`
	RoeID      string    `json:"roe_id"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
	TaskID     string    `json:"task_id"`
}

func (c *Consumers) handleDiscoverAsset(msg *nats.Msg) error {
	var ev discoverAssetChanged
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		return poison(fmt.Errorf("discover asset event does not decode: %w", err))
	}
	if ev.Asset.Type == "" || ev.Asset.Value == "" {
		return poison(fmt.Errorf("discover asset event missing asset.type/value"))
	}

	// Tenant: the discover module is a trusted platform producer; the event
	// carries tenant_id (validated active). Fallback: single active tenant.
	tenantID := ev.TenantID
	if tenantID == "" {
		var err error
		tenantID, err = c.singleTenant()
		if err != nil {
			return err
		}
	}
	if tenantID == "" {
		return poison(fmt.Errorf("discover asset event for %q carries no resolvable tenant", ev.Asset.Value))
	}
	if ok, err := c.st.TenantExists(context.Background(), tenantID); err != nil {
		return err
	} else if !ok {
		return poison(fmt.Errorf("tenant %s not found/active", tenantID))
	}

	status := ""
	switch ev.Change {
	case "expired":
		status = store.StatusExpired
	case "reactivated", "new":
		status = store.StatusActive
	case "attribute_changed":
		status = "" // keep existing
	default:
		return poison(fmt.Errorf("unknown change kind %q", ev.Change))
	}

	key := ev.EventID
	if key == "" {
		key = fmt.Sprintf("%s/%s/%s", tenantID, ev.Asset.Type, ev.Asset.Value)
	}
	b := &ingest.Batch{
		IdempotencyKey: "hub.discover.asset.changed:" + key,
		TaskID:         ev.TaskID,
		Internal:       true,
		Assets: []ingest.AssetIn{{
			Type: ev.Asset.Type, Value: ev.Asset.Value, Attributes: ev.Asset.Attributes,
			Confidence: ev.Asset.Confidence, Status: status, RoeID: ev.RoeID,
			Source: ev.Source,
		}},
	}
	if !ev.ObservedAt.IsZero() {
		b.Assets[0].LastSeen = &ev.ObservedAt
	}
	actor := store.Actor{Type: "service", ID: "dp-consumer-discover"}
	if _, prob := c.eng.Apply(context.Background(), actor, tenantID, b); prob != nil {
		if prob.Reason == "INTERNAL" {
			return fmt.Errorf("apply discover asset: %s", prob.Detail)
		}
		return poison(fmt.Errorf("apply discover asset: %s: %s", prob.Reason, prob.Detail))
	}
	return nil
}

// ---------------------------------------------------------------------------
// mapping helpers
// ---------------------------------------------------------------------------

func unmarshalEnvelope(data []byte) (*platformv1.Envelope, error) {
	var env platformv1.Envelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

// parseAssetRef splits "asset:<kind>:<identifier>" (doc 04 §4.3 asset_ref).
// Identifier may contain colons (IPv6) — SplitN(3).
func parseAssetRef(ref string) (kind, value string) {
	parts := strings.SplitN(ref, ":", 3)
	if len(parts) == 3 && parts[0] == "asset" {
		kind = parts[1]
		if kind == "host" {
			kind = "" // resolved by value lookup
		}
		return kind, parts[2]
	}
	return "", ""
}

// canonicalHost reduces a URL/host target to its canonical host (doc 01 §10.1).
func canonicalHost(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "://"); i >= 0 {
		rest := t[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		t = rest
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return strings.TrimSuffix(strings.ToLower(t), ".")
}

// resolveTenantByAsset finds the tenant owning the asset with this canonical
// value. Returns ("","","") when unknown (caller may fall back).
func (c *Consumers) resolveTenantByAsset(value string) (tenantID, typ, val string, err error) {
	if value == "" {
		return "", "", "", nil
	}
	cv, cerr := ingest.CanonicalizeAssetValue(guessAssetType(value), value)
	if cerr != nil {
		cv = strings.ToLower(value)
	}
	a, err := c.st.FindAssetByValue(context.Background(), cv)
	if err != nil {
		return "", "", "", err
	}
	if a != nil {
		return a.TenantID, a.Type, a.Value, nil
	}
	// Fallback: single active tenant (MVP-A cohort).
	tid, err := c.singleTenant()
	if err != nil || tid == "" {
		return "", "", "", err
	}
	return tid, "", "", nil
}

func (c *Consumers) singleTenant() (string, error) {
	return c.st.SingleActiveTenant(context.Background())
}

// guessAssetType picks a canonicalization rule for a bare value.
func guessAssetType(value string) string {
	if strings.Contains(value, "/") {
		return store.AssetNetblock
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return store.AssetIP
	}
	return store.AssetSubdomain
}

func mapSeverity(s detectv1.Severity) string {
	switch s {
	case detectv1.Severity_SEVERITY_INFORMATIONAL:
		return "info"
	case detectv1.Severity_SEVERITY_LOW:
		return "low"
	case detectv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case detectv1.Severity_SEVERITY_HIGH:
		return "high"
	case detectv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	}
	return "info"
}

// mapFindingStatus maps the proto FindingStatus (doc 04 §4.3) onto the
// lifecycle enum of record (doc 04 §7.3 / dp.findings.state, Ruling C4).
func mapFindingStatus(s detectv1.FindingStatus) string {
	switch s {
	case detectv1.FindingStatus_FINDING_STATUS_CONFIRMED:
		return "confirmed_open"
	case detectv1.FindingStatus_FINDING_STATUS_REMEDIATING:
		return "remediation_claimed"
	case detectv1.FindingStatus_FINDING_STATUS_RESOLVED:
		return "verified_closed"
	case detectv1.FindingStatus_FINDING_STATUS_REGRESSED:
		return "reopened"
	case detectv1.FindingStatus_FINDING_STATUS_SUPPRESSED:
		return "accepted_risk"
	default: // OPEN, UNSPECIFIED
		return "new"
	}
}

func mapAssetKind(k monitorv1.AssetKind) (string, error) {
	switch k {
	case monitorv1.AssetKind_ASSET_KIND_DOMAIN:
		return store.AssetDomain, nil
	case monitorv1.AssetKind_ASSET_KIND_SUBDOMAIN:
		return store.AssetSubdomain, nil
	case monitorv1.AssetKind_ASSET_KIND_IP:
		return store.AssetIP, nil
	case monitorv1.AssetKind_ASSET_KIND_CLOUD_RESOURCE:
		return store.AssetCloudResource, nil
	}
	return "", fmt.Errorf("unsupported monitor AssetKind %s", k)
}
