// Package reducer consumes worker RawFindings and commits the normalized,
// deduplicated asset graph (doc 02 §2.2 reducer, §2.3 step 3):
//
//	normalize → SCOPE RE-CHECK (out-of-scope ⇒ quarantined_findings, never
//	assets) → dedup/merge on the canonical key (tenant,type,value) → upsert
//	the local working store → upsert into the data platform via its Ingest
//	API (Ruling C4) → write findings provenance → emit AssetChange.
//
// Dedup is two-layered (doc 02 §7.2): JetStream msg-ids collapse worker
// re-emission at the stream; (task, source, asset, observed_at bucket)
// collapses it at the store. Asset merges are idempotent upserts, so
// redelivery of a finding is always safe.
package reducer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"time"

	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/dpingest"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// Disposition tells the queue loop how to settle the message.
type Disposition int

const (
	// Ack — committed (or deliberately dropped: terminal order, quarantine).
	Ack Disposition = iota
	// Retry — transient dependency failure (DP ingest, scope lookup); the
	// caller naks for redelivery. After MaxDPRetries deliveries the reducer
	// degrades: local commit stands, the DP gap is audit-recorded, Ack.
	Retry
)

// Deps wires the reducer.
type Deps struct {
	Store *store.Store
	// DP — data platform ingest client; nil ⇒ offline mode (local store only).
	DP *dpingest.Client
	// Audit — order/task/quarantine audit events (local spool + forwarder).
	Audit *auditfwd.Emitter
	// PublishChange emits one AssetChange on hub.discover.asset.changed.
	PublishChange func(ctx context.Context, ch *model.AssetChange) error
	// PublishStatus asks the status reporter to re-emit the order status
	// (progress moves / finalization).
	PublishStatus func(ctx context.Context, orderID string)
	// Expand derives recursion tasks for a newly discovered in-scope domain
	// asset (doc 02 §2.4); nil ⇒ no recursion.
	Expand func(ctx context.Context, order *model.DiscoveryOrder, host string, depth int) error
	// ScopeFor resolves the order row (request + state) and its
	// gatekeeper-resolved effective scope (cached by the caller). Fail-closed:
	// an error retries later.
	ScopeFor func(ctx context.Context, orderID string) (order *model.DiscoveryOrder, state string, scope *sdkscope.Scope, err error)
	// MaxDPRetries — DP-ingest redeliveries before degrade-and-ack
	// (default 5).
	MaxDPRetries int
	Now          func() time.Time
	Log          *slog.Logger
}

// Reducer processes results messages.
type Reducer struct {
	d Deps
}

// New builds a Reducer.
func New(d Deps) *Reducer {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxDPRetries <= 0 {
		d.MaxDPRetries = 5
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Reducer{d: d}
}

// Process handles one discover.results message. deliveries is the JetStream
// NumDelivered counter (1 = first delivery).
func (r *Reducer) Process(ctx context.Context, msg *model.ResultMessage, deliveries uint64) Disposition {
	switch msg.Kind {
	case model.ResultDone:
		return r.processDone(ctx, msg)
	case model.ResultFinding:
		if msg.Finding == nil {
			return Ack // malformed — poison; do not loop
		}
		return r.processFinding(ctx, msg, deliveries)
	}
	return Ack
}

// processDone folds task-completion markers into order progress and
// finalizes the order when the DAG is accounted for.
func (r *Reducer) processDone(ctx context.Context, msg *model.ResultMessage) Disposition {
	deltas := map[string]int{}
	if msg.Error != "" {
		deltas["failed"] = 1
	} else {
		deltas["done"] = 1
	}
	if err := r.d.Store.IncrementProgress(ctx, msg.OrderID, deltas); err != nil {
		r.d.Log.Warn("progress update failed", "order_id", msg.OrderID, "error", err)
		return Retry
	}
	order, err := r.d.Store.GetOrder(ctx, msg.OrderID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Ack
		}
		return Retry
	}
	p := order.Progress
	if order.State == model.OrderRunning && p.TasksTotal > 0 && p.Done+p.Failed >= p.TasksTotal {
		state := model.OrderCompleted
		if p.Failed > 0 {
			state = model.OrderPartial
		}
		if err := r.d.Store.SetOrderState(ctx, msg.OrderID, state, nil); err != nil {
			return Retry
		}
		r.audit(ctx, msg.TenantID, auditfwd.ActionOrderFinalize, msg.OrderID, "", "", map[string]any{
			"order_id": msg.OrderID, "state": state,
			"tasks_total": p.TasksTotal, "failed": p.Failed,
		})
	}
	if r.d.PublishStatus != nil {
		r.d.PublishStatus(ctx, msg.OrderID)
	}
	return Ack
}

// processFinding is the §2.3 step-3 pipeline for one RawFinding.
func (r *Reducer) processFinding(ctx context.Context, msg *model.ResultMessage, deliveries uint64) Disposition {
	f := msg.Finding
	order, orderState, sc, err := r.d.ScopeFor(ctx, f.OrderID)
	if err != nil {
		r.d.Log.Warn("scope resolution failed (retrying)", "order_id", f.OrderID, "error", err)
		return Retry // fail-closed: no scope, no promotion
	}
	if order == nil {
		return Ack // unknown order — poison; drop
	}
	if orderState != model.OrderRunning && orderState != model.OrderPending {
		return Ack // terminal order (cancelled/finalized) — cooperative stop
	}

	// ---- scope re-check (doc 02 §4.2: quarantine, never promote) ----------
	if reason := scopeViolation(f.Asset, sc); reason != "" {
		return r.quarantine(ctx, order, f, reason)
	}

	// ---- dedup / merge against the working store ---------------------------
	rec, kind, changed, err := r.mergeAsset(ctx, order, f)
	if err != nil {
		r.d.Log.Warn("asset merge failed", "asset", f.Asset.Value, "error", err)
		return Retry
	}

	// ---- edge endpoints + edges --------------------------------------------
	var edgeAssets []model.AssetRecord
	var edgeRefs []model.EdgeRef
	for _, e := range msg.Edges {
		for _, endpoint := range []model.Asset{e.Src, e.Dst} {
			if reason := scopeViolation(endpoint, sc); reason != "" {
				continue
			}
			ep := &model.RawFinding{
				TaskID: f.TaskID, OrderID: f.OrderID, Asset: endpoint,
				Source: f.Source, ObservedAt: f.ObservedAt,
			}
			epRec, _, _, err := r.mergeAsset(ctx, order, ep)
			if err != nil {
				r.d.Log.Warn("edge endpoint merge failed", "asset", endpoint.Value, "error", err)
				continue
			}
			edgeAssets = append(edgeAssets, *epRec)
		}
		srcRec, serr := r.d.Store.GetAsset(ctx, order.TenantID, e.Src.Type, e.Src.Value)
		dstRec, derr := r.d.Store.GetAsset(ctx, order.TenantID, e.Dst.Type, e.Dst.Value)
		if serr != nil || derr != nil {
			continue
		}
		if err := r.d.Store.UpsertEdge(ctx, order.TenantID, srcRec.AssetID, dstRec.AssetID, e.Rel, r.d.Now().UTC()); err != nil {
			r.d.Log.Warn("edge upsert failed", "rel", e.Rel, "error", err)
			continue
		}
		edgeRefs = append(edgeRefs, e)
	}

	// ---- provenance (dedup on task+source+asset+observed bucket) -----------
	exists, err := r.d.Store.FindingExists(ctx, f.TaskID, f.Source, rec.AssetID, f.ObservedAt)
	if err != nil {
		return Retry
	}
	if !exists {
		if err := r.d.Store.InsertFinding(ctx, &store.FindingRow{
			TaskID: f.TaskID, OrderID: f.OrderID, TenantID: order.TenantID,
			AssetID: rec.AssetID, Source: f.Source, ObservedAt: f.ObservedAt.UTC(),
			EvidenceURI: f.EvidenceURI, ConfidenceHint: f.ConfidenceHint,
		}); err != nil {
			return Retry
		}
	}

	// ---- data platform upsert (Ruling C4 — system of record) ---------------
	if r.d.DP != nil {
		items := []dpingest.AssetItem{{Record: rec, Source: f.Source, EvidenceURI: f.EvidenceURI}}
		for i := range edgeAssets {
			items = append(items, dpingest.AssetItem{Record: &edgeAssets[i], Source: f.Source})
		}
		primary := string(rec.Type) + "|" + rec.Value
		if err := r.d.DP.UpsertBatch(ctx, order.TenantID, f.OrderID, f.TaskID, primary, items, edgeRefs); err != nil {
			if deliveries < uint64(r.d.MaxDPRetries) {
				r.d.Log.Warn("dp ingest failed (retrying)", "asset", rec.Value, "error", err)
				return Retry
			}
			// Degrade: the working store is committed; the DP gap is recorded
			// for replay tooling (doc 02 §7.2 queue-outage posture).
			r.audit(ctx, order.TenantID, auditfwd.ActionDPIngestFailure, f.OrderID, f.TaskID, order.Authorization.ROEID, map[string]any{
				"asset": rec.Value, "error": err.Error(),
			})
		}
	}

	// ---- AssetChange + progress ---------------------------------------------
	if kind != "" && r.d.PublishChange != nil {
		ch := &model.AssetChange{
			SchemaVersion: model.SchemaVersion,
			TenantID:      order.TenantID,
			AssetID:       rec.AssetID,
			Kind:          kind,
			Asset:         *rec,
			ChangedFields: changed,
			OrderID:       f.OrderID,
			EmittedAt:     r.d.Now().UTC(),
		}
		if err := r.d.PublishChange(ctx, ch); err != nil {
			r.d.Log.Warn("asset change publish failed", "asset", rec.Value, "error", err)
			return Retry
		}
	}
	deltas := map[string]int{"assets_found": 1}
	if kind == model.ChangeNew {
		deltas["new_assets"] = 1
	}
	if err := r.d.Store.IncrementProgress(ctx, f.OrderID, deltas); err != nil {
		r.d.Log.Warn("progress update failed", "order_id", f.OrderID, "error", err)
	}

	// ---- recursion (doc 02 §2.4) ---------------------------------------------
	if kind == model.ChangeNew && r.d.Expand != nil &&
		(rec.Type == model.AssetDomain || rec.Type == model.AssetSubdomain) &&
		rec.Attributes["wildcard"] != true {
		depth := depthOf(rec)
		if err := r.d.Expand(ctx, order, rec.Value, depth); err != nil {
			r.d.Log.Warn("expansion failed", "host", rec.Value, "error", err)
		}
	}
	return Ack
}

// quarantine drops an out-of-scope finding into quarantined_findings with a
// reason code (doc 02 §4.2) and audit-records it.
func (r *Reducer) quarantine(ctx context.Context, order *model.DiscoveryOrder, f *model.RawFinding, reason string) Disposition {
	if err := r.d.Store.InsertQuarantine(ctx, &store.QuarantineRow{
		TenantID: order.TenantID, OrderID: f.OrderID, Asset: f.Asset,
		Source: f.Source, ReasonCode: reason, ObservedAt: f.ObservedAt.UTC(),
	}); err != nil {
		return Retry
	}
	r.audit(ctx, order.TenantID, auditfwd.ActionQuarantine, f.OrderID, f.TaskID, order.Authorization.ROEID, map[string]any{
		"asset_type": string(f.Asset.Type), "asset_value": f.Asset.Value,
		"source": f.Source, "reason_code": reason,
	})
	return Ack
}

// mergeAsset upserts one finding's asset and reports the AssetChange kind
// ("" = no visible change) plus changed fields.
func (r *Reducer) mergeAsset(ctx context.Context, order *model.DiscoveryOrder, f *model.RawFinding) (*model.AssetRecord, string, []string, error) {
	observed := f.ObservedAt.UTC()
	if observed.IsZero() {
		observed = r.d.Now().UTC()
	}
	weight := model.SourceWeightOf(f.Source)
	if f.ConfidenceHint > weight {
		weight = f.ConfidenceHint
	}

	existing, err := r.d.Store.GetAsset(ctx, order.TenantID, f.Asset.Type, f.Asset.Value)
	if errors.Is(err, store.ErrNotFound) {
		rec := &model.AssetRecord{
			TenantID:   order.TenantID,
			Type:       f.Asset.Type,
			Value:      f.Asset.Value,
			Attributes: mergeAttributes(nil, f.Asset.Attributes, f.Source),
			Confidence: weight,
			FirstSeen:  observed,
			LastSeen:   observed,
			ROEID:      order.Authorization.ROEID,
		}
		rec.Status = model.StatusForConfidence(rec.Confidence)
		if err := r.d.Store.InsertAsset(ctx, rec); err != nil {
			return nil, "", nil, fmt.Errorf("insert asset: %w", err)
		}
		return rec, model.ChangeNew, nil, nil
	}
	if err != nil {
		return nil, "", nil, err
	}

	// Merge: attributes union, sources union, confidence recompute, last_seen.
	var changed []string
	newAttrs := mergeAttributes(existing.Attributes, f.Asset.Attributes, f.Source)
	if !reflect.DeepEqual(normalizeAttrs(existing.Attributes), normalizeAttrs(newAttrs)) {
		changed = append(changed, "attributes")
		existing.Attributes = newAttrs
	}
	sources, _ := existing.Attributes["sources"].([]any)
	weights := make([]float64, 0, len(sources))
	for _, s := range sources {
		if name, ok := s.(string); ok {
			weights = append(weights, model.SourceWeightOf(name))
		}
	}
	if len(weights) == 0 {
		weights = []float64{weight}
	}
	if conf := model.Confidence(weights); conf != existing.Confidence {
		changed = append(changed, "confidence")
		existing.Confidence = conf
	}
	kind := ""
	if existing.Status == model.AssetExpired {
		existing.Status = model.StatusForConfidence(existing.Confidence)
		changed = append(changed, "status")
		kind = model.ChangeReactivated
	} else if len(changed) > 0 {
		kind = model.ChangeAttributeChanged
	}
	if observed.After(existing.LastSeen) {
		existing.LastSeen = observed
	}
	if err := r.d.Store.UpdateAsset(ctx, existing); err != nil {
		return nil, "", nil, fmt.Errorf("update asset: %w", err)
	}
	return existing, kind, changed, nil
}

// mergeAttributes unions attribute maps (new wins per key) and maintains the
// "sources" provenance list (sorted union) that drives confidence
// corroboration (doc 02 §4.4).
func mergeAttributes(old, new map[string]any, source string) map[string]any {
	out := map[string]any{}
	for k, v := range old {
		out[k] = v
	}
	for k, v := range new {
		if k == "sources" {
			continue
		}
		out[k] = v
	}
	seen := map[string]bool{}
	var sources []string
	if old != nil {
		if list, ok := old["sources"].([]any); ok {
			for _, s := range list {
				if name, ok := s.(string); ok && !seen[name] {
					seen[name] = true
					sources = append(sources, name)
				}
			}
		}
	}
	if source != "" && !seen[source] {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	anySources := make([]any, len(sources))
	for i, s := range sources {
		anySources[i] = s
	}
	out["sources"] = anySources
	return out
}

// normalizeAttrs maps nil → empty for stable DeepEqual.
func normalizeAttrs(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// depthOf reads the recursion depth attribute (0 when absent).
func depthOf(rec *model.AssetRecord) int {
	if d, ok := rec.Attributes["depth"].(float64); ok {
		return int(d)
	}
	return 0
}

// scopeViolation returns the quarantine reason for an out-of-scope asset
// ("" = in scope). Exclusions always win (doc 02 §6.1).
func scopeViolation(a model.Asset, sc *sdkscope.Scope) string {
	if sc == nil {
		return store.ReasonOutOfScope // fail-closed
	}
	switch a.Type {
	case model.AssetDomain, model.AssetSubdomain, model.AssetIP, model.AssetNetblock:
		dec := sc.Evaluate(a.Value)
		if dec.Allowed {
			return ""
		}
		if dec.Excluded {
			return store.ReasonExcluded
		}
		return store.ReasonOutOfScope
	case model.AssetCloudResource:
		account := cloudAccount(a.Attributes)
		for _, ex := range sc.ExplicitExcludes {
			if ex == account || ex == a.Value {
				return store.ReasonExcluded
			}
		}
		for _, acct := range sc.CloudAccounts {
			if acct == account {
				return ""
			}
		}
		return store.ReasonOutOfScope
	case model.AssetCert:
		// Certs travel with their SANs: in scope iff at least one SAN is.
		sans, _ := a.Attributes["cert"].(map[string]any)["sans"].([]any)
		if len(sans) == 0 {
			return "" // no scope signal — allow (hosts carry the decision)
		}
		for _, s := range sans {
			if host, ok := s.(string); ok && sc.Evaluate(host).Allowed {
				return ""
			}
		}
		return store.ReasonOutOfScope
	}
	return store.ReasonOutOfScope
}

func cloudAccount(attrs map[string]any) string {
	cloud, _ := attrs["cloud"].(map[string]any)
	acct, _ := cloud["account"].(string)
	return acct
}

func (r *Reducer) audit(ctx context.Context, tenantID, action, target, taskID, roeID string, payload map[string]any) {
	if r.d.Audit == nil {
		return
	}
	payload["task_id"] = taskID
	payload["roe_id"] = roeID
	if err := r.d.Audit.Emit(ctx, auditfwd.Event{
		TenantID: tenantID, Action: action, Target: target,
		TaskID: taskID, ROEID: roeID, Payload: payload,
	}); err != nil {
		r.d.Log.Warn("audit emit failed", "action", action, "error", err)
	}
}

// OrderStatus decodes the stored order request (helper for callers).
func OrderStatus(row *store.OrderRow) (*model.OrderStatus, error) {
	var req model.DiscoveryOrder
	if err := json.Unmarshal(row.Request, &req); err != nil {
		return nil, err
	}
	st := &model.OrderStatus{
		OrderID:   row.OrderID,
		TenantID:  row.TenantID,
		State:     row.State,
		Progress:  row.Progress,
		StartedAt: row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if len(row.Gate) > 0 {
		var g model.Gate
		if err := json.Unmarshal(row.Gate, &g); err == nil {
			st.Gate = &g
		}
	}
	if st.State == model.OrderCompleted || st.State == model.OrderPartial ||
		st.State == model.OrderFailed || st.State == model.OrderCancelled || st.State == model.OrderDenied {
		st.FinishedAt = row.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return st, nil
}
