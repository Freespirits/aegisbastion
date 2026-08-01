// Package ingest implements the doc 09 §2.2 write path: validated, idempotent
// batches of assets/edges/findings from subordinate modules. One batch = one
// Postgres transaction keyed by the caller's idempotency key (retries are
// no-ops, doc 09 §8). Output of R1+ tasks re-verifies the gatekeeper Scope
// Token (defense in depth — dp never grants, Ruling B). Committed batches
// emit dp.* change events (doc 09 §2.2 step 4) and data-access audit records
// (doc 09 §4.4).
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/events"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/lifecycle"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/problem"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/scopeverify"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// Batch is one POST /v1/ingest/batch payload (also synthesized by the bus
// consumers — one ingest path for every write).
type Batch struct {
	IdempotencyKey string      `json:"idempotency_key"`
	TaskID         string      `json:"task_id,omitempty"`
	RiskClass      string      `json:"risk_class,omitempty"` // R1+ ⇒ scope_token mandatory
	ScopeToken     string      `json:"scope_token,omitempty"`
	Finalize       bool        `json:"finalize,omitempty"` // emit dp.task.rollup_finalized
	Assets         []AssetIn   `json:"assets,omitempty"`
	Edges          []EdgeIn    `json:"edges,omitempty"`
	Findings       []FindingIn `json:"findings,omitempty"`
	Targets        []string    `json:"targets,omitempty"`   // extra targets for the scope check
	TenantID       string      `json:"tenant_id,omitempty"` // must match the credential when present
	// Internal marks batches synthesized by the bus consumers (never decoded
	// from the wire): the REST-only Scope Token re-verification (doc 09 §2.2)
	// is skipped because bus events carry no token material — their
	// authorization was enforced at dispatch (PEP-1) and per-target by the
	// module SDKs (PEP-2), per Ruling B.
	Internal bool `json:"-"`
}

// AssetIn is one asset write item.
type AssetIn struct {
	Type        string         `json:"type"`
	Value       string         `json:"value"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Confidence  *float64       `json:"confidence,omitempty"`
	Status      string         `json:"status,omitempty"`
	RoeID       string         `json:"roe_id,omitempty"`
	FirstSeen   *time.Time     `json:"first_seen,omitempty"`
	LastSeen    *time.Time     `json:"last_seen,omitempty"`
	Source      string         `json:"source,omitempty"` // provenance, e.g. "crt.sh"
	EvidenceURI string         `json:"evidence_uri,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
}

// EdgeIn is one edge write item; endpoints reference assets by asset_id or
// (type, value).
type EdgeIn struct {
	SrcAssetID string         `json:"src_asset_id,omitempty"`
	SrcType    string         `json:"src_type,omitempty"`
	SrcValue   string         `json:"src_value,omitempty"`
	DstAssetID string         `json:"dst_asset_id,omitempty"`
	DstType    string         `json:"dst_type,omitempty"`
	DstValue   string         `json:"dst_value,omitempty"`
	Rel        string         `json:"rel"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// FindingIn is one finding write item.
type FindingIn struct {
	FindingID   string         `json:"finding_id,omitempty"`
	AssetUID    string         `json:"asset_uid,omitempty"`
	AssetType   string         `json:"asset_type,omitempty"`
	AssetValue  string         `json:"asset_value,omitempty"`
	Module      string         `json:"module"`
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	State       string         `json:"state,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Validation  map[string]any `json:"validation,omitempty"`
	Risk        map[string]any `json:"risk,omitempty"`
	EvidenceRef string         `json:"evidence_ref,omitempty"`
	Occurrence  int            `json:"occurrence,omitempty"`
	FirstSeen   *time.Time     `json:"first_seen,omitempty"`
	LastSeen    *time.Time     `json:"last_seen,omitempty"`
	TaskID      string         `json:"task_id,omitempty"`
	Compliance  map[string]any `json:"compliance,omitempty"`
	Sensitive   bool           `json:"sensitive,omitempty"`
	LegalHold   bool           `json:"legal_hold,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
}

// Counts are the per-batch outcome counters (persisted in ingest_batches).
type Counts struct {
	AssetsUpserted   int `json:"assets_upserted"`
	AssetsCreated    int `json:"assets_created"`
	EdgesUpserted    int `json:"edges_upserted"`
	FindingsInserted int `json:"findings_inserted"`
	FindingsMerged   int `json:"findings_merged"`
	StateChanges     int `json:"state_changes"`
}

// Result is the ingest acknowledgement.
type Result struct {
	IdempotencyKey string `json:"idempotency_key"`
	Replay         bool   `json:"replay"` // true when the key was already applied
	Status         string `json:"status"` // accepted | rejected (ledger state)
	TaskID         string `json:"task_id,omitempty"`
	ScopeTokenJTI  string `json:"scope_token_jti,omitempty"`
	Counts         Counts `json:"counts"`
}

// Engine applies batches. Same code path serves the REST ingest endpoint and
// the JetStream consumers.
type Engine struct {
	st       *store.Store
	verifier *scopeverify.Verifier // nil ⇒ token checks disabled (tests only)
	ev       *events.Publisher
	log      *slog.Logger
}

// New builds an Engine.
func New(st *store.Store, verifier *scopeverify.Verifier, ev *events.Publisher, log *slog.Logger) *Engine {
	return &Engine{st: st, verifier: verifier, ev: ev, log: log}
}

// Apply validates and applies one batch under the caller's TPEL identity.
// Fail-closed throughout; every rejection is audit-logged and ledgered.
func (e *Engine) Apply(ctx context.Context, actor store.Actor, tenantID string, b *Batch) (*Result, *problem.Problem) {
	// ---- schema validation (doc 09 §12: SCHEMA_INVALID) -------------------
	if prob := e.validate(b); prob != nil {
		e.reject(ctx, actor, tenantID, b, prob)
		return nil, prob
	}
	// ---- tenant binding (payload never overrides the credential) ----------
	if prob := bindTenant(tenantID, b); prob != nil {
		e.reject(ctx, actor, tenantID, b, prob)
		return nil, prob
	}
	// ---- Scope Token re-verification (doc 09 §2.2/§9.1) --------------------
	var jti string
	if e.verifier != nil && !b.Internal {
		claims, prob := e.reverify(ctx, b)
		if prob != nil {
			e.reject(ctx, actor, tenantID, b, prob)
			return nil, prob
		}
		if claims != nil {
			jti = claims.JTI
			if b.TaskID == "" {
				b.TaskID = claims.Claims.TaskID
			}
		}
	}

	// ---- idempotency + application (one tx) -------------------------------
	tx, err := e.st.Pool.Begin(ctx)
	if err != nil {
		return nil, problem.Internal("begin tx: " + err.Error())
	}
	defer func() { _ = tx.Rollback(ctx) }()

	fresh, err := store.BeginBatchTx(ctx, tx, tenantID, b.IdempotencyKey, b.TaskID, jti)
	if err != nil {
		return nil, problem.Internal("idempotency ledger: " + err.Error())
	}
	if !fresh {
		_ = tx.Rollback(ctx)
		rec, gerr := e.st.GetBatch(ctx, b.IdempotencyKey)
		if gerr != nil || rec == nil {
			return nil, problem.Internal("idempotency replay lookup: " + fmt.Sprint(gerr))
		}
		if rec.TenantID != tenantID {
			// Same key under a different tenant: never reveal the other
			// tenant's outcome (fail-closed).
			return nil, problem.Mismatch("idempotency_key was used under a different tenant")
		}
		return &Result{
			IdempotencyKey: rec.IdempotencyKey,
			Replay:         true,
			Status:         rec.Status,
			TaskID:         rec.TaskID,
			ScopeTokenJTI:  rec.ScopeTokenJTI,
			Counts:         countsFromMap(rec.Counts),
		}, nil
	}

	res := &Result{IdempotencyKey: b.IdempotencyKey, Status: "accepted", TaskID: b.TaskID, ScopeTokenJTI: jti}
	var evs []events.Event
	now := time.Now().UTC()

	for i := range b.Assets {
		a := &b.Assets[i]
		out, err := store.UpsertAssetTx(ctx, tx, tenantID, store.AssetUpsert{
			Type: a.Type, Value: a.Value, Attributes: a.Attributes,
			Confidence: derefConfidence(a.Confidence), Status: a.Status, RoeID: a.RoeID,
			FirstSeen: derefTime(a.FirstSeen), LastSeen: derefTime(a.LastSeen),
			Source: a.Source, TaskID: b.TaskID, EvidenceURI: a.EvidenceURI,
		})
		if err != nil {
			return nil, problem.Internal("asset upsert: " + err.Error())
		}
		res.Counts.AssetsUpserted++
		etype := events.TypeAssetAttributeChanged
		subj := events.SubjectAssetAttributeChanged
		if out.Created {
			res.Counts.AssetsCreated++
			etype = events.TypeAssetCreated
			subj = events.SubjectAssetCreated
		}
		evs = append(evs, events.Event{
			Type: etype, Subject: subj, TenantID: tenantID,
			ObjectRef: "asset/" + out.AssetID,
			Data: map[string]any{
				"asset_id": out.AssetID, "asset_type": a.Type, "value": a.Value,
				"task_id": b.TaskID, "occurred_at": now.Format(time.RFC3339Nano),
			},
		})
	}
	for i := range b.Edges {
		eg := &b.Edges[i]
		if _, err := store.UpsertEdgeTx(ctx, tx, tenantID, store.EdgeUpsert{
			SrcAssetID: eg.SrcAssetID, SrcType: eg.SrcType, SrcValue: eg.SrcValue,
			DstAssetID: eg.DstAssetID, DstType: eg.DstType, DstValue: eg.DstValue,
			Rel: eg.Rel, Attributes: eg.Attributes,
		}); err != nil {
			return nil, problem.Invalid("edge: " + err.Error())
		}
		res.Counts.EdgesUpserted++
	}
	for i := range b.Findings {
		f := &b.Findings[i]
		taskID := f.TaskID
		if taskID == "" {
			taskID = b.TaskID
		}
		out, err := store.UpsertFindingTx(ctx, tx, tenantID, store.FindingUpsert{
			FindingID: f.FindingID, AssetUID: f.AssetUID,
			AssetType: f.AssetType, AssetValue: f.AssetValue,
			Module: f.Module, CheckID: f.CheckID, Title: f.Title,
			Severity: f.Severity, State: f.State, Fingerprint: f.Fingerprint,
			Validation: f.Validation, Risk: f.Risk, EvidenceRef: f.EvidenceRef,
			Occurrence: f.Occurrence, FirstSeen: derefTime(f.FirstSeen),
			LastSeen: derefTime(f.LastSeen), TaskID: taskID,
			Compliance: f.Compliance, Sensitive: f.Sensitive, LegalHold: f.LegalHold,
		}, actor, advance)
		if err != nil {
			return nil, problem.Internal("finding upsert: " + err.Error())
		}
		if out.Created {
			res.Counts.FindingsInserted++
			sev, _ := f.Risk["score"].(float64)
			evs = append(evs, events.Event{
				Type: events.TypeFindingCreated, Subject: events.SubjectFindingCreated,
				TenantID: tenantID, ObjectRef: "finding/" + out.FindingID,
				Data: map[string]any{
					"finding_id": out.FindingID, "asset_ref": f.AssetType + ":" + f.AssetValue,
					"asset_uid": out.AssetUID, "severity": f.Severity,
					"validation": f.Validation, "risk_score": sev,
					"task_id": taskID, "occurred_at": now.Format(time.RFC3339Nano),
				},
			})
		} else {
			res.Counts.FindingsMerged++
		}
		if out.StateChanged {
			res.Counts.StateChanges++
			evs = append(evs, events.Event{
				Type: events.TypeFindingStateChanged, Subject: events.SubjectFindingStateChanged,
				TenantID: tenantID, ObjectRef: "finding/" + out.FindingID,
				Data: map[string]any{
					"finding_id": out.FindingID, "from_state": out.FromState,
					"to_state": out.ToState, "task_id": taskID,
					"occurred_at": now.Format(time.RFC3339Nano),
				},
			})
		}
		if out.IllegalSkipped && e.log != nil {
			e.log.Warn("finding state proposal unreachable; kept current state",
				"finding", out.FindingID, "proposed", f.State)
		}
	}

	if err := store.FinishBatchTx(ctx, tx, b.IdempotencyKey, countsToMap(res.Counts)); err != nil {
		return nil, problem.Internal("finish batch: " + err.Error())
	}
	if err := store.AuditOutboxTx(ctx, tx, store.AuditRecord{
		TenantID: tenantID, Actor: actor, Action: "ingest.batch",
		ObjectRef:  "batch/" + b.IdempotencyKey,
		ParamsHash: paramsHash(b),
	}); err != nil {
		return nil, problem.Internal("audit outbox: " + err.Error())
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, problem.Internal("commit: " + err.Error())
	}

	// ---- post-commit change events (doc 09 §2.2 step 4) -------------------
	for _, ev := range evs {
		if err := e.ev.Publish(ctx, ev); err != nil && e.log != nil {
			e.log.Error("change event publish failed", "type", ev.Type, "err", err)
		}
	}
	if b.Finalize && b.TaskID != "" {
		e.emitRollupFinalized(ctx, tenantID, b.TaskID, now)
	}
	return res, nil
}

// reject ledgers + audits a rejected batch (doc 09 §2.2: rejected ingests
// are forwarded as audit events).
func (e *Engine) reject(ctx context.Context, actor store.Actor, tenantID string, b *Batch, prob *problem.Problem) {
	key := b.IdempotencyKey
	if key == "" {
		key = "unkeyed-" + store.NewUUIDv7()
	}
	if err := e.st.RejectBatch(ctx, tenantID, key, b.TaskID, prob.Reason); err != nil && e.log != nil {
		e.log.Warn("reject ledger failed", "err", err)
	}
	if err := e.st.AuditOutbox(ctx, store.AuditRecord{
		TenantID: tenantID, Actor: actor, Action: "ingest.rejected",
		ObjectRef: "batch/" + key, ParamsHash: paramsHash(b),
	}); err != nil && e.log != nil {
		e.log.Error("audit outbox write failed for rejected ingest", "err", err)
	}
}

// validate enforces the batch schema (doc 09 §12 SCHEMA_INVALID).
func (e *Engine) validate(b *Batch) *problem.Problem {
	if strings.TrimSpace(b.IdempotencyKey) == "" {
		return problem.Invalid("idempotency_key is required")
	}
	if len(b.IdempotencyKey) > 200 {
		return problem.Invalid("idempotency_key exceeds 200 characters")
	}
	if len(b.Assets)+len(b.Edges)+len(b.Findings) == 0 {
		return problem.Invalid("batch carries no assets, edges or findings")
	}
	switch b.RiskClass {
	case "", "R0", "R1", "R2", "R3":
	default:
		return problem.Invalid("risk_class must be one of R0|R1|R2|R3")
	}
	for i := range b.Assets {
		a := &b.Assets[i]
		if !oneOf(a.Type, store.AssetKinds) {
			return problem.Invalid(fmt.Sprintf("assets[%d].type %q not in %v", i, a.Type, store.AssetKinds))
		}
		cv, err := CanonicalizeAssetValue(a.Type, a.Value)
		if err != nil {
			return problem.Invalid(fmt.Sprintf("assets[%d].value: %v", i, err))
		}
		a.Value = cv
		switch a.Status {
		case "", store.StatusActive, store.StatusCandidate, store.StatusExpired, store.StatusQuarantined:
		default:
			return problem.Invalid(fmt.Sprintf("assets[%d].status %q invalid", i, a.Status))
		}
		if a.Confidence != nil && (*a.Confidence < 0 || *a.Confidence > 1) {
			return problem.Invalid(fmt.Sprintf("assets[%d].confidence must be in [0,1]", i))
		}
	}
	for i := range b.Edges {
		eg := &b.Edges[i]
		if strings.TrimSpace(eg.Rel) == "" {
			return problem.Invalid(fmt.Sprintf("edges[%d].rel is required", i))
		}
		if eg.SrcAssetID == "" && (eg.SrcType == "" || eg.SrcValue == "") {
			return problem.Invalid(fmt.Sprintf("edges[%d]: src needs asset_id or (type,value)", i))
		}
		if eg.DstAssetID == "" && (eg.DstType == "" || eg.DstValue == "") {
			return problem.Invalid(fmt.Sprintf("edges[%d]: dst needs asset_id or (type,value)", i))
		}
		if eg.SrcType != "" {
			cv, err := CanonicalizeAssetValue(eg.SrcType, eg.SrcValue)
			if err != nil {
				return problem.Invalid(fmt.Sprintf("edges[%d].src: %v", i, err))
			}
			eg.SrcValue = cv
		}
		if eg.DstType != "" {
			cv, err := CanonicalizeAssetValue(eg.DstType, eg.DstValue)
			if err != nil {
				return problem.Invalid(fmt.Sprintf("edges[%d].dst: %v", i, err))
			}
			eg.DstValue = cv
		}
	}
	for i := range b.Findings {
		f := &b.Findings[i]
		if !oneOf(f.Module, store.FindingModules) {
			return problem.Invalid(fmt.Sprintf("findings[%d].module %q not in %v", i, f.Module, store.FindingModules))
		}
		if !oneOf(f.Severity, store.Severities) {
			return problem.Invalid(fmt.Sprintf("findings[%d].severity %q not in %v", i, f.Severity, store.Severities))
		}
		if strings.TrimSpace(f.CheckID) == "" || strings.TrimSpace(f.Title) == "" {
			return problem.Invalid(fmt.Sprintf("findings[%d]: check_id and title are required", i))
		}
		if f.AssetUID == "" && (f.AssetType == "" || f.AssetValue == "") {
			return problem.Invalid(fmt.Sprintf("findings[%d]: asset needs asset_uid or (asset_type,asset_value)", i))
		}
		if f.AssetType != "" {
			cv, err := CanonicalizeAssetValue(f.AssetType, f.AssetValue)
			if err != nil {
				return problem.Invalid(fmt.Sprintf("findings[%d].asset_value: %v", i, err))
			}
			f.AssetValue = cv
		}
		if f.State != "" {
			if _, err := lifecycle.Parse(f.State); err != nil {
				return problem.Invalid(fmt.Sprintf("findings[%d].state: %v", i, err))
			}
		}
		if f.FindingID != "" {
			if _, err := parseUUID(f.FindingID); err != nil {
				return problem.Invalid(fmt.Sprintf("findings[%d].finding_id: %v", i, err))
			}
		}
	}
	return nil
}

// bindTenant enforces "tenant from credential, never from payload"
// (doc 09 §2.2): any payload tenant_id must match the resolved tenant.
func bindTenant(tenantID string, b *Batch) *problem.Problem {
	if b.TenantID != "" && !strings.EqualFold(b.TenantID, tenantID) {
		return problem.Mismatch(fmt.Sprintf("batch tenant_id %s ≠ credential tenant %s", b.TenantID, tenantID))
	}
	for i := range b.Assets {
		if t := b.Assets[i].TenantID; t != "" && !strings.EqualFold(t, tenantID) {
			return problem.Mismatch(fmt.Sprintf("assets[%d].tenant_id %s ≠ credential tenant %s", i, t, tenantID))
		}
	}
	for i := range b.Findings {
		if t := b.Findings[i].TenantID; t != "" && !strings.EqualFold(t, tenantID) {
			return problem.Mismatch(fmt.Sprintf("findings[%d].tenant_id %s ≠ credential tenant %s", i, t, tenantID))
		}
	}
	return nil
}

// reverify runs the doc 09 §2.2 defense-in-depth Scope Token check.
func (e *Engine) reverify(ctx context.Context, b *Batch) (*scopeverify.Result, *problem.Problem) {
	tokenRequired := b.RiskClass == "R1" || b.RiskClass == "R2" || b.RiskClass == "R3"
	for i := range b.Findings {
		if store.OffensiveModules[b.Findings[i].Module] {
			tokenRequired = true
			break
		}
	}
	if b.ScopeToken == "" && !tokenRequired {
		return nil, nil // R0 passive ingest (doc 09 §8: continues on service creds)
	}
	targets := make([]string, 0, len(b.Targets)+len(b.Findings)+len(b.Assets))
	targets = append(targets, b.Targets...)
	// The scope check covers exactly what the batch touches: finding asset
	// references, explicit targets, and (when the batch writes them) assets.
	for i := range b.Findings {
		if v := b.Findings[i].AssetValue; v != "" {
			targets = append(targets, v)
		}
	}
	for i := range b.Assets {
		targets = append(targets, b.Assets[i].Value)
	}
	res, err := e.verifier.Verify(ctx, b.ScopeToken, b.TaskID, targets)
	if err != nil {
		return nil, problem.Unverifiable(fmt.Sprintf(
			"batch references R1+ task %q but the presented token failed verification: %v",
			b.TaskID, err))
	}
	return res, nil
}

// emitRollupFinalized publishes dp.task.rollup_finalized (doc 09 §3.2).
func (e *Engine) emitRollupFinalized(ctx context.Context, tenantID, taskID string, now time.Time) {
	r, err := e.st.Rollup(ctx, tenantID, taskID)
	if err != nil || r == nil {
		if e.log != nil && err != nil {
			e.log.Warn("rollup compute failed", "task", taskID, "err", err)
		}
		return
	}
	data, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	m["occurred_at"] = now.Format(time.RFC3339Nano)
	if err := e.ev.Publish(ctx, events.Event{
		Type: events.TypeTaskRollupFinalized, Subject: events.SubjectTaskRollupFinalized,
		TenantID: tenantID, ObjectRef: "task/" + taskID, Data: m,
	}); err != nil && e.log != nil {
		e.log.Error("rollup_finalized publish failed", "task", taskID, "err", err)
	}
}

// advance bridges store's hop callback to the lifecycle package.
func advance(from, to string) ([]string, bool) {
	p, ok := lifecycle.Path(lifecycle.State(from), lifecycle.State(to))
	if !ok {
		return nil, false
	}
	out := make([]string, len(p))
	for i, s := range p {
		out[i] = string(s)
	}
	return out, true
}

// CanonicalizeAssetValue normalizes an asset value per doc 02 §4.2
// (punycode-lowercase domains without trailing dot; canonical IPs; masked
// CIDRs; lowercase cert hashes).
func CanonicalizeAssetValue(typ, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("empty value")
	}
	switch typ {
	case store.AssetDomain, store.AssetSubdomain:
		v = strings.TrimPrefix(strings.ToLower(v), "*.")
		v = strings.TrimSuffix(v, ".")
		if v == "" || strings.ContainsAny(v, "/ @") {
			return "", fmt.Errorf("invalid domain %q", value)
		}
		return v, nil
	case store.AssetIP:
		ip, err := netip.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("invalid ip %q", value)
		}
		return ip.String(), nil
	case store.AssetNetblock:
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("invalid netblock %q", value)
		}
		return p.Masked().String(), nil
	case store.AssetCert:
		return strings.ToLower(v), nil
	default:
		return v, nil // cloud_resource: arn/resource-id verbatim
	}
}

// paramsHash hashes the canonical batch params for the audit record
// (doc 09 §4.4 params_hash).
func paramsHash(b *Batch) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	// ScopeToken is credential material: hash its presence via jti-sized
	// length only, never the raw token.
	safe := *b
	safe.ScopeToken = ""
	if b.ScopeToken != "" {
		safe.ScopeToken = fmt.Sprintf("<present:%d bytes>", len(b.ScopeToken))
	}
	_ = enc.Encode(safe)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func countsToMap(c Counts) map[string]int {
	return map[string]int{
		"assets_upserted": c.AssetsUpserted, "assets_created": c.AssetsCreated,
		"edges_upserted": c.EdgesUpserted, "findings_inserted": c.FindingsInserted,
		"findings_merged": c.FindingsMerged, "state_changes": c.StateChanges,
	}
}

func countsFromMap(m map[string]int) Counts {
	return Counts{
		AssetsUpserted:   m["assets_upserted"],
		AssetsCreated:    m["assets_created"],
		EdgesUpserted:    m["edges_upserted"],
		FindingsInserted: m["findings_inserted"],
		FindingsMerged:   m["findings_merged"],
		StateChanges:     m["state_changes"],
	}
}

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func derefConfidence(c *float64) float64 {
	if c == nil {
		return 0.5
	}
	return *c
}

func parseUUID(s string) (string, error) {
	if len(s) != 36 {
		return "", fmt.Errorf("not a UUID: %q", s)
	}
	return s, nil
}
