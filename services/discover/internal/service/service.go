// Package service is the discover-orchestrator's order service layer (doc 02
// §2.2 order-intake/authz-precheck/planner/queue-producer/status-reporter +
// §6.5 kill switch). The REST surface (http.go) and the MCP surface (mcp.go)
// both wrap this layer — no logic forks (doc 02 §9).
//
// Authorization posture (Ruling B): gatekeeper is the single PDP. Intake
// calls policy-service.Authorize fail-closed per technique (PEP-1-style
// re-check); Discover mints nothing. Orders denied by gatekeeper persist as
// DENIED with its reason codes; gatekeeper unreachable ⇒ intake fails closed
// (doc 02 §7.2).
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/pepclient"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/planner"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/reducer"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// Sentinel errors mapped onto HTTP statuses by the REST layer.
var (
	// ErrValidation — malformed order (400).
	ErrValidation = errors.New("validation failed")
	// ErrDenied — gatekeeper denied every requested technique (403).
	ErrDenied = errors.New("order denied by gatekeeper")
	// ErrGatekeeperDown — intake fails closed (502, doc 02 §7.2).
	ErrGatekeeperDown = errors.New("gatekeeper unreachable — intake fails closed")
	// ErrIntakePaused — audit spool full; R1+ intake pauses (503, doc 02 §6.4).
	ErrIntakePaused = errors.New("audit spool full — R1+ intake paused")
	// ErrNotFound — unknown order (404).
	ErrNotFound = store.ErrNotFound
	// ErrConflict — invalid state transition (409).
	ErrConflict = errors.New("invalid state for this operation")
)

// Deps wires the Service.
type Deps struct {
	Store   *store.Store
	PEP     *pepclient.Client
	Planner *planner.Planner
	JS      nats.JetStreamContext
	Audit   *auditfwd.Emitter
	// Revoker — gatekeeper revocation-service (admin tenant disable, doc 02
	// §6.5); nil ⇒ disable is unavailable.
	Revoker       gatekeeperv1.RevocationServiceClient
	AuditSpoolMax int64
	Now           func() time.Time
	Log           *slog.Logger
}

// Service is the order service layer.
type Service struct {
	d Deps

	mu         sync.Mutex
	scopeCache map[string]*scopeEntry // roe_id → cached resolved scope
}

type scopeEntry struct {
	res       *pepclient.ResolvedROE
	fetchedAt time.Time
}

// scopeCacheTTL bounds staleness of the gatekeeper-resolved scope mirror
// (doc 02 §6.1: consumed read-only; revocation propagates on the bus).
const scopeCacheTTL = 60 * time.Second

// New builds the Service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Service{d: d, scopeCache: map[string]*scopeEntry{}}
}

// ---------------------------------------------------------------------------
// Order intake (doc 02 §2.3 step 1)
// ---------------------------------------------------------------------------

// SubmitOrder validates, gate-checks, persists, plans, and dispatches one
// DiscoveryOrder. The returned OrderStatus reflects the persisted record;
// ErrDenied / ErrGatekeeperDown / ErrValidation / ErrIntakePaused classify
// the failure for the caller.
func (s *Service) SubmitOrder(ctx context.Context, order *model.DiscoveryOrder) (*model.OrderStatus, error) {
	order.ApplyDefaults()
	if err := order.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	order.OrderID = uuid.NewString()

	// Audit spool fail-closed: spool full ⇒ R1+ intake pauses (doc 02 §6.4).
	requestsR1 := false
	for _, t := range order.Techniques {
		if t.Active() {
			requestsR1 = true
			break
		}
	}
	if requestsR1 {
		paused, n, err := s.d.Audit.IntakePaused(ctx, s.d.AuditSpoolMax)
		if err != nil || paused {
			return nil, fmt.Errorf("%w (unforwarded=%d, err=%v)", ErrIntakePaused, n, err)
		}
	}

	s.audit(ctx, order.TenantID, auditfwd.ActionOrderSubmit, order.OrderID, order.Authorization.ROEID, map[string]any{
		"order_id":   order.OrderID,
		"commander":  order.RequestedBy.Commander,
		"agent_id":   order.RequestedBy.AgentID,
		"seeds":      len(order.Seeds),
		"techniques": order.Techniques,
	})

	// Resolve the gatekeeper RoE (effective scope + version) — fail-closed.
	roe, err := s.resolveROE(ctx, order.Authorization.ROEID, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatekeeperDown, err)
	}

	// PEP-1-style pre-check per technique (doc 02 §2.2 authz-precheck).
	seedValues := make([]string, 0, len(order.Seeds))
	for _, sd := range order.Seeds {
		seedValues = append(seedValues, sd.Value)
	}
	allowed := map[model.Technique]bool{}
	riskClass := "R0"
	var reasons []string
	var decisionID, decidedAt string
	for _, t := range order.Techniques {
		if t.Active() {
			// Accepted in schema, not implemented at MVP (doc 02 §8).
			reasons = appendUnique(reasons, model.ReasonActiveNotAllowed+": "+string(t))
			continue
		}
		dec, err := s.d.PEP.AuthorizeTechnique(ctx, order, t, roe.Version, seedValues)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatekeeperDown, err)
		}
		if dec.Allowed {
			allowed[t] = true
			if decisionID == "" {
				decisionID = dec.Gate.DecisionID
				decidedAt = dec.Gate.DecidedAt
			}
			if dec.RiskClass != "" {
				riskClass = dec.RiskClass
			}
		} else {
			for _, r := range dec.Gate.Reasons {
				reasons = appendUnique(reasons, string(t)+": "+r)
			}
			if decisionID == "" {
				decisionID = dec.Gate.DecisionID
				decidedAt = dec.Gate.DecidedAt
			}
		}
	}

	gate := model.Gate{
		Decision:   "allow",
		Reasons:    reasons,
		ROEID:      order.Authorization.ROEID,
		DecisionID: decisionID,
		DecidedAt:  decidedAt,
	}

	// Persist the order (PENDING; DENIED when nothing was allowed).
	requestJSON, err := json.Marshal(order)
	if err != nil {
		return nil, err
	}
	state := model.OrderPending
	if len(allowed) == 0 {
		gate.Decision = "deny"
		state = model.OrderDenied
	}
	if err := s.d.Store.InsertOrder(ctx, &store.OrderRow{
		OrderID:  order.OrderID,
		TenantID: order.TenantID,
		Request:  requestJSON,
		State:    state,
		Progress: model.Progress{},
	}); err != nil {
		return nil, fmt.Errorf("persist order: %w", err)
	}
	if err := s.d.Store.SetOrderGate(ctx, order.OrderID, gate); err != nil {
		return nil, fmt.Errorf("persist gate: %w", err)
	}
	s.audit(ctx, order.TenantID, auditfwd.ActionGateDecision, order.OrderID, order.Authorization.ROEID, map[string]any{
		"order_id":    order.OrderID,
		"decision":    gate.Decision,
		"decision_id": gate.DecisionID,
		"reasons":     gate.Reasons,
	})

	if state == model.OrderDenied {
		st := s.statusFromParts(order, model.OrderDenied, &gate, model.Progress{}, true)
		s.publishStatus(ctx, st)
		return st, ErrDenied
	}

	// Plan + dispatch.
	plan := s.d.Planner.Plan(order, roe.Scope, riskClass)
	for seed, reason := range plan.RejectedSeeds {
		s.d.Log.Warn("seed rejected by planner scope check", "seed", seed, "reason", reason)
	}
	for _, r := range plan.Reasons {
		gate.Reasons = appendUnique(gate.Reasons, r)
	}
	_ = s.d.Store.SetOrderGate(ctx, order.OrderID, gate)

	tasks := filterAllowed(plan.Tasks, allowed)
	if err := s.d.Store.SetProgressTotal(ctx, order.OrderID, len(tasks)); err != nil {
		return nil, err
	}
	if err := s.d.Store.SetOrderState(ctx, order.OrderID, model.OrderRunning, nil); err != nil {
		return nil, err
	}
	dispatched := 0
	for _, t := range tasks {
		if err := queue.PublishTask(ctx, s.d.JS, t); err != nil {
			return nil, fmt.Errorf("dispatch task %s: %w", t.TaskID, err)
		}
		dispatched++
		s.audit(ctx, order.TenantID, auditfwd.ActionTaskDispatch, t.TaskID, order.Authorization.ROEID, map[string]any{
			"order_id": order.OrderID, "task_id": t.TaskID,
			"technique": string(t.Technique), "source": t.Source,
			"seed": t.Seed.Value, "token_jti": "",
		})
	}

	// Zero-task orders finalize immediately (all seeds unsupported/rejected).
	finalState := model.OrderRunning
	finished := false
	if len(tasks) == 0 {
		finalState = model.OrderCompleted
		finished = true
		if err := s.d.Store.SetOrderState(ctx, order.OrderID, finalState, nil); err != nil {
			return nil, err
		}
	}
	st := s.statusFromParts(order, finalState, &gate, model.Progress{TasksTotal: len(tasks)}, finished)
	s.publishStatus(ctx, st)
	s.d.Log.Info("order accepted", "order_id", order.OrderID, "tasks", dispatched,
		"rejected_seeds", len(plan.RejectedSeeds), "dropped_active", len(plan.DroppedActive))
	return st, nil
}

func filterAllowed(tasks []model.Task, allowed map[model.Technique]bool) []model.Task {
	out := tasks[:0]
	for _, t := range tasks {
		if allowed[t.Technique] {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Status / assets reads (doc 02 §3.1)
// ---------------------------------------------------------------------------

// GetStatus returns the persisted order status.
func (s *Service) GetStatus(ctx context.Context, orderID string) (*model.OrderStatus, error) {
	row, err := s.d.Store.GetOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}
	return reducer.OrderStatus(row)
}

// ListOrderAssets pages assets attributed to an order.
func (s *Service) ListOrderAssets(ctx context.Context, orderID, cursor string, limit int) ([]model.AssetRecord, string, error) {
	return s.d.Store.ListOrderAssets(ctx, orderID, cursor, limit)
}

// ListAssets is the tenant-scoped working-store read API (fresh path for
// Monitor, doc 02 §3.1).
func (s *Service) ListAssets(ctx context.Context, q store.AssetQuery) ([]model.AssetRecord, string, error) {
	return s.d.Store.ListAssets(ctx, q)
}

// ---------------------------------------------------------------------------
// Cancel + kill switch (doc 02 §3.1, §6.5)
// ---------------------------------------------------------------------------

// Cancel cooperatively stops an order: the state flip halts new expansion
// and workers skip queued tasks of terminal orders; in-flight tasks run out
// (doc 02 §3.1 cancel semantics). Audit + status event follow.
func (s *Service) Cancel(ctx context.Context, orderID string) (*model.OrderStatus, error) {
	row, err := s.d.Store.GetOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}
	switch row.State {
	case model.OrderPending, model.OrderRunning:
	default:
		return nil, fmt.Errorf("%w: order is %s", ErrConflict, row.State)
	}
	if err := s.d.Store.SetOrderState(ctx, orderID, model.OrderCancelled, nil); err != nil {
		return nil, err
	}
	var order model.DiscoveryOrder
	_ = json.Unmarshal(row.Request, &order)
	s.audit(ctx, row.TenantID, auditfwd.ActionOrderCancel, orderID, order.Authorization.ROEID, map[string]any{
		"order_id": orderID, "previous_state": row.State,
	})
	st, err := s.GetStatus(ctx, orderID)
	if err != nil {
		return nil, err
	}
	s.publishStatus(ctx, st)
	return st, nil
}

// DisableTenant drains this module's work for one tenant THROUGH gatekeeper
// (doc 02 §6.5): a revocation per active RoE (gatekeeper's revocation scopes
// are global/roe/target/capability — per-RoE is its finest module-relevant
// form; the halt is recorded in the audit of record). Platform-admin only —
// enforced by the caller's edge authz, recorded here.
func (s *Service) DisableTenant(ctx context.Context, tenantID, actor string) (int, error) {
	if s.d.Revoker == nil {
		return 0, fmt.Errorf("revocation-service not configured")
	}
	running, err := s.d.Store.ListOrdersByState(ctx, model.OrderRunning, tenantID)
	if err != nil {
		return 0, err
	}
	roes := map[string]bool{}
	for _, row := range running {
		var order model.DiscoveryOrder
		if err := json.Unmarshal(row.Request, &order); err != nil {
			continue
		}
		roes[order.Authorization.ROEID] = true
	}
	issued := 0
	for roeID := range roes {
		_, err := s.d.Revoker.Revoke(ctx, &gatekeeperv1.RevokeRequest{
			Scope:     gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
			Key:       roeID,
			IssuedBy:  actor,
			Reason:    "discover:disable for tenant " + tenantID,
			ExpiresAt: timestamppb.New(s.d.Now().UTC().Add(24 * time.Hour)),
		})
		if err != nil {
			return issued, fmt.Errorf("revoke roe %s: %w", roeID, err)
		}
		issued++
	}
	s.audit(ctx, tenantID, auditfwd.ActionAdminDisable, tenantID, "", map[string]any{
		"tenant_id": tenantID, "actor": actor, "roes_revoked": issued,
	})
	return issued, nil
}

// HandleRevocation applies one gatekeeper RevocationEvent: running orders
// under a revoked RoE (or a global revocation) transition to CANCELLED so
// workers stop picking up their tasks (halt ≤ 5 s is enforced worker-side
// via the pep-sdk revocation cache; this is the orchestrator's bookkeeping).
func (s *Service) HandleRevocation(ctx context.Context, evt *gatekeeperv1.RevocationEvent) {
	rev := evt.GetRevocation()
	if rev == nil {
		return
	}
	var roeMatch func(roeID string) bool
	switch rev.GetScope() {
	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL:
		roeMatch = func(string) bool { return true }
	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE:
		roeMatch = func(id string) bool { return id == rev.GetKey() }
	default:
		return
	}
	running, err := s.d.Store.ListOrdersByState(ctx, model.OrderRunning, "")
	if err != nil {
		s.d.Log.Warn("revocation sweep failed", "error", err)
		return
	}
	for _, row := range running {
		var order model.DiscoveryOrder
		if err := json.Unmarshal(row.Request, &order); err != nil {
			continue
		}
		if !roeMatch(order.Authorization.ROEID) {
			continue
		}
		if err := s.d.Store.SetOrderState(ctx, row.OrderID, model.OrderCancelled, nil); err != nil {
			s.d.Log.Warn("revocation cancel failed", "order_id", row.OrderID, "error", err)
			continue
		}
		s.audit(ctx, row.TenantID, auditfwd.ActionOrderCancel, row.OrderID, order.Authorization.ROEID, map[string]any{
			"order_id":      row.OrderID,
			"revocation_id": rev.GetRevocationId(),
			"reason":        "gatekeeper revocation: " + rev.GetReason(),
		})
		if st, err := s.GetStatus(ctx, row.OrderID); err == nil {
			s.publishStatus(ctx, st)
		}
	}
}

// ---------------------------------------------------------------------------
// Scope resolution for the reducer (fail-closed; 60 s mirror of the
// gatekeeper-resolved effective scope, doc 02 §6.1)
// ---------------------------------------------------------------------------

// ScopeFor resolves the order + its gatekeeper scope for the reducer.
func (s *Service) ScopeFor(ctx context.Context, orderID string) (*model.DiscoveryOrder, string, *sdkscope.Scope, error) {
	row, err := s.d.Store.GetOrder(ctx, orderID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", nil, nil
	}
	if err != nil {
		return nil, "", nil, err
	}
	var order model.DiscoveryOrder
	if err := json.Unmarshal(row.Request, &order); err != nil {
		return nil, "", nil, fmt.Errorf("decode order %s: %w", orderID, err)
	}
	roe, err := s.resolveROE(ctx, order.Authorization.ROEID, false)
	if err != nil {
		return nil, "", nil, err
	}
	return &order, row.State, roe.Scope, nil
}

// ResolvedScope exposes the gatekeeper-resolved scope mirror
// (discover://scopes resource, doc 02 §3.1).
func (s *Service) ResolvedScope(ctx context.Context, roeID string) (*sdkscope.Scope, error) {
	roe, err := s.resolveROE(ctx, roeID, false)
	if err != nil {
		return nil, err
	}
	return roe.Scope, nil
}

// RunningOrderIDs lists RUNNING order ids (status heartbeat, doc 02 §3.3).
func (s *Service) RunningOrderIDs(ctx context.Context) ([]string, error) {
	rows, err := s.d.Store.ListOrdersByState(ctx, model.OrderRunning, "")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.OrderID)
	}
	return ids, nil
}

func (s *Service) resolveROE(ctx context.Context, roeID string, forceRefresh bool) (*pepclient.ResolvedROE, error) {
	s.mu.Lock()
	entry := s.scopeCache[roeID]
	s.mu.Unlock()
	if !forceRefresh && entry != nil && s.d.Now().Sub(entry.fetchedAt) < scopeCacheTTL {
		return entry.res, nil
	}
	res, err := s.d.PEP.ResolveROE(ctx, roeID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.scopeCache[roeID] = &scopeEntry{res: res, fetchedAt: s.d.Now()}
	s.mu.Unlock()
	return res, nil
}

// ---------------------------------------------------------------------------
// Janitor: time budgets + asset expiry sweeper
// ---------------------------------------------------------------------------

// SweepOnce enforces per-order time budgets (doc 02 §2.4) and, when
// assetTTL > 0, expires stale assets emitting AssetChange "expired" events.
// finalizeCtx is used for webhook callbacks.
func (s *Service) SweepOnce(ctx context.Context, assetTTL time.Duration) {
	running, err := s.d.Store.ListOrdersByState(ctx, model.OrderRunning, "")
	if err != nil {
		s.d.Log.Warn("janitor: list running", "error", err)
		return
	}
	for _, row := range running {
		var order model.DiscoveryOrder
		if err := json.Unmarshal(row.Request, &order); err != nil {
			continue
		}
		budget := time.Duration(order.Options.TimeBudgetSec) * time.Second
		if budget > 0 && s.d.Now().Sub(row.CreatedAt) > budget {
			if err := s.d.Store.SetOrderState(ctx, row.OrderID, model.OrderPartial, nil); err != nil {
				continue
			}
			s.audit(ctx, row.TenantID, auditfwd.ActionOrderFinalize, row.OrderID, order.Authorization.ROEID, map[string]any{
				"order_id": row.OrderID, "state": model.OrderPartial,
				"reasons": []string{model.ReasonBudgetExhausted},
			})
			if st, err := s.GetStatus(ctx, row.OrderID); err == nil {
				s.publishStatus(ctx, st)
				s.fireCallback(ctx, &order, st)
			}
		}
	}
	if assetTTL > 0 {
		cutoff := s.d.Now().UTC().Add(-assetTTL)
		expired, err := s.d.Store.ExpireStaleAssets(ctx, cutoff)
		if err != nil {
			s.d.Log.Warn("janitor: expire assets", "error", err)
			return
		}
		for i := range expired {
			rec := &expired[i]
			ch := &model.AssetChange{
				SchemaVersion: model.SchemaVersion,
				TenantID:      rec.TenantID,
				AssetID:       rec.AssetID,
				Kind:          model.ChangeExpired,
				Asset:         *rec,
				ChangedFields: []string{"status"},
				EmittedAt:     s.d.Now().UTC(),
			}
			if err := s.PublishAssetChange(ctx, ch); err != nil {
				s.d.Log.Warn("janitor: publish expired change", "asset", rec.Value, "error", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Event publishing (hub.discover.* — JSON module events, DISCOVER_EVENTS)
// ---------------------------------------------------------------------------

// PublishAssetChange emits one AssetChange (doc 02 §3.2) — the reducer's
// PublishChange hook.
func (s *Service) PublishAssetChange(ctx context.Context, ch *model.AssetChange) error {
	body, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	msgID := fmt.Sprintf("dac-%s-%s-%d", ch.AssetID, ch.Kind, ch.EmittedAt.UnixNano())
	msg := nats.NewMsg(model.SubjectAssetChanged)
	msg.Header.Set(nats.MsgIdHdr, msgID)
	msg.Data = body
	_, err = s.d.JS.PublishMsg(msg, nats.Context(ctx))
	return err
}

// publishStatus emits hub.discover.order.status_changed and fires the
// per-order webhook on terminal states (doc 02 §3.1/§3.3). It is the
// reducer's PublishStatus hook (re-reads the order).
func (s *Service) publishStatus(ctx context.Context, st *model.OrderStatus) {
	body, err := json.Marshal(st)
	if err != nil {
		return
	}
	msgID := fmt.Sprintf("dost-%s-%s-%d", st.OrderID, st.State, s.d.Now().UnixNano())
	msg := nats.NewMsg(model.SubjectOrderStatusChanged)
	msg.Header.Set(nats.MsgIdHdr, msgID)
	msg.Data = body
	if _, err := s.d.JS.PublishMsg(msg, nats.Context(ctx)); err != nil {
		s.d.Log.Warn("status event publish failed", "order_id", st.OrderID, "error", err)
	}
}

// PublishStatusFor re-reads and emits an order's status (reducer hook).
func (s *Service) PublishStatusFor(ctx context.Context, orderID string) {
	st, err := s.GetStatus(ctx, orderID)
	if err != nil {
		return
	}
	s.publishStatus(ctx, st)
	if st.FinishedAt != "" {
		row, err := s.d.Store.GetOrder(ctx, orderID)
		if err != nil {
			return
		}
		var order model.DiscoveryOrder
		if err := json.Unmarshal(row.Request, &order); err != nil {
			return
		}
		s.fireCallback(ctx, &order, st)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) statusFromParts(order *model.DiscoveryOrder, state string, gate *model.Gate, p model.Progress, finished bool) *model.OrderStatus {
	st := &model.OrderStatus{
		OrderID:   order.OrderID,
		TenantID:  order.TenantID,
		State:     state,
		Gate:      gate,
		Progress:  p,
		StartedAt: s.d.Now().UTC().Format(time.RFC3339),
	}
	if finished {
		st.FinishedAt = s.d.Now().UTC().Format(time.RFC3339)
	}
	return st
}

func (s *Service) audit(ctx context.Context, tenantID, action, target, roeID string, payload map[string]any) {
	if s.d.Audit == nil {
		return
	}
	payload["roe_id"] = roeID
	if err := s.d.Audit.Emit(ctx, auditfwd.Event{
		TenantID: tenantID, Action: action, Target: target, ROEID: roeID, Payload: payload,
	}); err != nil {
		s.d.Log.Warn("audit emit failed", "action", action, "error", err)
	}
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// ExpandTasks is the reducer's recursion hook (doc 02 §2.4): derived
// depth+1 tasks for a newly discovered in-scope host, budget-checked against
// the order's max_tasks.
func (s *Service) ExpandTasks(ctx context.Context, order *model.DiscoveryOrder, host string, depth int) error {
	roe, err := s.resolveROE(ctx, order.Authorization.ROEID, false)
	if err != nil {
		return err
	}
	tasks := s.d.Planner.ExpandDiscovered(order, host, depth, roe.Scope, "R0")
	if len(tasks) == 0 {
		return nil
	}
	row, err := s.d.Store.GetOrder(ctx, order.OrderID)
	if err != nil {
		return err
	}
	if row.Progress.TasksTotal+len(tasks) > order.Options.MaxTasks {
		// Budget stop (doc 02 §2.4): recorded, not fatal.
		s.audit(ctx, order.TenantID, auditfwd.ActionOrderFinalize, order.OrderID, order.Authorization.ROEID, map[string]any{
			"order_id": order.OrderID, "reasons": []string{model.ReasonBudgetExhausted + ": max_tasks"},
		})
		return nil
	}
	for _, t := range tasks {
		if err := queue.PublishTask(ctx, s.d.JS, t); err != nil {
			return err
		}
	}
	if err := s.d.Store.SetProgressTotal(ctx, order.OrderID, row.Progress.TasksTotal+len(tasks)); err != nil {
		return err
	}
	return nil
}

// TrimmedReasonList renders gate reasons for logs.
func TrimmedReasonList(reasons []string) string {
	if len(reasons) > 8 {
		return strings.Join(reasons[:8], "; ") + "; …"
	}
	return strings.Join(reasons, "; ")
}
