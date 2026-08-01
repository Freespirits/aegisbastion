// Package auditfwd is Discover's audit emitter + durability spool (doc 02
// §6.4). Every order submission, gate decision, task dispatch, cancellation,
// and admin action is:
//
//  1. appended to the local audit_spool table FIRST (bounded durability
//     during forwarding outages — the row is the record of intent), then
//  2. forwarded to gatekeeper's audit-service — the platform audit of record
//     (doc 11 §3.4) — via the audit.events bus subject, and marked
//     forwarded_at.
//
// Fail-closed mirror of doc 11's audit-gating rule: when the unforwarded
// backlog exceeds MaxUnforwarded, R1+ order intake pauses (doc 02 §6.4) —
// IntakePaused reports it and the order service enforces.
//
// Events are the platform envelope form (aegisbastion.platform.v1.AuditEvent on
// audit.events, doc 01 §8.1); gatekeeper's audit-service chains them
// (seq/hash assigned server-side — we emit without them).
package auditfwd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/sdks/go/audit"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// Actions (audit_spool.action; mapped onto platformv1.AuditEventType for the
// bus forward — the exact verb always rides in payload.action).
const (
	ActionOrderSubmit     = "order.submit"
	ActionGateDecision    = "gate.decision"
	ActionTaskDispatch    = "task.dispatch"
	ActionTaskDone        = "task.done"
	ActionWorkerRefusal   = "worker.refusal"
	ActionOrderCancel     = "order.cancel"
	ActionOrderFinalize   = "order.finalize"
	ActionAdminDisable    = "admin.tenant_disable"
	ActionDPIngestFailure = "dp.ingest_failed"
	ActionQuarantine      = "finding.quarantined"
)

// Event is one auditable occurrence.
type Event struct {
	TenantID string
	Action   string
	Target   string // order_id / task_id / tenant_id the action concerns
	// MissionID/TaskID/ROEID populate the platform AuditSubject triple
	// (empty when not applicable — Discover orders are module-scoped, not
	// platform missions).
	MissionID string
	TaskID    string
	ROEID     string
	Payload   map[string]any
}

// Emitter appends to the spool; the Forwarder drains it.
type Emitter struct {
	st      *store.Store
	actorID string
}

// NewEmitter builds the spool appender. actorID is the service identity
// (e.g. "discover-orchestrator").
func NewEmitter(st *store.Store, actorID string) *Emitter {
	return &Emitter{st: st, actorID: actorID}
}

// Emit appends one event to the local spool (durability first). The
// forwarder picks it up within its poll interval.
func (e *Emitter) Emit(ctx context.Context, ev Event) error {
	actor, _ := json.Marshal(map[string]string{"kind": "service", "id": e.actorID})
	payload := map[string]any{"action": ev.Action}
	for k, v := range ev.Payload {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("auditfwd: marshal payload: %w", err)
	}
	_, err = e.st.AppendSpool(ctx, &store.SpoolRow{
		TenantID: ev.TenantID,
		Actor:    actor,
		Action:   ev.Action,
		Target:   ev.Target,
		Payload:  body,
	})
	if err != nil {
		return fmt.Errorf("auditfwd: spool append %s: %w", ev.Action, err)
	}
	return nil
}

// IntakePaused implements doc 02 §6.4: spool full ⇒ R1+ order intake pauses.
func (e *Emitter) IntakePaused(ctx context.Context, maxUnforwarded int64) (bool, int64, error) {
	if maxUnforwarded <= 0 {
		return false, 0, nil
	}
	n, err := e.st.UnforwardedSpoolCount(ctx)
	if err != nil {
		// Spool unreadable ⇒ pause (fail-closed).
		return true, 0, fmt.Errorf("auditfwd: spool count: %w", err)
	}
	return n >= maxUnforwarded, n, nil
}

// Forwarder drains the spool to gatekeeper's audit-service via audit.events.
type Forwarder struct {
	st      *store.Store
	emit    audit.Emitter
	actorID string
	log     *slog.Logger
}

// NewForwarder builds the drain loop. emit is typically the SDK bus emitter
// (audit.events via sdks/go/bus).
func NewForwarder(st *store.Store, emit audit.Emitter, actorID string, log *slog.Logger) *Forwarder {
	if log == nil {
		log = slog.Default()
	}
	return &Forwarder{st: st, emit: emit, actorID: actorID, log: log}
}

// Run polls and forwards until ctx is done. Outages are retried on the next
// tick — rows stay unforwarded (durability preserved).
func (f *Forwarder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		f.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (f *Forwarder) drain(ctx context.Context) {
	rows, err := f.st.UnforwardedSpool(ctx, 100)
	if err != nil {
		f.log.Warn("audit spool read failed", "error", err)
		return
	}
	for _, r := range rows {
		if err := f.forwardOne(ctx, r); err != nil {
			f.log.Warn("audit forward failed (retained in spool)", "seq", r.Seq, "error", err)
			return // preserve order; retry next tick
		}
	}
}

func (f *Forwarder) forwardOne(ctx context.Context, r store.SpoolRow) error {
	var payload map[string]any
	if len(r.Payload) > 0 {
		_ = json.Unmarshal(r.Payload, &payload)
	}
	var actor struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if len(r.Actor) > 0 {
		_ = json.Unmarshal(r.Actor, &actor)
	}
	// The AuditSubject triple rides in the payload keys the Emitter recorded.
	missionID, _ := payload["mission_id"].(string)
	taskID, _ := payload["task_id"].(string)
	roeID, _ := payload["roe_id"].(string)
	evt, err := audit.NewEvent(eventType(r.Action), audit.Ident{
		AgentID:   firstNonEmpty(actor.ID, f.actorID),
		MissionID: missionID,
		TaskID:    taskID,
		ROEID:     roeID,
	}, payload)
	if err != nil {
		return err
	}
	if err := f.emit.Emit(ctx, evt); err != nil {
		return err
	}
	return f.st.MarkSpoolForwarded(ctx, r.Seq)
}

// eventType maps the module action onto the platform audit vocabulary
// (doc 01 §5.9). The exact verb stays in payload.action.
func eventType(action string) platformv1.AuditEventType {
	switch action {
	case ActionOrderSubmit:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_PLAN_SUBMITTED
	case ActionGateDecision:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_AUTHZ_DECISION
	case ActionTaskDispatch:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_DISPATCHED
	case ActionTaskDone, ActionOrderFinalize:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_RESULT
	case ActionWorkerRefusal:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION
	case ActionOrderCancel, ActionAdminDisable:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_KILL_SWITCH
	default:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_UNSPECIFIED
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
