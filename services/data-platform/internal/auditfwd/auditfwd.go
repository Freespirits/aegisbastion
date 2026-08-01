// Package auditfwd is the data-access audit forwarder (doc 09 §4.4): it
// drains dp.audit_outbox onto the platform AUDIT stream (subject
// "audit.events", durable — doc 01 §8.1) for gatekeeper's audit-service,
// which is the hash-chained audit of record. dp operates no hash chain of its
// own (Ruling B).
//
// Wire form: platformv1.Envelope{ payload: platformv1.AuditEvent } — the
// envelope the gatekeeper audit consumer (services/gatekeeper
// internal/audit) ingests. dp's domain actions (ingest.batch,
// query.evidence_access, retention.purge, …) travel in the payload as
// "dp_action"; the platform AuditEventType enum has no data-access value, so
// the event type is UNSPECIFIED and the semantic action lives in the payload
// (gatekeeper stores it verbatim).
//
// Delivery is at-least-once: rows are marked forwarded only after the
// JetStream publish is acked; gatekeeper dedups on event_id (doc 01 §8.2), so
// replays are safe. Fail-closed posture (doc 09 §8): when the forwarder
// cannot drain, rows accumulate in the bounded Postgres outbox and operators
// see the backlog via logs and the readiness check.
package auditfwd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// SubjectAuditEvents is the canonical platform audit subject (doc 01 §8.1).
const SubjectAuditEvents = "audit.events"

// Forwarder drains the outbox.
type Forwarder struct {
	st     *store.Store
	js     nats.JetStreamContext
	source string // envelope source instance id
	log    *slog.Logger
}

// New builds a Forwarder. js may be nil — Run then no-ops (rows accumulate).
func New(st *store.Store, js nats.JetStreamContext, source string, log *slog.Logger) *Forwarder {
	return &Forwarder{st: st, js: js, source: source, log: log}
}

// Run drains on a ticker until ctx is cancelled.
func (f *Forwarder) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 2 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := f.DrainOnce(ctx)
			if err != nil && f.log != nil {
				f.log.Warn("audit forward incomplete (outbox backlog retained)",
					"forwarded", n, "err", err)
			}
		}
	}
}

// DrainOnce forwards up to 200 pending rows, oldest first. Stops at the first
// publish failure (order preserved) and reports it for the next tick.
func (f *Forwarder) DrainOnce(ctx context.Context) (int, error) {
	if f.js == nil {
		return 0, nil
	}
	rows, err := f.st.PendingAuditBatch(ctx, 200)
	if err != nil {
		return 0, fmt.Errorf("pending audit: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	forwarded := 0
	for _, p := range rows {
		data, err := marshalAuditEvent(f.source, p)
		if err != nil {
			return forwarded, fmt.Errorf("marshal audit %s: %w", p.AuditID, err)
		}
		msg := nats.NewMsg(SubjectAuditEvents)
		msg.Data = data
		msg.Header.Set(nats.MsgIdHdr, p.AuditID)
		if _, err := f.js.PublishMsg(msg, nats.Context(ctx)); err != nil {
			return forwarded, fmt.Errorf("publish audit %s: %w", p.AuditID, err)
		}
		if err := f.st.MarkAuditForwarded(ctx, []string{p.AuditID}); err != nil {
			return forwarded, fmt.Errorf("mark forwarded %s: %w", p.AuditID, err)
		}
		forwarded++
	}
	return forwarded, nil
}

// marshalAuditEvent renders one outbox row as an Envelope-wrapped
// platformv1.AuditEvent (the form the gatekeeper audit consumer ingests).
func marshalAuditEvent(source string, p *store.PendingAudit) ([]byte, error) {
	payload := map[string]any{
		"dp_action": p.Action,
		"service":   source,
	}
	if p.TenantID != nil {
		payload["tenant_id"] = *p.TenantID
	}
	if p.ObjectRef != nil {
		payload["object_ref"] = *p.ObjectRef
	}
	if p.ParamsHash != nil {
		payload["params_hash"] = *p.ParamsHash
	}
	st, err := structpb.NewStruct(payload)
	if err != nil {
		return nil, err
	}
	evt := &platformv1.AuditEvent{
		EventId: p.AuditID, // idempotent on event_id (doc 01 §8.2)
		Ts:      timestamppb.New(p.TS),
		Type:    platformv1.AuditEventType_AUDIT_EVENT_TYPE_UNSPECIFIED,
		Actor: &platformv1.AuditActor{
			Kind: p.Actor.Type,
			Id:   p.Actor.ID,
		},
		Payload: st,
	}
	any, err := anypb.New(evt)
	if err != nil {
		return nil, err
	}
	env := &platformv1.Envelope{
		EventId: p.AuditID,
		Type:    string(evt.ProtoReflect().Descriptor().FullName()),
		Ts:      timestamppb.New(p.TS),
		Payload: any,
	}
	return proto.Marshal(env)
}
