package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
)

// kindFromPlatformType maps the platform audit vocabulary (doc 01 §5.9) onto
// stored kind strings (doc 11 §3.4 where overlapping).
var kindFromPlatformType = map[platformv1.AuditEventType]string{
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_MISSION_CREATED: "mission.created",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_PLAN_SUBMITTED:  "plan.submitted",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_AUTHZ_DECISION:  KindAuthorizationDecision,
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_DISPATCHED: "task.dispatched",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED:  "target.touched",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_RESULT:     "task.result",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_ROE_REVOKED:     KindROERevoked,
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_KILL_SWITCH:     "kill.switch",
	platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION: "scope.violation",
}

// RunConsumer drains audit.events (doc 01 §8.1: durable, never sampled) into
// the hash chain until ctx is cancelled. Modules forward execution.* and
// platform events here; ingestion is idempotent on event_id.
func (s *Service) RunConsumer(ctx context.Context, b *bus.Bus) error {
	sub, err := b.JS.Subscribe(bus.SubjectAuditEvents, func(msg *nats.Msg) {
		if err := s.handleBusMessage(msg); err != nil {
			fmt.Printf("audit: consumer: %v\n", err)
			// Nak for redelivery (at-least-once); malformed messages would
			// poison the queue, so they are acked + dropped after logging.
			if strings.Contains(err.Error(), "unmarshal") {
				_ = msg.Ack()
				return
			}
			_ = msg.NakWithDelay(5 * time.Second)
			return
		}
		_ = msg.Ack()
	}, nats.Durable("gatekeeper-audit"), nats.ManualAck(), nats.AckWait(30*time.Second),
		nats.MaxDeliver(10), nats.DeliverAll())
	if err != nil {
		return fmt.Errorf("audit: subscribe %s: %w", bus.SubjectAuditEvents, err)
	}
	<-ctx.Done()
	return sub.Drain()
}

func (s *Service) handleBusMessage(msg *nats.Msg) error {
	var env platformv1.Envelope
	if err := proto.Unmarshal(msg.Data, &env); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}
	var pa platformv1.AuditEvent
	if err := env.GetPayload().UnmarshalTo(&pa); err != nil {
		return fmt.Errorf("unmarshal audit payload (%s): %w", env.GetType(), err)
	}
	kind, ok := kindFromPlatformType[pa.GetType()]
	if !ok {
		kind = strings.ToLower(strings.TrimPrefix(pa.GetType().String(), "AUDIT_EVENT_TYPE_"))
	}
	in := Input{
		EventID: pa.GetEventId(),
		Kind:    kind,
		Actor: map[string]any{
			"kind": pa.GetActor().GetKind(),
			"id":   pa.GetActor().GetId(),
		},
		Subject: map[string]any{
			"mission_id": pa.GetSubject().GetMissionId(),
			"task_id":    pa.GetSubject().GetTaskId(),
			"roe_id":     pa.GetSubject().GetRoeId(),
		},
	}
	if p := pa.GetPayload(); p != nil {
		in.Payload = structpbAsMap(p)
	}
	if ts := pa.GetTs(); ts != nil {
		in.OccurredAt = ts.AsTime()
	}
	// Idempotent on event_id (doc 01 §8.2): a duplicate redelivery is acked
	// without double-chaining.
	exists, err := s.exists(context.Background(), in.EventID)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = s.Record(context.Background(), in)
	return err
}

func (s *Service) exists(ctx context.Context, eventID string) (bool, error) {
	if eventID == "" {
		return false, nil
	}
	var n int
	err := s.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE event_id = $1`, eventID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("audit: exists: %w", err)
	}
	return n > 0, nil
}

func structpbAsMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}
