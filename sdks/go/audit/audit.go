// Package audit provides the agent-side audit emission helpers of doc 01
// §5.9/§10.4 and Ruling A.4:
//
//   - per-probe TARGET_TOUCHED records (the authoritative cross-check for
//     scope-bound watch tokens),
//   - SCOPE_VIOLATION records when the SDK itself denies a target contact
//     (token misuse / manifest mismatch caught pre-contact),
//   - the "scope:sha256:<hash>" checkpoint form for TaskResult
//     targets_touched (accepted ONLY alongside the per-probe records),
//   - JCS (RFC 8785) canonical JSON (doc 01 §10.2) used by the hash chain
//     and the scope-manifest hashing.
//
// Agents emit events WITHOUT seq/prev_hash/hash — those are assigned by the
// single-writer audit-service when it chains the event (doc 01 §5.9, doc 11
// §3.4). Emission is never sampled (doc 01 §8.1).
package audit

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Subject is the canonical bus subject for audit events (doc 01 §8.1).
const Subject = "audit.events"

// Emitter delivers audit events. Implementations must be safe for concurrent
// use; delivery is at-least-once (never sampled).
type Emitter interface {
	Emit(ctx context.Context, evt *platformv1.AuditEvent) error
}

// EmitterFunc adapts a function to Emitter (tests, custom transports).
type EmitterFunc func(ctx context.Context, evt *platformv1.AuditEvent) error

// Emit implements Emitter.
func (f EmitterFunc) Emit(ctx context.Context, evt *platformv1.AuditEvent) error {
	return f(ctx, evt)
}

// NopEmitter drops events (R0-style local spooling substitute in tests).
type NopEmitter struct{}

// Emit implements Emitter.
func (NopEmitter) Emit(context.Context, *platformv1.AuditEvent) error { return nil }

// Ident identifies the entities an event concerns — the AuditSubject triple
// plus the actor.
type Ident struct {
	// AgentID — the emitting agent (actor kind "agent").
	AgentID string
	// MissionID / TaskID / ROEID — the AuditSubject triple.
	MissionID string
	TaskID    string
	ROEID     string
}

// NewEvent builds an AuditEvent (id + ts set; seq/hash left to the
// audit-service chain writer). payload may be nil.
func NewEvent(evtType platformv1.AuditEventType, id Ident, payload map[string]any) (*platformv1.AuditEvent, error) {
	var ps *structpb.Struct
	if payload != nil {
		var err error
		ps, err = structpb.NewStruct(payload)
		if err != nil {
			return nil, err
		}
	}
	return &platformv1.AuditEvent{
		EventId: "aud_" + ulid.Make().String(),
		Ts:      timestamppb.New(time.Now().UTC()),
		Type:    evtType,
		Actor: &platformv1.AuditActor{
			Kind: "agent",
			Id:   id.AgentID,
		},
		Subject: &platformv1.AuditSubject{
			MissionId: id.MissionID,
			TaskId:    id.TaskID,
			RoeId:     id.ROEID,
		},
		Payload: ps,
	}, nil
}

// TargetTouchedEvent builds the per-probe TARGET_TOUCHED record (doc 01 §5.9,
// doc 03 §9.6). extra may carry probe_type, token_jti, rps observed, etc.
func TargetTouchedEvent(id Ident, target, tokenJTI string, extra map[string]any) (*platformv1.AuditEvent, error) {
	payload := map[string]any{
		"target":    target,
		"token_jti": tokenJTI,
	}
	for k, v := range extra {
		payload[k] = v
	}
	return NewEvent(platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED, id, payload)
}

// ScopeViolationEvent builds the SCOPE_VIOLATION record the SDK emits when it
// denies a target contact pre-contact (token misuse / manifest mismatch —
// doc 01 §10.5; "a scan job without a valid in-scope token is dead-lettered
// and audit-logged", doc 03 §9.2).
func ScopeViolationEvent(id Ident, target, tokenJTI, reason string) (*platformv1.AuditEvent, error) {
	return NewEvent(platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION, id, map[string]any{
		"target":                target,
		"token_jti":             tokenJTI,
		"reason":                reason,
		"denied_before_contact": true,
	})
}

// ScopeHashValue renders the canonical scope-hash audit form
// "scope:sha256:<hash>" from a verified manifest hash (Ruling A.3).
func ScopeHashValue(manifestSHA256Hex string) string {
	return "scope:sha256:" + manifestSHA256Hex
}

// CheckpointTargetsTouched returns the TaskResult metrics.targets_touched
// form for a scope-bound watch token: ["scope:sha256:<hash>"]. It is accepted
// ONLY alongside the per-probe TARGET_TOUCHED records, which remain the
// authoritative cross-check (Ruling A.4, doc 01 §5.7, doc 03 §4.3).
func CheckpointTargetsTouched(manifestSHA256Hex string) []string {
	return []string{ScopeHashValue(manifestSHA256Hex)}
}
