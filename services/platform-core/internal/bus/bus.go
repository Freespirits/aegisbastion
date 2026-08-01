// Package bus wraps the NATS JetStream connection: canonical subjects
// (doc 01 §8.1), the §8.2 Envelope codec, the transactional outbox relay
// (doc 01 §13 bus-outage buffering), and KV access for leases.
package bus

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
)

// Canonical subjects (doc 01 §8.1; Ruling C11 for revocations).
const (
	SubjectTaskAssignPrefix = "task.assign." // + agent_id
	SubjectTaskResult       = "task.result"
	SubjectAgentHeartbeat   = "agent.heartbeat"
	SubjectMissionEvents    = "mission.events"
	SubjectControlKill      = "control.kill" // core NATS broadcast — NO JetStream stream
	SubjectAuditEvents      = "audit.events"
	SubjectRevocations      = "tasks.revocations.v1" // gatekeeper → Orchestrator
)

// KV buckets (created by deploy/jetstream-bootstrap).
const (
	KVLeases        = "leases"
	KVAgentPresence = "agent_presence"
)

// Bus bundles the NATS handles platform-core uses.
type Bus struct {
	NC     *nats.Conn
	JS     nats.JetStreamContext
	Leases nats.KeyValue
}

// Connect dials NATS and resolves the JetStream context + lease bucket.
// When withKV is false (unit tests without a bootstrapped server) the KV
// handle stays nil.
func Connect(url, name string) (*Bus, error) {
	nc, err := nats.Connect(url,
		nats.Name(name),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect %s: %w", url, err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	b := &Bus{NC: nc, JS: js}
	kv, err := js.KeyValue(KVLeases)
	if err == nil {
		b.Leases = kv
	}
	return b, nil
}

// Close drains and closes the connection.
func (b *Bus) Close() {
	_ = b.NC.Drain()
	b.NC.Close()
}

// NewEnvelope wraps a payload in the doc 01 §8.2 envelope.
func NewEnvelope(missionID string, payload proto.Message) (*platformv1.Envelope, error) {
	any, err := anypb.New(payload)
	if err != nil {
		return nil, err
	}
	return &platformv1.Envelope{
		EventId:   ids.New("evt"),
		Type:      string(payload.ProtoReflect().Descriptor().FullName()),
		Ts:        timestamppb.Now(),
		MissionId: missionID,
		Payload:   any,
	}, nil
}

// MarshalEnvelope serializes an envelope for the bus/outbox.
func MarshalEnvelope(env *platformv1.Envelope) ([]byte, error) {
	return proto.Marshal(env)
}

// PublishEnvelope JetStream-publishes an envelope (used by the outbox relay).
func (b *Bus) PublishEnvelope(subject string, data []byte) error {
	_, err := b.JS.Publish(subject, data)
	return err
}

// BroadcastKill publishes on control.kill — core NATS ONLY, no JetStream
// durable (doc 01 §8.1 + Ruling C11; agents must ACK within 5 s).
func (b *Bus) BroadcastKill(data []byte) error {
	return b.NC.Publish(SubjectControlKill, data)
}

// KillPayload is the control.kill broadcast payload (a Struct inside the
// §8.2 Envelope; there is deliberately no proto message — control.kill is a
// core-NATS broadcast, not a persisted contract).
func KillFields(scope, key, revocationID, reason string, missionIDs []string) map[string]any {
	missions := make([]any, 0, len(missionIDs))
	for _, m := range missionIDs {
		missions = append(missions, m)
	}
	return map[string]any{
		"scope":         scope,
		"key":           key,
		"revocation_id": revocationID,
		"reason":        reason,
		"mission_ids":   missions,
		"issued_at":     time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// EnsureStreamTasksConsumer creates (idempotently) the durable pull consumer
// the Orchestrator uses for task.result (doc 01 §8.1: durable, at-least-once;
// idempotent consumer via task_id).
func (b *Bus) EnsureResultsConsumer() (*nats.Subscription, error) {
	return b.JS.PullSubscribe(SubjectTaskResult, "orchestrator-results",
		nats.BindStream("TASK_RESULTS"),
		nats.AckWait(30*time.Second),
		nats.MaxDeliver(5),
	)
}

// EnsureRevocationsConsumer creates the durable pull consumer on
// tasks.revocations.v1 (gatekeeper revocation-service → Orchestrator kill
// switch, Ruling C11).
func (b *Bus) EnsureRevocationsConsumer() (*nats.Subscription, error) {
	return b.JS.PullSubscribe(SubjectRevocations, "orchestrator-killswitch",
		nats.BindStream("GATEKEEPER"),
		nats.AckWait(10*time.Second),
		nats.MaxDeliver(10),
	)
}
