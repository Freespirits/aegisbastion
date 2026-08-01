// Package bus is the SDK's NATS JetStream client (doc 01 §8, Ruling C3).
// Every message on the bus is wrapped in the platform Envelope (doc 01 §8.2):
// event_id (ULID), type (fully-qualified protobuf name), ts, mission_id,
// trace_context, payload (google.protobuf.Any).
//
// Publishing is outbox-friendly (doc 01 §13 "services buffer via outbox table
// and replay"): BuildMessage produces a deterministic, fully-formed *nats.Msg
// (Nats-Msg-Id = event_id for JetStream dedup) that callers may persist and a
// relay may publish later via PublishMsg with identical dedup semantics.
//
// Consumers MUST be idempotent on event_id/task_id — duplicate delivery is
// expected under at-least-once (doc 01 §8.2).
package bus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Canonical subjects (doc 01 §8.1, doc 11 §2.3).
const (
	// SubjectTaskResult — agents → Orchestrator (durable, at-least-once).
	SubjectTaskResult = "task.result"
	// SubjectAgentHeartbeat — agents → Registry (ephemeral, 30 s TTL).
	SubjectAgentHeartbeat = "agent.heartbeat"
	// SubjectMissionEvents — Orchestrator → commanders/UI.
	SubjectMissionEvents = "mission.events"
	// SubjectAuditEvents — all services → audit-service (never sampled).
	SubjectAuditEvents = "audit.events"
	// SubjectControlKill — Orchestrator → all agents. CORE NATS BROADCAST
	// ONLY: there is intentionally no JetStream stream for it (contracts
	// wave decision; doc 01 §8.1 "no persistence needed; agents must ACK
	// within 5 s").
	SubjectControlKill = "control.kill"
	// SubjectRevocations — gatekeeper revocation-service kill-switch
	// commands (durable; PEP halt ≤ 5 s, doc 11 §7).
	SubjectRevocations = "tasks.revocations.v1"
)

// JetStream streams the SDK binds to (provisioned by deploy/jetstream-bootstrap).
const (
	// StreamTaskAssign — WorkQueue over task.assign.*.
	StreamTaskAssign = "TASK_ASSIGN"
	// StreamGatekeeper — durable stream over the gatekeeper subjects incl.
	// tasks.revocations.v1.
	StreamGatekeeper = "GATEKEEPER"
)

// SubjectTaskAssign returns the per-agent assignment subject
// task.assign.{agent_id} (doc 01 §8.1; only the Orchestrator may publish it).
func SubjectTaskAssign(agentID string) string { return "task.assign." + agentID }

// Client wraps a NATS connection and its JetStream context.
type Client struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// Connect dials NATS and opens the JetStream context.
func Connect(url string, opts ...nats.Option) (*Client, error) {
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("bus: connect %s: %w", url, err)
	}
	return FromConn(nc)
}

// FromConn wraps an existing connection.
func FromConn(nc *nats.Conn) (*Client, error) {
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: JetStream context: %w", err)
	}
	return &Client{nc: nc, js: js}, nil
}

// Conn returns the underlying connection (core-NATS users: kill broadcast).
func (c *Client) Conn() *nats.Conn { return c.nc }

// JetStream returns the JetStream context.
func (c *Client) JetStream() nats.JetStreamContext { return c.js }

// Close drains and closes the connection.
func (c *Client) Close() {
	_ = c.nc.Drain()
	c.nc.Close()
}

// PublishOptions carries the envelope metadata for one publish.
type PublishOptions struct {
	// MissionID — owning mission (empty for platform-internal messages).
	MissionID string
	// Trace — W3C trace context propagated from the triggering assignment.
	Trace *platformv1.TraceContext
	// EventID overrides the generated ULID — use the persisted outbox id when
	// replaying so redeliveries dedup on the same Nats-Msg-Id.
	EventID string
}

// NewEnvelope wraps payload in the doc 01 §8.2 envelope.
func NewEnvelope(payload proto.Message, opts PublishOptions) (*platformv1.Envelope, error) {
	any, err := anypb.New(payload)
	if err != nil {
		return nil, fmt.Errorf("bus: pack payload %T: %w", payload, err)
	}
	eventID := opts.EventID
	if eventID == "" {
		eventID = ulid.Make().String()
	}
	return &platformv1.Envelope{
		EventId:      eventID,
		Type:         string(payload.ProtoReflect().Descriptor().FullName()),
		Ts:           timestamppb.Now(),
		MissionId:    opts.MissionID,
		TraceContext: opts.Trace,
		Payload:      any,
	}, nil
}

// MarshalEnvelope serializes an envelope for the wire.
func MarshalEnvelope(env *platformv1.Envelope) ([]byte, error) {
	data, err := proto.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("bus: marshal envelope: %w", err)
	}
	return data, nil
}

// UnmarshalEnvelope parses an envelope off the wire.
func UnmarshalEnvelope(data []byte) (*platformv1.Envelope, error) {
	var env platformv1.Envelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("bus: unmarshal envelope: %w", err)
	}
	return &env, nil
}

// UnpackPayload decodes env.Payload into a fresh message of its registered
// type. Callers type-assert to the expected payload type.
func UnpackPayload(env *platformv1.Envelope) (proto.Message, error) {
	if env.GetPayload() == nil {
		return nil, errors.New("bus: envelope has no payload")
	}
	msg, err := anypb.UnmarshalNew(env.GetPayload(), proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("bus: unpack payload type %q: %w", env.GetType(), err)
	}
	return msg, nil
}

// BuildMessage builds a fully-formed NATS message for subject — headers carry
// Nats-Msg-Id = event_id so JetStream dedups replays (outbox-friendly).
func BuildMessage(subject string, payload proto.Message, opts PublishOptions) (*nats.Msg, error) {
	env, err := NewEnvelope(payload, opts)
	if err != nil {
		return nil, err
	}
	data, err := MarshalEnvelope(env)
	if err != nil {
		return nil, err
	}
	h := nats.Header{}
	h.Set(nats.MsgIdHdr, env.GetEventId())
	return &nats.Msg{Subject: subject, Header: h, Data: data}, nil
}

// Publish wraps payload in an envelope and publishes it via JetStream with
// Nats-Msg-Id dedup. Returns the event_id.
func (c *Client) Publish(ctx context.Context, subject string, payload proto.Message, opts PublishOptions) (string, error) {
	msg, err := BuildMessage(subject, payload, opts)
	if err != nil {
		return "", err
	}
	if err := c.PublishMsg(ctx, msg); err != nil {
		return "", err
	}
	return msg.Header.Get(nats.MsgIdHdr), nil
}

// PublishMsg publishes a pre-built message via JetStream (outbox relay path).
func (c *Client) PublishMsg(ctx context.Context, msg *nats.Msg) error {
	pubOpts := []nats.PubOpt{nats.Context(ctx)}
	if id := msg.Header.Get(nats.MsgIdHdr); id != "" {
		pubOpts = append(pubOpts, nats.MsgId(id))
	}
	if _, err := c.js.PublishMsg(msg, pubOpts...); err != nil {
		return fmt.Errorf("bus: publish %s: %w", msg.Subject, err)
	}
	return nil
}

// PublishCore publishes an envelope on a core-NATS subject (no persistence —
// e.g. nothing the SDK produces goes to control.kill, but heartbeat-style
// fire-and-forget subjects may use it).
func (c *Client) PublishCore(subject string, payload proto.Message, opts PublishOptions) (string, error) {
	msg, err := BuildMessage(subject, payload, opts)
	if err != nil {
		return "", err
	}
	if err := c.nc.PublishMsg(msg); err != nil {
		return "", fmt.Errorf("bus: core publish %s: %w", subject, err)
	}
	return msg.Header.Get(nats.MsgIdHdr), nil
}

// Disposition tells the consumer how to settle a message.
type Disposition int

const (
	// Ack settles the message (handled; do not redeliver).
	Ack Disposition = iota
	// Nak negatively settles — redeliver per the consumer's policy.
	Nak
	// Term settles permanently — no redelivery (poison message).
	Term
)

// MessageControl exposes in-flight settlement to handlers of long-running
// work: call InProgress to extend the ack wait while a task runs (the
// Orchestrator redelivers task.assign.* on lease expiry, doc 01 §6.3).
type MessageControl struct {
	msg *nats.Msg
}

// InProgress extends the ack deadline for this message.
func (m *MessageControl) InProgress() error {
	if m.msg == nil {
		return nil
	}
	return m.msg.InProgress()
}

// EnvelopeHandler consumes one envelope and returns its settlement.
type EnvelopeHandler func(ctx context.Context, env *platformv1.Envelope, ctl *MessageControl) Disposition

// Consume creates (or attaches to) a durable JetStream consumer on subject
// bound to stream, with explicit acks, and delivers envelopes to h. ackWait
// should exceed the longest handler run between InProgress pings.
func (c *Client) Consume(stream, subject, durable string, ackWait time.Duration, h EnvelopeHandler) (*nats.Subscription, error) {
	if ackWait <= 0 {
		ackWait = 5 * time.Minute
	}
	sub, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		env, err := UnmarshalEnvelope(msg.Data)
		if err != nil {
			// Unparseable envelopes are poison — Term so they do not loop.
			_ = msg.Term()
			return
		}
		switch h(context.Background(), env, &MessageControl{msg: msg}) {
		case Ack:
			_ = msg.Ack()
		case Nak:
			_ = msg.Nak()
		case Term:
			_ = msg.Term()
		}
	},
		nats.Durable(durable),
		nats.BindStream(stream),
		nats.ManualAck(),
		nats.AckWait(ackWait),
	)
	if err != nil {
		return nil, fmt.Errorf("bus: consume %s on %s (durable %s): %w", subject, stream, durable, err)
	}
	return sub, nil
}

// SubscribeCore subscribes to a core-NATS subject (no JetStream) — the
// control.kill broadcast path (no stream by design).
func (c *Client) SubscribeCore(subject string, h EnvelopeHandler) (*nats.Subscription, error) {
	sub, err := c.nc.Subscribe(subject, func(msg *nats.Msg) {
		env, err := UnmarshalEnvelope(msg.Data)
		if err != nil {
			return
		}
		h(context.Background(), env, &MessageControl{})
	})
	if err != nil {
		return nil, fmt.Errorf("bus: core subscribe %s: %w", subject, err)
	}
	return sub, nil
}
