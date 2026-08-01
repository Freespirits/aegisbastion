// Package bus wraps the NATS JetStream connection: gatekeeper publishes the
// doc 11 §2.3 subjects (authz.decisions.v1, authz.denials.v1, roe.events.v1,
// tasks.revocations.v1, authz.approvals.v1, audit.anomalies.v1) and consumes
// audit.events for the audit ingest path. Every message is a
// aegisbastion.platform.v1.Envelope (doc 01 §8.2) with an Any-packed payload.
package bus

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
)

// Gatekeeper subjects (doc 11 §2.3; streams provisioned by deploy/jetstream-bootstrap).
const (
	SubjectDecisions   = "authz.decisions.v1"
	SubjectDenials     = "authz.denials.v1"
	SubjectROEEvents   = "roe.events.v1"
	SubjectRevocations = "tasks.revocations.v1"
	SubjectApprovals   = "authz.approvals.v1"
	SubjectAnomalies   = "audit.anomalies.v1"
	// SubjectAuditEvents is the platform-wide audit ingest subject (doc 01 §8.1).
	SubjectAuditEvents = "audit.events"
)

// Publisher publishes typed events to bus subjects. Implemented by *Bus in
// production and by fakes in tests.
type Publisher interface {
	Publish(ctx context.Context, subject string, payload proto.Message) error
}

// Bus is the NATS-backed Publisher.
type Bus struct {
	NC *nats.Conn
	JS nats.JetStreamContext
}

// Connect dials NATS with retry (infra may still be starting).
func Connect(ctx context.Context, natsURL string) (*Bus, error) {
	var nc *nats.Conn
	var err error
	deadline := time.Now().Add(60 * time.Second)
	for {
		nc, err = nats.Connect(natsURL,
			nats.Name("aegisbastion-gatekeeper"),
			nats.Timeout(5*time.Second),
			nats.RetryOnFailedConnect(false),
		)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("bus: connect %s: %w", natsURL, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	return &Bus{NC: nc, JS: js}, nil
}

// Publish wraps payload in a doc 01 §8.2 Envelope and publishes it (JetStream,
// at-least-once). The envelope type is the fully-qualified proto message name.
func (b *Bus) Publish(ctx context.Context, subject string, payload proto.Message) error {
	any, err := anypb.New(payload)
	if err != nil {
		return fmt.Errorf("bus: pack %T: %w", payload, err)
	}
	env := &platformv1.Envelope{
		EventId: ids.New("evt"),
		Type:    string(payload.ProtoReflect().Descriptor().FullName()),
		Ts:      timestamppb.Now(),
		Payload: any,
	}
	raw, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("bus: marshal envelope: %w", err)
	}
	if _, err := b.JS.Publish(subject, raw, nats.Context(ctx)); err != nil {
		return fmt.Errorf("bus: publish %s: %w", subject, err)
	}
	return nil
}

// Close drains the connection.
func (b *Bus) Close() { b.NC.Drain() }

// NopPublisher drops everything (tests, dry paths).
type NopPublisher struct{}

// Publish implements Publisher.
func (NopPublisher) Publish(context.Context, string, proto.Message) error { return nil }
