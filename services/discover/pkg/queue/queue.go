// Package queue is Discover's module-internal JetStream plumbing (doc 02
// §2.2 data plane): per-technique task lanes (workqueue), the worker →
// reducer results subject, and the poison-task DLQ.
//
// The DISCOVER_TASKS stream is module-internal plumbing (doc 02 §2.2 — like
// MONITOR_JOBS for doc 03) and is therefore ensured by the module itself at
// startup (idempotent AddStream), not by deploy/jetstream-bootstrap, which
// owns only the cross-module DISCOVER_EVENTS stream. This keeps the module
// self-contained and leaves shared bootstrap files untouched.
//
// Delivery semantics: at-least-once with explicit ack AFTER the store write
// (doc 02 §2.2); consumers must be idempotent — every publish carries a
// deterministic Nats-Msg-Id so JetStream dedups republishes, and the reducer
// additionally dedups on (task, source, asset, observed_at bucket)
// (doc 02 §7.2).
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// Stream is the module-internal work stream.
const Stream = "DISCOVER_TASKS"

// Consumer durables.
const (
	// DurablePrefix prefixes per-lane worker durables (e.g. "worker-passive").
	DurablePrefix = "worker-"
	// DurableReducer is the reducer's results consumer.
	DurableReducer = "reducer"
)

// MaxDeliveries bounds redelivery before a lane task is dead-lettered
// (doc 02 §7.2: retry with exponential backoff, max 5).
const MaxDeliveries = 5

// EnsureStream idempotently creates the module-internal stream.
func EnsureStream(js nats.JetStreamContext) error {
	subjects := []string{
		model.LanePassive, model.LaneCT, model.LaneCloud, model.LaneActive,
		model.SubjectResults, model.SubjectDLQ,
	}
	_, err := js.AddStream(&nats.StreamConfig{
		Name:        Stream,
		Description: "doc 02 §2.2 (module-internal): per-technique task lanes + worker→reducer results + DLQ",
		Subjects:    subjects,
		Retention:   nats.WorkQueuePolicy,
		MaxBytes:    1 << 30,
	})
	if err == nil {
		return nil
	}
	// Already exists (possibly from a previous boot): verify subjects cover
	// ours; update is additive and safe.
	var apiErr *nats.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode == nats.JSErrCodeStreamNameInUse {
		info, gerr := js.StreamInfo(Stream)
		if gerr != nil {
			return fmt.Errorf("queue: stream %s exists but info failed: %w", Stream, gerr)
		}
		have := map[string]bool{}
		for _, s := range info.Config.Subjects {
			have[s] = true
		}
		for _, s := range subjects {
			if !have[s] {
				cfg := info.Config
				cfg.Subjects = append(append([]string{}, info.Config.Subjects...), s)
				if _, uerr := js.UpdateStream(&cfg); uerr != nil {
					return fmt.Errorf("queue: extend stream %s with %s: %w", Stream, s, uerr)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("queue: ensure stream %s: %w", Stream, err)
}

// PublishTask publishes one lane task (Nats-Msg-Id dedups republishes).
func PublishTask(ctx context.Context, js nats.JetStreamContext, t model.Task) error {
	body, err := json.Marshal(t)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(t.Technique.Lane())
	msg.Header.Set(nats.MsgIdHdr, "dtask-"+t.TaskID)
	msg.Data = body
	_, err = js.PublishMsg(msg, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("queue: publish task %s: %w", t.TaskID, err)
	}
	return nil
}

// FindingMsgID is the deterministic JetStream dedup id for one finding
// (redelivery-safe: a worker re-emission collapses at the stream level).
func FindingMsgID(taskID string, a model.Asset) string {
	sum := sha256.Sum256([]byte(taskID + "|" + string(a.Type) + "|" + a.Value))
	return "dres-" + taskID + "-" + hex.EncodeToString(sum[:8])
}

// PublishResult publishes one worker → reducer message on discover.results.
func PublishResult(ctx context.Context, js nats.JetStreamContext, msgID string, m *model.ResultMessage) error {
	m.SchemaVersion = model.SchemaVersion
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(model.SubjectResults)
	msg.Header.Set(nats.MsgIdHdr, msgID)
	msg.Data = body
	_, err = js.PublishMsg(msg, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("queue: publish result %s: %w", msgID, err)
	}
	return nil
}

// PublishDLQ dead-letters a poison lane task with the refusal/panic reason
// (doc 02 §7.2: panic → DLQ with stack + seed).
func PublishDLQ(ctx context.Context, js nats.JetStreamContext, t model.Task, reason string) error {
	rec := map[string]any{
		"schema_version": model.SchemaVersion,
		"task":           t,
		"reason":         reason,
		"dead_at":        time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(model.SubjectDLQ)
	msg.Header.Set(nats.MsgIdHdr, "ddlq-"+t.TaskID)
	msg.Data = body
	_, err = js.PublishMsg(msg, nats.Context(ctx))
	return err
}

// Consumer is a durable pull consumer over one subject of the stream.
type Consumer struct {
	sub *nats.Subscription
}

// SubscribeTasks creates (idempotently) and binds the per-lane worker
// consumer (durable "worker-<lane>" — one durable per pool so pools scale
// independently, doc 02 §2.2). BindStream, not Bind: the consumer must come
// up on a cold stream (same pattern as platform-core's results consumer).
func SubscribeTasks(js nats.JetStreamContext, lane string) (*Consumer, error) {
	durable := DurablePrefix + strings.TrimPrefix(lane, "discover.tasks.")
	sub, err := js.PullSubscribe(lane, durable,
		nats.BindStream(Stream),
		nats.AckWait(2*time.Minute),
		nats.MaxDeliver(MaxDeliveries+1),
		nats.ManualAck(),
	)
	if err != nil {
		return nil, fmt.Errorf("queue: subscribe %s: %w", lane, err)
	}
	return &Consumer{sub: sub}, nil
}

// SubscribeResults creates (idempotently) and binds the reducer's results
// consumer.
func SubscribeResults(js nats.JetStreamContext) (*Consumer, error) {
	sub, err := js.PullSubscribe(model.SubjectResults, DurableReducer,
		nats.BindStream(Stream),
		nats.AckWait(2*time.Minute),
		nats.MaxDeliver(MaxDeliveries+1),
		nats.ManualAck(),
	)
	if err != nil {
		return nil, fmt.Errorf("queue: subscribe %s: %w", model.SubjectResults, err)
	}
	return &Consumer{sub: sub}, nil
}

// Fetch pulls the next batch (blocking up to wait).
func (c *Consumer) Fetch(batch int, wait time.Duration) ([]*nats.Msg, error) {
	msgs, err := c.sub.Fetch(batch, nats.MaxWait(wait))
	if errors.Is(err, nats.ErrTimeout) {
		return nil, nil
	}
	return msgs, err
}

// Close unsubscribes (the durable survives — work resumes on restart).
func (c *Consumer) Close() { _ = c.sub.Unsubscribe() }

// Deliveries returns how often a message was delivered (1 = first).
func Deliveries(msg *nats.Msg) uint64 {
	md, err := msg.Metadata()
	if err != nil {
		return 1
	}
	return md.NumDelivered
}

// DecodeTask unmarshals a lane message.
func DecodeTask(msg *nats.Msg) (model.Task, error) {
	var t model.Task
	if err := json.Unmarshal(msg.Data, &t); err != nil {
		return t, fmt.Errorf("queue: decode task: %w", err)
	}
	return t, nil
}

// DecodeResult unmarshals a results message.
func DecodeResult(msg *nats.Msg) (*model.ResultMessage, error) {
	var m model.ResultMessage
	if err := json.Unmarshal(msg.Data, &m); err != nil {
		return nil, fmt.Errorf("queue: decode result: %w", err)
	}
	return &m, nil
}
