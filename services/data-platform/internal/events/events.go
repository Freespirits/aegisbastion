// Package events publishes the data platform's domain change events
// (doc 09 §2.2 step 4, §3.2) on NATS JetStream as CloudEvents 1.0 JSON with
// the tenantid extension attribute (doc 09 §12). Publishing carries
// Nats-Msg-Id = event id for JetStream dedup (outbox-friendly).
//
// Failure posture (doc 09 §8 "JetStream down"): events are appended to a
// local spill file and a relay replays them in order on recovery — no event
// loss.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Subjects (doc 09 §2.2/§3.2; all captured by the DP_EVENTS stream's
// "dp.>" + "retention.purged" subscriptions — see deploy/jetstream-bootstrap).
const (
	SubjectAssetCreated          = "dp.asset.created"
	SubjectAssetAttributeChanged = "dp.asset.attribute_changed"
	SubjectFindingCreated        = "dp.finding.created"
	SubjectFindingStateChanged   = "dp.finding.state_changed"
	SubjectTaskRollupFinalized   = "dp.task.rollup_finalized"
	SubjectRetentionPurged       = "retention.purged"
)

// Event types inside the CloudEvents envelope (canonical JSON, versioned v1,
// doc 09 §3.3/§12).
const (
	TypeAssetCreated          = "dp.asset.created.v1"
	TypeAssetAttributeChanged = "dp.asset.attribute_changed.v1"
	TypeFindingCreated        = "dp.finding.created.v1"
	TypeFindingStateChanged   = "dp.finding.state_changed.v1"
	TypeTaskRollupFinalized   = "dp.task.rollup_finalized.v1"
	TypeRetentionPurged       = "dp.retention.purged.v1"
)

// Event is one domain change event before serialization.
type Event struct {
	// Type — one of the Type* constants.
	Type string
	// Subject routes the event (one of the Subject* constants).
	Subject string
	// TenantID — mandatory partition key (doc 09 §7), mapped to the
	// CloudEvents tenantid extension.
	TenantID string
	// ObjectRef — e.g. "finding/<uuid>" (CloudEvents subject attribute).
	ObjectRef string
	// Data — the versioned payload (doc 09 §3.3 shape).
	Data map[string]any
	// ID — event id; a fresh UUIDv7 when empty.
	ID string
	// Time — occurred_at; now when zero.
	Time time.Time
}

// cloudEvent is the wire form (CloudEvents 1.0, JSON content mode).
type cloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject,omitempty"`
	Time            string         `json:"time"`
	TenantID        string         `json:"tenantid"`
	DataContentType string         `json:"datacontenttype"`
	Data            map[string]any `json:"data"`
}

// Marshal renders the CloudEvents JSON document.
func Marshal(e Event) ([]byte, error) {
	id := e.ID
	if id == "" {
		id = uuid.Must(uuid.NewV7()).String()
	}
	ts := e.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	ce := cloudEvent{
		SpecVersion:     "1.0",
		ID:              id,
		Source:          "//aegisbastion/dp",
		Type:            e.Type,
		Subject:         e.ObjectRef,
		Time:            ts.UTC().Format(time.RFC3339Nano),
		TenantID:        e.TenantID,
		DataContentType: "application/json",
		Data:            e.Data,
	}
	if ce.Data == nil {
		ce.Data = map[string]any{}
	}
	return json.Marshal(ce)
}

// Publisher emits events to JetStream with spill-file durability.
type Publisher struct {
	js        nats.JetStreamContext
	spillPath string
	log       *slog.Logger

	mu sync.Mutex // serializes spill writes
}

// New builds a Publisher. js may be nil (degraded mode — everything spills).
func New(js nats.JetStreamContext, spillPath string, log *slog.Logger) *Publisher {
	return &Publisher{js: js, spillPath: spillPath, log: log}
}

// Publish emits one event. On JetStream failure the event is appended to the
// spill file (fsync) and nil is returned — the relay replays it (doc 09 §8).
// A spill failure is the only error path.
func (p *Publisher) Publish(ctx context.Context, e Event) error {
	data, err := Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event %s: %w", e.Type, err)
	}
	if p.js != nil {
		msg := nats.NewMsg(e.Subject)
		msg.Data = data
		var ce cloudEvent
		_ = json.Unmarshal(data, &ce)
		msg.Header.Set(nats.MsgIdHdr, ce.ID)
		if _, err := p.js.PublishMsg(msg, nats.Context(ctx)); err == nil {
			return nil
		} else if p.log != nil {
			p.log.Warn("event publish failed; spilling", "subject", e.Subject, "err", err)
		}
	}
	return p.spill(e.Subject, data)
}

// spill appends one event line {subject, data} to the spill file (fsync).
func (p *Publisher) spill(subject string, data []byte) error {
	if p.spillPath == "" {
		return fmt.Errorf("events: JetStream unavailable and no spill file configured (event %s dropped)", subject)
	}
	line, err := json.Marshal(map[string]any{"subject": subject, "data": json.RawMessage(data)})
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := os.OpenFile(p.spillPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// RelayOnce replays pending spill lines in order. On the first failed line
// it stops (order preserved) and retries on the next tick.
func (p *Publisher) RelayOnce(ctx context.Context) (int, error) {
	if p.spillPath == "" || p.js == nil {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := os.ReadFile(p.spillPath)
	if os.IsNotExist(err) || len(raw) == 0 {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	replayed := 0
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' {
			continue
		}
		line := raw[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Subject string          `json:"subject"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return replayed, fmt.Errorf("spill replay: bad line: %w", err)
		}
		msg := nats.NewMsg(rec.Subject)
		msg.Data = rec.Data
		var ce cloudEvent
		if err := json.Unmarshal(rec.Data, &ce); err == nil {
			msg.Header.Set(nats.MsgIdHdr, ce.ID)
		}
		if _, err := p.js.PublishMsg(msg, nats.Context(ctx)); err != nil {
			// Keep this line and everything after it for the next round.
			remaining := raw[start-len(line)-1:]
			if werr := os.WriteFile(p.spillPath, remaining, 0o600); werr != nil {
				return replayed, werr
			}
			return replayed, fmt.Errorf("spill replay publish: %w", err)
		}
		replayed++
	}
	if err := os.Truncate(p.spillPath, 0); err != nil {
		return replayed, err
	}
	return replayed, nil
}

// RelayLoop replays the spill file on a ticker until ctx is cancelled.
func (p *Publisher) RelayLoop(ctx context.Context, tick time.Duration) {
	if p.spillPath == "" || tick <= 0 {
		return
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := p.RelayOnce(ctx); err != nil && p.log != nil {
				p.log.Warn("event spill relay incomplete", "replayed", n, "err", err)
			} else if n > 0 && p.log != nil {
				p.log.Info("event spill replayed", "events", n)
			}
		}
	}
}
