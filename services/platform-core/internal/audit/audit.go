// Package audit implements the platform's hash-chained, append-only
// operational audit log (doc 01 §5.9, §10.4). Each event:
//
//	hash = "sha256:" + hex( sha256( prev_hash || canonical(event minus hash) ) )
//
// The canonical form is deterministic JSON (compact, sorted keys — Go's
// encoding/json orders map keys); every hashed value is a string/integer, so
// no float-canonicalization corner cases arise. The chain tip is read and the
// next link inserted under a Postgres advisory transaction lock, keeping the
// chain consistent across concurrent writers and replicas.
//
// Failure posture (doc 01 §13 "Audit write failure"): dispatch is on the
// audit critical path. When the DB write fails, the caller may spill the
// event to a local file (fsync) before proceeding; spilled events are
// replayed into the chain when the DB recovers.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
)

// advisoryLockID serializes chain-tip reads/writes platform-wide.
const advisoryLockID int64 = 0x7374726b3438 // "strk48"

// EventType mirrors platformv1.AuditEventType names (kept as strings so the
// package has no protobuf dependency).
type EventType string

const (
	MissionCreated EventType = "MISSION_CREATED"
	PlanSubmitted  EventType = "PLAN_SUBMITTED"
	AuthzDecision  EventType = "AUTHZ_DECISION"
	TaskDispatched EventType = "TASK_DISPATCHED"
	TargetTouched  EventType = "TARGET_TOUCHED"
	TaskResult     EventType = "TASK_RESULT"
	ROERevoked     EventType = "ROE_REVOKED"
	KillSwitch     EventType = "KILL_SWITCH"
	ScopeViolation EventType = "SCOPE_VIOLATION"
)

// Actor identifies who caused an event (doc 01 §5.9).
type Actor struct {
	Kind string `json:"kind"` // "service" | "commander" | "user" | "agent"
	ID   string `json:"id"`
}

// Subject links an event to the entities it concerns (doc 01 §5.9).
type Subject struct {
	MissionID string `json:"mission_id,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
	RoeID     string `json:"roe_id,omitempty"`
}

// Event is one link in the chain.
type Event struct {
	EventID  string         `json:"event_id"`
	Seq      uint64         `json:"seq"`
	TS       time.Time      `json:"ts"`
	Type     EventType      `json:"type"`
	Actor    Actor          `json:"actor"`
	Subject  Subject        `json:"subject"`
	Payload  map[string]any `json:"payload"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// canonicalJSON renders the event minus its hash deterministically.
func canonicalJSON(e *Event) ([]byte, error) {
	type wire struct {
		EventID  string         `json:"event_id"`
		Seq      uint64         `json:"seq"`
		TS       string         `json:"ts"`
		Type     EventType      `json:"type"`
		Actor    Actor          `json:"actor"`
		Subject  Subject        `json:"subject"`
		Payload  map[string]any `json:"payload"`
		PrevHash string         `json:"prev_hash"`
	}
	payload := e.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	return json.Marshal(wire{
		EventID:  e.EventID,
		Seq:      e.Seq,
		TS:       e.TS.UTC().Format(time.RFC3339Nano),
		Type:     e.Type,
		Actor:    e.Actor,
		Subject:  e.Subject,
		Payload:  payload,
		PrevHash: e.PrevHash,
	})
}

// computeHash derives the link hash for an event whose Seq/PrevHash are set.
func computeHash(e *Event) (string, error) {
	canon, err := canonicalJSON(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(e.PrevHash), canon...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Logger appends events to the chain. Safe for concurrent use.
type Logger struct {
	pool      *pgxpool.Pool
	spillPath string
	mu        sync.Mutex // serializes spill writes
}

// NewLogger builds a Logger. spillPath may be empty (no last-resort spill).
func NewLogger(pool *pgxpool.Pool, spillPath string) *Logger {
	return &Logger{pool: pool, spillPath: spillPath}
}

// Log appends one event to the chain. On DB failure the event is spilled to
// the local spill file (fsync) when configured, and SpilledError is returned
// so the caller can decide to proceed (doc 01 §13: fsync before dispatch).
func (l *Logger) Log(ctx context.Context, typ EventType, actor Actor, subj Subject, payload map[string]any) error {
	ev := &Event{
		EventID: ids.New("aud"),
		TS:      time.Now().UTC(),
		Type:    typ,
		Actor:   actor,
		Subject: subj,
		Payload: payload,
	}
	err := l.append(ctx, ev)
	if err == nil {
		return nil
	}
	if l.spillPath != "" {
		if serr := l.spill(ev); serr == nil {
			return &SpilledError{Event: ev, Cause: err}
		} else {
			return fmt.Errorf("audit db write failed (%v) AND spill failed: %w", err, serr)
		}
	}
	return fmt.Errorf("audit db write failed (no spill configured): %w", err)
}

// SpilledError reports that the event was durably spilled instead of chained.
// The dispatch critical path treats this as "audited" per doc 01 §13.
type SpilledError struct {
	Event *Event
	Cause error
}

func (e *SpilledError) Error() string {
	return fmt.Sprintf("audit event %s spilled to file (db: %v)", e.Event.EventID, e.Cause)
}

// append inserts the event as the next chain link.
func (l *Logger) append(ctx context.Context, ev *Event) error {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockID); err != nil {
		return err
	}
	var prev string
	var prevSeq uint64
	err = tx.QueryRow(ctx,
		"SELECT hash, seq FROM platform.audit_events ORDER BY seq DESC LIMIT 1").Scan(&prev, &prevSeq)
	if err != nil {
		prev, prevSeq = "", 0 // genesis
	}
	ev.PrevHash = prev
	ev.Seq = prevSeq + 1
	// timestamptz stores microseconds — truncate BEFORE hashing so the
	// canonical form survives the DB round trip (chain verification).
	ev.TS = ev.TS.UTC().Truncate(time.Microsecond)
	h, err := computeHash(ev)
	if err != nil {
		return err
	}
	ev.Hash = h

	payload := ev.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO platform.audit_events (seq, event_id, ts, type, actor, subject, payload, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		ev.Seq, ev.EventID, ev.TS, string(ev.Type),
		map[string]string{"kind": ev.Actor.Kind, "id": ev.Actor.ID},
		map[string]string{"mission_id": ev.Subject.MissionID, "task_id": ev.Subject.TaskID, "roe_id": ev.Subject.RoeID},
		payload, ev.PrevHash, ev.Hash)
	if err != nil {
		return err
	}
	// Keep the bigserial ahead of the explicitly-chained seq values.
	if _, err := tx.Exec(ctx, `
		SELECT setval('platform.audit_events_seq_seq',
		    COALESCE((SELECT MAX(seq) FROM platform.audit_events), 1))`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// spill writes the event (unhashed — it is re-chained on replay) as one JSON
// line with fsync.
func (l *Logger) spill(ev *Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.spillPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReplaySpill re-chains any spilled events and truncates the spill file.
// Best-effort: individual failures stop the replay (retried next call).
func (l *Logger) ReplaySpill(ctx context.Context) (int, error) {
	if l.spillPath == "" {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.spillPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	replayed := 0
	start := 0
	for i, b := range data {
		if b != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return replayed, fmt.Errorf("spill replay: bad line: %w", err)
		}
		// Re-chain with fresh seq/prev; keep original event id/ts.
		if err := l.append(ctx, &ev); err != nil {
			return replayed, err
		}
		replayed++
	}
	if replayed > 0 {
		if err := os.Truncate(l.spillPath, 0); err != nil {
			return replayed, err
		}
	}
	return replayed, nil
}

// Trail returns events for a mission in chain order (GetAuditTrail, doc 01
// §7.3): events with seq > afterSeq, ascending, capped at limit.
func (l *Logger) Trail(ctx context.Context, missionID string, afterSeq uint64, limit uint32) ([]*Event, error) {
	if limit == 0 || limit > 1000 {
		limit = 200
	}
	rows, err := l.pool.Query(ctx, `
		SELECT event_id, seq, ts, type, actor, subject, payload, prev_hash, hash
		FROM platform.audit_events
		WHERE subject ->> 'mission_id' = $1 AND seq > $2
		ORDER BY seq ASC LIMIT $3`, missionID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		var ev Event
		var typ string
		var actor, subject, payload []byte
		if err := rows.Scan(&ev.EventID, &ev.Seq, &ev.TS, &typ, &actor, &subject, &payload, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, err
		}
		ev.Type = EventType(typ)
		_ = json.Unmarshal(actor, &ev.Actor)
		_ = json.Unmarshal(subject, &ev.Subject)
		_ = json.Unmarshal(payload, &ev.Payload)
		out = append(out, &ev)
	}
	return out, rows.Err()
}

// VerifyChain recomputes hashes over the full chain (auditor helper and
// acceptance-test support). Returns the first failing sequence, or 0 when
// the chain is intact.
func (l *Logger) VerifyChain(ctx context.Context) (uint64, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT event_id, seq, ts, type, actor, subject, payload, prev_hash, hash
		FROM platform.audit_events ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var ev Event
		var typ string
		var actor, subject, payload []byte
		if err := rows.Scan(&ev.EventID, &ev.Seq, &ev.TS, &typ, &actor, &subject, &payload, &ev.PrevHash, &ev.Hash); err != nil {
			return 0, err
		}
		ev.Type = EventType(typ)
		if err := json.Unmarshal(actor, &ev.Actor); err != nil {
			return ev.Seq, fmt.Errorf("seq %d: actor decode: %w", ev.Seq, err)
		}
		if err := json.Unmarshal(subject, &ev.Subject); err != nil {
			return ev.Seq, fmt.Errorf("seq %d: subject decode: %w", ev.Seq, err)
		}
		if err := json.Unmarshal(payload, &ev.Payload); err != nil {
			return ev.Seq, fmt.Errorf("seq %d: payload decode: %w", ev.Seq, err)
		}
		if ev.PrevHash != prev {
			return ev.Seq, nil
		}
		want, err := computeHash(&ev)
		if err != nil {
			return ev.Seq, err
		}
		if want != ev.Hash {
			return ev.Seq, nil
		}
		prev = ev.Hash
	}
	return 0, rows.Err()
}
