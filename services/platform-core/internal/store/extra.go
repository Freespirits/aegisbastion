package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Agent Registry (platform.agents, doc 01 §5.8)
// ---------------------------------------------------------------------------

// RegisterAgent upserts by SPIFFE ID: first registration assigns a new
// agent_id; re-registration (version change, restart) updates the manifest
// and keeps the identity (doc 01 §9 item 1). QUARANTINED/REVOKED agents stay
// quarantined — re-registration does not lift a quarantine.
func (s *Store) RegisterAgent(ctx context.Context, a *Agent) error {
	return s.Pool.QueryRow(ctx, `
		INSERT INTO platform.agents
		    (agent_id, agent_type, version, build_hash, capabilities, spiffe_id,
		     limits, region, sandboxed, status, last_heartbeat_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ONLINE', now())
		ON CONFLICT (spiffe_id) DO UPDATE SET
		    version          = EXCLUDED.version,
		    build_hash       = EXCLUDED.build_hash,
		    capabilities     = EXCLUDED.capabilities,
		    limits           = EXCLUDED.limits,
		    region           = EXCLUDED.region,
		    sandboxed        = EXCLUDED.sandboxed,
		    status           = CASE WHEN platform.agents.status IN ('QUARANTINED','REVOKED')
		                            THEN platform.agents.status ELSE 'ONLINE' END,
		    last_heartbeat_at = now(),
		    updated_at        = now()
		RETURNING agent_id, status, registered_at`,
		a.AgentID, a.AgentType, a.Version, a.BuildHash, mustJSON(a.Capabilities), a.SpiffeID,
		map[string]int{"max_concurrent_tasks": a.MaxConcurrent}, a.Region, a.Sandboxed,
	).Scan(&a.AgentID, &a.Status, &a.RegisteredAt)
}

// GetAgent fetches an agent by id.
func (s *Store) GetAgent(ctx context.Context, agentID string) (*Agent, error) {
	a := &Agent{}
	var limits map[string]int
	err := s.Pool.QueryRow(ctx, `
		SELECT agent_id, agent_type, version, build_hash, capabilities, spiffe_id,
		       limits, COALESCE(region,''), sandboxed, status, last_heartbeat_at, registered_at
		FROM platform.agents WHERE agent_id = $1`, agentID,
	).Scan(&a.AgentID, &a.AgentType, &a.Version, &a.BuildHash, &a.Capabilities, &a.SpiffeID,
		&limits, &a.Region, &a.Sandboxed, &a.Status, &a.LastHeartbeat, &a.RegisteredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.MaxConcurrent = limits["max_concurrent_tasks"]
	return a, nil
}

// TouchHeartbeat records a heartbeat and returns the agent (for kill-flag
// evaluation); returns ErrNotFound for unknown agents.
func (s *Store) TouchHeartbeat(ctx context.Context, agentID string) (*Agent, error) {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE platform.agents SET last_heartbeat_at = now(), updated_at = now(),
		    status = CASE WHEN status = 'OFFLINE' THEN 'ONLINE' ELSE status END
		WHERE agent_id = $1 AND status NOT IN ('QUARANTINED','REVOKED')`, agentID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetAgent(ctx, agentID)
}

// MarkStaleAgentsOffline flips ONLINE agents whose heartbeat TTL expired to
// OFFLINE and returns them (their in-flight tasks get redelivered, doc 01
// §13 "Agent crash mid-task").
func (s *Store) MarkStaleAgentsOffline(ctx context.Context, ttl time.Duration) ([]*Agent, error) {
	rows, err := s.Pool.Query(ctx, `
		UPDATE platform.agents SET status = 'OFFLINE', updated_at = now()
		WHERE status = 'ONLINE'
		  AND (last_heartbeat_at IS NULL OR last_heartbeat_at < now() - $1::interval)
		RETURNING agent_id`, intervalSeconds(ttl))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, &Agent{AgentID: id, Status: AgentOffline})
	}
	return out, rows.Err()
}

// SetAgentStatus forces a status (quarantine / revoke).
func (s *Store) SetAgentStatus(ctx context.Context, agentID, status string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE platform.agents SET status = $2, updated_at = now() WHERE agent_id = $1`,
		agentID, status)
	return err
}

// ListCapable returns ONLINE agents offering capability at a risk ceiling ≥
// the task's risk class, with their in-flight load, least-loaded first
// (capability matching, doc 01 §8.3/§9 item 2). The registry blocklist is
// enforced by filtering to ONLINE only (doc 01 §13: QUARANTINED/REVOKED
// checked at dispatch).
func (s *Store) ListCapable(ctx context.Context, capability string, riskRank int) ([]*Agent, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT a.agent_id, a.agent_type, a.version, a.build_hash, a.capabilities, a.spiffe_id,
		       a.limits, COALESCE(a.region,''), a.sandboxed, a.status, a.last_heartbeat_at,
		       (SELECT count(*) FROM platform.tasks t
		         WHERE t.assigned_agent_id = a.agent_id
		           AND t.state IN ('DISPATCHED','RUNNING')) AS in_flight
		FROM platform.agents a
		WHERE a.status = 'ONLINE'
		  AND a.capabilities @> $1::jsonb
		ORDER BY in_flight ASC, a.registered_at ASC`,
		mustJSON([]map[string]string{{"name": capability}}))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a := &Agent{}
		var limits map[string]int
		if err := rows.Scan(&a.AgentID, &a.AgentType, &a.Version, &a.BuildHash, &a.Capabilities,
			&a.SpiffeID, &limits, &a.Region, &a.Sandboxed, &a.Status, &a.LastHeartbeat, &a.InFlightTasks); err != nil {
			return nil, err
		}
		a.MaxConcurrent = limits["max_concurrent_tasks"]
		// risk_class_max must cover the task's declared risk class.
		ok := false
		for _, c := range a.Capabilities {
			if c.Name == capability && RiskRank(c.RiskClassMax) >= riskRank {
				ok = true
				break
			}
		}
		// Capacity: limits.max_concurrent_tasks (0 = unlimited).
		if ok && (a.MaxConcurrent <= 0 || a.InFlightTasks < a.MaxConcurrent) {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// CapabilityExists reports whether any registered agent (any status) offers
// the capability, and the highest risk_class_max offered (plan validation,
// doc 01 §6.1 step 4: "capability must exist in registry").
func (s *Store) CapabilityExists(ctx context.Context, name string) (bool, string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT capabilities FROM platform.agents
		WHERE capabilities @> $1::jsonb`,
		mustJSON([]map[string]string{{"name": name}}))
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	best := ""
	for rows.Next() {
		var caps []Capability
		if err := rows.Scan(&caps); err != nil {
			return false, "", err
		}
		for _, c := range caps {
			if c.Name == name && RiskRank(c.RiskClassMax) > RiskRank(best) {
				best = c.RiskClassMax
			}
		}
	}
	return best != "", best, rows.Err()
}

// RegisteredCapabilities returns the live capability view (PlannerService
// ListCapabilities, doc 01 §7.2): distinct capability × agent_type pairs
// from ONLINE agents.
func (s *Store) RegisteredCapabilities(ctx context.Context) (map[string][]CapabilityAgentType, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT agent_type, capabilities FROM platform.agents WHERE status = 'ONLINE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]CapabilityAgentType{}
	for rows.Next() {
		var agentType string
		var caps []Capability
		if err := rows.Scan(&agentType, &caps); err != nil {
			return nil, err
		}
		for _, c := range caps {
			key := c.Name + "|" + c.RiskClassMax + "|" + c.SchemaVersion + "|" + agentType
			out[key] = append(out[key], CapabilityAgentType{Capability: c, AgentType: agentType})
		}
	}
	return out, rows.Err()
}

// CapabilityAgentType pairs a capability with the agent type offering it.
type CapabilityAgentType struct {
	Capability Capability
	AgentType  string
}

// ---------------------------------------------------------------------------
// Outbox (platform.outbox, doc 01 §13 bus-outage buffering)
// ---------------------------------------------------------------------------

// OutboxMessage is one pending bus publish.
type OutboxMessage struct {
	ID       int64
	EventID  string
	Subject  string
	Payload  []byte // serialized Envelope protobuf
	TraceID  string
	Attempts int
}

// OutboxAdd inserts a pending publish (usually inside the caller's state
// transaction so state change + publish are atomic) and returns the row id.
// The column is jsonb (migration 000001), so the protobuf bytes ride in a
// base64 envelope.
func OutboxAdd(ctx context.Context, tx pgx.Tx, eventID, subject string, payload []byte, traceID string) (int64, error) {
	wrapped := map[string]string{"encoding": "base64", "data": base64.StdEncoding.EncodeToString(payload)}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO platform.outbox (event_id, subject, payload, trace_id)
		VALUES ($1,$2,$3,NULLIF($4,'')) RETURNING id`, eventID, subject, wrapped, traceID).Scan(&id)
	return id, err
}

// DecodeOutboxPayload unwraps the base64 envelope written by OutboxAdd.
func DecodeOutboxPayload(raw []byte) ([]byte, error) {
	var wrapped struct {
		Encoding string `json:"encoding"`
		Data     string `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Encoding != "base64" {
		return nil, fmt.Errorf("unknown outbox payload encoding %q", wrapped.Encoding)
	}
	return base64.StdEncoding.DecodeString(wrapped.Data)
}

// OutboxDrop removes a pending row (used to roll back a publish when the
// audit write on the dispatch critical path failed hard, doc 01 §13).
func (s *Store) OutboxDrop(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM platform.outbox WHERE id = $1 AND published_at IS NULL`, id)
	return err
}

// OutboxPending claims up to limit unpublished rows (SKIP LOCKED so
// replicas can relay concurrently).
func (s *Store) OutboxPending(ctx context.Context, limit int) ([]*OutboxMessage, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, event_id, subject, payload, COALESCE(trace_id,''), attempts
		FROM platform.outbox
		WHERE published_at IS NULL
		ORDER BY id ASC LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OutboxMessage
	for rows.Next() {
		m := &OutboxMessage{}
		var raw []byte
		if err := rows.Scan(&m.ID, &m.EventID, &m.Subject, &raw, &m.TraceID, &m.Attempts); err != nil {
			return nil, err
		}
		payload, err := DecodeOutboxPayload(raw)
		if err != nil {
			return nil, err
		}
		m.Payload = payload
		out = append(out, m)
	}
	return out, rows.Err()
}

// OutboxMarkPublished records a successful publish.
func (s *Store) OutboxMarkPublished(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE platform.outbox SET published_at = now() WHERE id = $1`, id)
	return err
}

// OutboxMarkAttempt records a failed publish attempt (retry next pass).
func (s *Store) OutboxMarkAttempt(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE platform.outbox SET attempts = attempts + 1 WHERE id = $1`, id)
	return err
}

// ---------------------------------------------------------------------------
// Kill switches (platform.kill_switches, doc 01 §10.5)
// ---------------------------------------------------------------------------

// EngageKillSwitch sets the flag checked by the Scheduler (in addition to
// the control.kill broadcast).
func (s *Store) EngageKillSwitch(ctx context.Context, scope, scopeID, engagedBy, reason string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO platform.kill_switches (scope, scope_id, engaged, engaged_by, reason, engaged_at)
		VALUES ($1,$2,true,$3,$4,now())
		ON CONFLICT (scope, scope_id) DO UPDATE SET
		    engaged = true, engaged_by = EXCLUDED.engaged_by,
		    reason = EXCLUDED.reason, engaged_at = now(), updated_at = now()`,
		scope, scopeID, engagedBy, reason)
	return err
}

// KillSwitchesEngaged returns the currently engaged (scope, scope_id) pairs.
func (s *Store) KillSwitchesEngaged(ctx context.Context) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT scope, scope_id FROM platform.kill_switches WHERE engaged`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var scope, id string
		if err := rows.Scan(&scope, &id); err != nil {
			return nil, err
		}
		out[scope+"/"+id] = true
	}
	return out, rows.Err()
}

func intervalSeconds(d time.Duration) string {
	return fmt.Sprintf("%f seconds", d.Seconds())
}
