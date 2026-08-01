// Package bootstrap applies the small set of schema objects platform-core
// needs that are not covered by db/migrations/000001_platform_core — above
// all the platform's own hash-chained operational audit table (doc 01 §5.9,
// §10.4, §15 step 2 "missions, plans, tasks, registry, audit (+ outbox)").
//
// Why service-side and not a new db/migrations file: db/migrations is owned
// by the data/migrations wave and golang-migrate versions must not collide
// across parallel implementation waves. Everything here is idempotent
// (IF NOT EXISTS / CREATE OR REPLACE), so a later proper migration can adopt
// the same objects without conflict.
package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// auditDDL creates platform.audit_events — the command layer's operational
// hash chain (doc 01 §5.9). Append-only is enforced at the DB layer per doc
// 01 §10.4 ("updates/deletes denied at the DB layer") via a trigger.
const auditDDL = `
CREATE TABLE IF NOT EXISTS platform.audit_events (
    seq       bigserial   PRIMARY KEY,
    event_id  text        NOT NULL UNIQUE,          -- ULID (aud_…)
    ts        timestamptz NOT NULL DEFAULT now(),
    type      text        NOT NULL,                 -- AuditEventType name (MISSION_CREATED, …)
    actor     jsonb       NOT NULL DEFAULT '{}',    -- {kind, id}
    subject   jsonb       NOT NULL DEFAULT '{}',    -- {mission_id, task_id, roe_id}
    payload   jsonb       NOT NULL DEFAULT '{}',
    prev_hash text        NOT NULL DEFAULT '',      -- "sha256:…" of previous link; '' at genesis
    hash      text        NOT NULL                  -- sha256(prev_hash || canonical(event minus hash))
);
CREATE INDEX IF NOT EXISTS audit_events_mission_idx
    ON platform.audit_events ((subject ->> 'mission_id'));
CREATE INDEX IF NOT EXISTS audit_events_task_idx
    ON platform.audit_events ((subject ->> 'task_id'));

CREATE OR REPLACE FUNCTION platform.audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'platform.audit_events is append-only (doc 01 §10.4)';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update ON platform.audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE OR DELETE ON platform.audit_events
    FOR EACH ROW EXECUTE FUNCTION platform.audit_events_append_only();
`

// Ensure applies the idempotent bootstrap DDL. It requires the platform
// schema to exist already (created by db/migrations 000001 via the compose
// db-migrate one-shot).
func Ensure(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, auditDDL); err != nil {
		return fmt.Errorf("bootstrap audit_events: %w", err)
	}
	return nil
}
