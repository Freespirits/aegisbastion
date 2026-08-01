-- 000001_platform_core.up.sql
-- Platform core & command layer stores (doc 01 §5, §6, §13).
-- Missions, plans, tasks (the scheduler queue), agent registry, bus outbox,
-- kill-switch flags. RoE/approval/token/audit stores are gatekeeper's
-- (000002) — the command layer references RoEs by roe_id/version only
-- (doc 01 §5.4, Ruling B).

BEGIN;

CREATE SCHEMA IF NOT EXISTS platform;

-- ---------------------------------------------------------------------------
-- Missions (doc 01 §5.1, lifecycle §6.1)
-- ---------------------------------------------------------------------------
CREATE TABLE platform.missions (
    mission_id        text        PRIMARY KEY,            -- ULID, server-assigned (msn_…)
    name              text        NOT NULL,
    owning_commander  text        NOT NULL CHECK (owning_commander IN ('cai', 'hexstrike')),
    objective         text        NOT NULL,
    roe_id            text        NOT NULL,               -- gatekeeper roe-service record (no local RoE tables)
    roe_version       integer     NOT NULL,               -- pinned RoE version at creation
    priority          text        NOT NULL DEFAULT 'P3_PLANNED',
    labels            jsonb       NOT NULL DEFAULT '{}',
    created_by        text        NOT NULL,
    state             text        NOT NULL DEFAULT 'DRAFT'
                      CHECK (state IN ('DRAFT','ACTIVE','PAUSED','COMPLETED','PLANNER_DEGRADED','KILLED')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- TaskPlans (commander → Orchestrator, doc 01 §5.2)
-- ---------------------------------------------------------------------------
CREATE TABLE platform.plans (
    plan_id          text        PRIMARY KEY,             -- ULID (pln_…)
    mission_id       text        NOT NULL REFERENCES platform.missions (mission_id),
    submitted_by     text        NOT NULL CHECK (submitted_by IN ('cai', 'hexstrike')),
    delegated_by     text,                                -- commander id on cross-commander delegation
    idempotency_key  text        NOT NULL UNIQUE,         -- e.g. hexstrike:msn_…:plan:7
    verdict          text        CHECK (verdict IN ('ACCEPTED','PARTIAL','REJECTED')),
    verdict_detail   jsonb,                               -- per-task reasons from PlannerAPI PlanVerdict
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX plans_mission_idx ON platform.plans (mission_id);

-- ---------------------------------------------------------------------------
-- Tasks — plan spec + runtime state in one row.
-- This table IS the scheduler queue: workers select with
-- SELECT … FOR UPDATE SKIP LOCKED (doc 01 §12). Transitions are written by
-- the Orchestrator only (doc 01 §6.2).
-- ---------------------------------------------------------------------------
CREATE TABLE platform.tasks (
    task_id                 text        PRIMARY KEY,      -- ULID (tsk_…)
    plan_id                 text        NOT NULL REFERENCES platform.plans (plan_id),
    mission_id              text        NOT NULL REFERENCES platform.missions (mission_id),
    task_key                text        NOT NULL,         -- unique within plan
    capability              text        NOT NULL,         -- must exist in registry
    risk_class              text        NOT NULL CHECK (risk_class IN ('R0','R1','R2','R3')),
    targets                 jsonb       NOT NULL,         -- exact-enumerated targets (scope-bound form lives in the token manifest)
    params                  jsonb       NOT NULL DEFAULT '{}',
    depends_on              jsonb       NOT NULL DEFAULT '[]',  -- task_keys within the same plan
    timeout_s               integer     NOT NULL DEFAULT 900,
    max_retries             integer     NOT NULL DEFAULT 0,
    attempt                 integer     NOT NULL DEFAULT 0,
    state                   text        NOT NULL DEFAULT 'PENDING'
                            CHECK (state IN ('PENDING','VALIDATING','QUEUED','DISPATCHED','RUNNING',
                                             'REPORTED','VALIDATED','COMPLETED','REJECTED_UNAUTHORIZED',
                                             'EXPIRED','FAILED','DEAD','KILLED','CANCELLED')),
    rejection_reason        text,
    -- dispatch-time wiring (doc 01 §6.3)
    assigned_agent_id       text,
    authorization_token_jti text,                         -- gatekeeper Scope Token jti (null for R0)
    decision_id             text,                         -- gatekeeper DecisionEvent ref (mandatory for R1+)
    approval_id             text,                         -- four-eyes approval ref (R3 / R2 stress prod)
    deadline                timestamptz,
    dispatched_at           timestamptz,
    started_at              timestamptz,
    finished_at             timestamptz,
    -- TaskResult echo (doc 01 §5.7)
    result_status           text        CHECK (result_status IN ('SUCCEEDED','FAILED','REJECTED_UNAUTHORIZED','KILLED','TIMEOUT')),
    result_summary          jsonb,
    artifact_refs           jsonb,
    targets_touched         jsonb,                        -- cross-checked by audit-service against token scope
    error                   text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (plan_id, task_key)
);
-- Scheduler hot path: pick QUEUED tasks by priority/deadline.
CREATE INDEX tasks_state_queue_idx ON platform.tasks (state, deadline) WHERE state IN ('QUEUED','DISPATCHED','RUNNING');
CREATE INDEX tasks_mission_idx ON platform.tasks (mission_id);
CREATE INDEX tasks_agent_idx   ON platform.tasks (assigned_agent_id) WHERE assigned_agent_id IS NOT NULL;

-- Append-only transition log; every transition also emits an audit event (doc 01 §6.2).
CREATE TABLE platform.task_state_transitions (
    id          bigserial   PRIMARY KEY,
    task_id     text        NOT NULL REFERENCES platform.tasks (task_id),
    from_state  text,
    to_state    text        NOT NULL,
    actor       text        NOT NULL,                     -- orchestrator instance / operator
    reason      text,
    ts          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX task_transitions_task_idx ON platform.task_state_transitions (task_id);

-- ---------------------------------------------------------------------------
-- Agent Registry (doc 01 §5.8 AgentManifest)
-- ---------------------------------------------------------------------------
CREATE TABLE platform.agents (
    agent_id          text        PRIMARY KEY,            -- assigned at first registration (agent_…)
    agent_type        text        NOT NULL
                      CHECK (agent_type IN ('discover','monitor','detect','alert','ddos','phishcatcher','ai-red-team')),
    version           text        NOT NULL,
    build_hash        text        NOT NULL,
    capabilities      jsonb       NOT NULL,               -- [{name, risk_class_max, schema_version}]
    spiffe_id         text        NOT NULL UNIQUE,
    limits            jsonb       NOT NULL DEFAULT '{}',  -- {max_concurrent_tasks}
    region            text,
    sandboxed         boolean     NOT NULL DEFAULT false,
    status            text        NOT NULL DEFAULT 'ONLINE'
                      CHECK (status IN ('ONLINE','OFFLINE','QUARANTINED','REVOKED')),
    last_heartbeat_at timestamptz,                        -- 30 s TTL (doc 01 §8.1); heartbeats also land in KV bucket agent_presence
    registered_at     timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
-- Capability lookup for plan validation ("capability must exist in registry", doc 01 §6.1).
CREATE INDEX agents_capabilities_gin ON platform.agents USING gin (capabilities);
-- Registry blocklist checked at dispatch (doc 01 §13).
CREATE INDEX agents_status_idx ON platform.agents (status) WHERE status IN ('QUARANTINED','REVOKED');

-- ---------------------------------------------------------------------------
-- Outbox — services buffer bus publishes here and replay after bus outage
-- (doc 01 §13 "Bus outage").
-- ---------------------------------------------------------------------------
CREATE TABLE platform.outbox (
    id           bigserial   PRIMARY KEY,
    event_id     text        NOT NULL UNIQUE,             -- ULID; consumers dedupe on it
    subject      text        NOT NULL,
    payload      jsonb       NOT NULL,
    trace_id     text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,                             -- null = pending relay
    attempts     integer     NOT NULL DEFAULT 0
);
CREATE INDEX outbox_pending_idx ON platform.outbox (id) WHERE published_at IS NULL;

-- ---------------------------------------------------------------------------
-- Kill switch — three scopes: global, per-mission, per-agent (doc 01 §10.5).
-- The Scheduler checks this flag in addition to the control.kill broadcast.
-- ---------------------------------------------------------------------------
CREATE TABLE platform.kill_switches (
    scope       text        NOT NULL CHECK (scope IN ('global','mission','agent')),
    scope_id    text        NOT NULL DEFAULT '',          -- mission_id / agent_id; '' for global
    engaged     boolean     NOT NULL DEFAULT false,
    engaged_by  text,
    reason      text,
    engaged_at  timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, scope_id)
);

COMMIT;
