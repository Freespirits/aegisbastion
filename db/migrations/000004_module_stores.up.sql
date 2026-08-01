-- 000004_module_stores.up.sql
-- Module-local operational stores on the platform PostgreSQL 16 instance.
--   discover.* — doc 02 §4.1 producer-side working store (retained per
--                Ruling C4; reducer upserts into dp via the Ingest API)
--   monitor.*  — doc 03 §8 (schema `monitor`)
--   detect.*   — doc 04 §11/§13 MVP fallback findings store (mirrors
--                dp.findings so migration is a copy), fingerprint cache (§7.2),
--                suppression list (§7.3)
-- These are operational stores, not systems of record: assets/findings of
-- record live in the dp schema (000003).

BEGIN;

-- ===========================================================================
-- DISCOVER — producer-side working store (doc 02 §4.1 verbatim + quarantine)
-- ===========================================================================
CREATE SCHEMA IF NOT EXISTS discover;

CREATE TABLE discover.assets (
    asset_id    uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL,
    type        text        NOT NULL,                   -- domain|subdomain|ip|netblock|cert|cloud_resource
    value       text        NOT NULL,                   -- canonical (doc 02 §4.2)
    attributes  jsonb       NOT NULL DEFAULT '{}',
    confidence  real        NOT NULL,
    status      text        NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','candidate','expired','quarantined')),
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    roe_id      text        NOT NULL,
    UNIQUE (tenant_id, type, value)
);
CREATE INDEX discover_assets_attributes_gin ON discover.assets USING gin (attributes);
CREATE INDEX discover_assets_active_idx     ON discover.assets (tenant_id) WHERE status = 'active';

CREATE TABLE discover.asset_edges (
    edge_id     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL,
    src         uuid        NOT NULL REFERENCES discover.assets (asset_id),
    dst         uuid        NOT NULL REFERENCES discover.assets (asset_id),
    rel         text        NOT NULL,                   -- resolves_to|cname_to|san_of|hosted_in|belongs_to_asn|cert_for
    attributes  jsonb       NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    UNIQUE (tenant_id, src, dst, rel)
);

CREATE TABLE discover.discovery_orders (
    order_id    uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL,
    request     jsonb       NOT NULL,                   -- DiscoveryOrder as submitted
    state       text        NOT NULL DEFAULT 'PENDING'
                CHECK (state IN ('PENDING','RUNNING','PARTIAL','COMPLETED','FAILED','CANCELLED','DENIED')),
    gate        jsonb,                                  -- {decision, reasons[], roe_id, decision_id, decided_at}
    progress    jsonb       NOT NULL DEFAULT '{}',      -- {tasks_total, done, failed, assets_found, new_assets}
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE discover.findings (
    finding_id      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         text,                               -- worker task (uuid in doc 02 wire form; text to hold platform ULIDs too)
    order_id        uuid        REFERENCES discover.discovery_orders (order_id),
    tenant_id       uuid        NOT NULL,
    asset_id        uuid        REFERENCES discover.assets (asset_id),
    source          text        NOT NULL,
    observed_at     timestamptz NOT NULL,
    evidence_uri    text,
    confidence_hint real
);
CREATE INDEX discover_findings_order_idx ON discover.findings (order_id);

-- Out-of-scope raw findings land here with a reason code, never in assets
-- (doc 02 §4.2).
CREATE TABLE discover.quarantined_findings (
    finding_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL,
    order_id     uuid        REFERENCES discover.discovery_orders (order_id),
    asset        jsonb       NOT NULL,                  -- {type, value, attributes}
    source       text        NOT NULL,
    reason_code  text        NOT NULL,                  -- OUT_OF_SCOPE|EXCLUDED|UNVALIDATED_GUESS|…
    observed_at  timestamptz NOT NULL,
    quarantined_at timestamptz NOT NULL DEFAULT now()
);

-- Local durability spool only; rows forward to gatekeeper audit-service (the
-- audit of record) and are marked forwarded_at (doc 02 §4.1).
CREATE TABLE discover.audit_spool (
    seq          bigserial   PRIMARY KEY,
    tenant_id    uuid,
    actor        jsonb       NOT NULL,
    action       text        NOT NULL,
    target       text,
    payload      jsonb,
    ts           timestamptz NOT NULL DEFAULT now(),
    forwarded_at timestamptz
);
CREATE INDEX discover_audit_spool_pending_idx ON discover.audit_spool (seq) WHERE forwarded_at IS NULL;

-- ===========================================================================
-- MONITOR (doc 03 §8, schema `monitor`)
-- ===========================================================================
CREATE SCHEMA IF NOT EXISTS monitor;

CREATE TABLE monitor.watch_assets (
    watch_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        uuid        NOT NULL,               -- dp.assets.asset_id
    mission_id      text        NOT NULL,
    identifier      text        NOT NULL,               -- canonical probe target (fqdn/ip/url)
    cadence_profile text        NOT NULL,               -- doc 03 §6.4 profile name
    next_due_at     timestamptz NOT NULL,               -- persisted scheduler heap
    fast_until      timestamptz,                        -- fast-cadence window after a change
    last_probe_at   timestamptz,
    state           text        NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active','paused','removed')),
    UNIQUE (mission_id, identifier)
);
CREATE INDEX watch_assets_due_idx ON monitor.watch_assets (next_due_at) WHERE state = 'active';

-- One row per asset × probe_type; hot read path for diffing.
-- NOTE: snapshot_id is `text` (prefixed ULID "snp_…", doc 03 §6.2) as of
-- migration 000006 — the uuid declaration below was corrected there.
CREATE TABLE monitor.snapshots_latest (
    asset_id      uuid        NOT NULL,
    probe_type    text        NOT NULL,                 -- dns|tls|http (MVP; tcp_port is Later)
    snapshot_id   uuid        NOT NULL,
    content_hash  text        NOT NULL,
    probe_ts      timestamptz NOT NULL,
    status        text        NOT NULL,                 -- ok|error|timeout
    PRIMARY KEY (asset_id, probe_type)
);

-- Insert only on change; monthly partitions; 90 d hot retention.
CREATE TABLE monitor.snapshots_history (
    snapshot_id   uuid        NOT NULL,
    asset_id      uuid        NOT NULL,
    probe_type    text        NOT NULL,
    probe_ts      timestamptz NOT NULL,
    content_hash  text        NOT NULL,
    data          jsonb       NOT NULL,                 -- SnapshotDocument v1 (doc 03 §6.2)
    raw_ref       text,                                 -- MinIO ref for raw body (30 d lifecycle)
    PRIMARY KEY (snapshot_id, probe_ts)
) PARTITION BY RANGE (probe_ts);
CREATE TABLE monitor.snapshots_history_default PARTITION OF monitor.snapshots_history DEFAULT;
CREATE INDEX snapshots_history_asset_idx ON monitor.snapshots_history (asset_id, probe_type, probe_ts DESC);

-- Append-only; monthly partitions; 400 d retention (aligns with audit hot retention).
CREATE TABLE monitor.change_events (
    event_id     text        NOT NULL,                  -- ULID
    mission_id   text        NOT NULL,
    asset_id     uuid        NOT NULL,
    change_type  text        NOT NULL,                  -- doc 03 §5.2 enum
    severity     text        NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    fingerprint  text        NOT NULL,
    payload      jsonb       NOT NULL,                  -- MonitorChange v1
    occurred_at  timestamptz NOT NULL,
    PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);
CREATE TABLE monitor.change_events_default PARTITION OF monitor.change_events DEFAULT;
CREATE INDEX change_events_mission_idx ON monitor.change_events (mission_id, occurred_at);
CREATE INDEX change_events_fp_idx      ON monitor.change_events (fingerprint, occurred_at);

-- Transactional with change_events insert; M6 relay publishes and marks.
CREATE TABLE monitor.event_outbox (
    event_id     text        PRIMARY KEY,
    subject      text        NOT NULL,                  -- monitor.changes|monitor.alert|monitor.assets.new
    payload      jsonb       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX monitor_outbox_pending_idx ON monitor.event_outbox (created_at) WHERE published_at IS NULL;

-- 24 h fingerprint dedup window (doc 01 §6.4 monitor fan-in).
CREATE TABLE monitor.dedup_window (
    fingerprint    text        PRIMARY KEY,
    first_event_id text        NOT NULL,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    count          integer     NOT NULL DEFAULT 1,
    expires_at     timestamptz NOT NULL DEFAULT (now() + interval '24 hours')
);
CREATE INDEX dedup_window_expiry_idx ON monitor.dedup_window (expires_at);

CREATE TABLE monitor.baselines (
    rule_id      text        PRIMARY KEY,
    mission_id   text        NOT NULL,
    name         text        NOT NULL,
    rego_ref     text        NOT NULL,                  -- compiled Rego ref
    config       jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE monitor.baseline_state (
    asset_id  uuid        NOT NULL,
    rule_id   text        NOT NULL REFERENCES monitor.baselines (rule_id),
    state     text        NOT NULL,                     -- in_baseline|drifted
    since     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, rule_id)
);

CREATE TABLE monitor.exposure_state (
    asset_id   uuid        NOT NULL,
    rule_id    text        NOT NULL,                    -- exposure rule id (doc 03 §7.4)
    state      text        NOT NULL CHECK (state IN ('open','closed')),
    opened_at  timestamptz NOT NULL DEFAULT now(),
    closed_at  timestamptz,
    PRIMARY KEY (asset_id, rule_id)
);

-- Suppressions gate outbound emission; they never delete change_events history.
CREATE TABLE monitor.suppressions (
    suppression_id uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    selector       jsonb       NOT NULL,                -- {mission?|asset?|rule?|change_type?}
    reason         text        NOT NULL,
    created_by     text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL
);

-- DLQ for poison scan jobs (fail-closed dead-lettering, doc 03 §9.2).
CREATE TABLE monitor.scan_jobs_dead (
    id         bigserial   PRIMARY KEY,
    job        jsonb       NOT NULL,
    error      text,
    attempts   integer     NOT NULL DEFAULT 0,
    dead_at    timestamptz NOT NULL DEFAULT now()
);

-- ===========================================================================
-- DETECT — MVP fallback store (doc 04 §13: mirrors dp.findings so migration
-- is a copy once 09 ships), fingerprint cache (§7.2), suppression list (§7.3)
-- ===========================================================================
CREATE SCHEMA IF NOT EXISTS detect;

CREATE TABLE detect.findings_fallback (
    tenant_id     uuid        NOT NULL,
    finding_id    uuid        NOT NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    asset_uid     uuid,
    module        text        NOT NULL DEFAULT 'detect',
    check_id      text        NOT NULL,
    title         text        NOT NULL,
    severity      text        NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    state         text        NOT NULL DEFAULT 'new'
                  CHECK (state IN ('new','triaged','validating','confirmed_open',
                                   'remediation_claimed','verified_closed',
                                   'false_positive','accepted_risk','reopened')),
    fingerprint   text,
    validation    jsonb       NOT NULL,
    risk          jsonb       NOT NULL,
    evidence_ref  text,
    occurrence    int         NOT NULL DEFAULT 1,
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    task_id       text,
    compliance    jsonb,
    PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX detect_fallback_fp_idx ON detect.findings_fallback (tenant_id, fingerprint);

-- Cross-run dedup cache (doc 04 §7.2 D8; authoritative view is 09's query API).
CREATE TABLE detect.fingerprints (
    fingerprint  text        PRIMARY KEY,               -- sha256(scope_key|target|port/scheme|path|vuln_identity)
    tenant_id    uuid        NOT NULL,
    finding_id   uuid        NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    occurrences  integer     NOT NULL DEFAULT 1
);

-- false_positive suppression signatures with monthly expiry (doc 04 §7.3).
CREATE TABLE detect.suppressions (
    signature_hash text        PRIMARY KEY,
    tenant_id      uuid        NOT NULL,
    check_id       text,
    reason         text        NOT NULL,
    created_by     text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL DEFAULT (now() + interval '30 days')
);

COMMIT;
