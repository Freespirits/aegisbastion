-- 000003_data_platform.up.sql
-- Data platform (doc 09): asset inventory (doc 02 §4.1 relational schema,
-- adopted verbatim per Ruling C4), findings store (doc 09 §4.2 with native
-- monthly partitioning), findings lifecycle states per doc 04 §7.3
-- (persisted by 09 per Ruling C4 — see state CHECK below), tenancy schema
-- (doc 09 §4.3), ingest idempotency, and the data-access audit outbox
-- (doc 09 §4.4 — forwarded to gatekeeper's audit of record; no independent
-- hash chain here).

BEGIN;

CREATE SCHEMA IF NOT EXISTS dp;
CREATE SCHEMA IF NOT EXISTS tenancy;

-- ---------------------------------------------------------------------------
-- Asset store — doc 02 §4.1 adopted verbatim (Ruling C4).
-- ---------------------------------------------------------------------------
CREATE TABLE dp.assets (
    asset_id    uuid        PRIMARY KEY,                -- UUIDv7 (doc 09 §12)
    tenant_id   uuid        NOT NULL,
    type        text        NOT NULL,                   -- domain|subdomain|ip|netblock|cert|cloud_resource
    value       text        NOT NULL,                   -- canonical: punycode fqdn lowercased; ip as text; cidr; cert sha256; cloud arn/resource-id
    attributes  jsonb       NOT NULL DEFAULT '{}',      -- {dns:[], cnames:[], asn, depth, wildcard, cloud:{…}, cert:{…}}
    confidence  real        NOT NULL,                   -- 0..1 (doc 02 §4.4)
    status      text        NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','candidate','expired','quarantined')),
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    roe_id      text        NOT NULL,                   -- gatekeeper RoE record this asset was discovered under
    UNIQUE (tenant_id, type, value)
);
CREATE INDEX assets_attributes_gin ON dp.assets USING gin (attributes);
CREATE INDEX assets_active_idx     ON dp.assets (tenant_id) WHERE status = 'active';

CREATE TABLE dp.asset_edges (
    edge_id     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL,
    src         uuid        NOT NULL REFERENCES dp.assets (asset_id),
    dst         uuid        NOT NULL REFERENCES dp.assets (asset_id),
    rel         text        NOT NULL,                   -- resolves_to|cname_to|san_of|hosted_in|belongs_to_asn|cert_for
    attributes  jsonb       NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    UNIQUE (tenant_id, src, dst, rel)
);

-- Raw-finding provenance (doc 02 §4.1 `findings`): every source observation
-- that fed an asset. Distinct from the vulnerability findings store below.
CREATE TABLE dp.finding_provenance (
    finding_id      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         text,                               -- Orchestrator-assigned task id (text: tsk_… ULIDs)
    order_id        uuid,                               -- discover order id, when applicable
    tenant_id       uuid        NOT NULL,
    asset_id        uuid        REFERENCES dp.assets (asset_id),
    source          text        NOT NULL,               -- crt.sh|censys|nuclei|…
    observed_at     timestamptz NOT NULL,
    evidence_uri    text,
    confidence_hint real
);
CREATE INDEX finding_provenance_order_idx ON dp.finding_provenance (order_id);
CREATE INDEX finding_provenance_task_idx  ON dp.finding_provenance (task_id);

-- ---------------------------------------------------------------------------
-- Findings store (doc 09 §4.2) — vulnerability findings with lifecycle.
-- Native RANGE partitioning by created_at (monthly partitions; default
-- partition keeps MVP inserts safe until the partition cron lands).
-- State enum follows doc 04 §7.3 (findings lifecycle, persisted by 09 per
-- Ruling C4) — it supersedes the state CHECK sketched in doc 09 §4.2.
-- ---------------------------------------------------------------------------
CREATE TABLE dp.findings (
    tenant_id     uuid        NOT NULL,
    finding_id    uuid        NOT NULL,                 -- UUIDv7
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    asset_uid     uuid        NOT NULL,                 -- dp.assets.asset_id
    module        text        NOT NULL,                 -- detect|ai-redteam|ddos-sim|phish-catcher
    check_id      text        NOT NULL,                 -- 'CVE-2024-XXXX', 'prompt-injection-direct', 'phish-catcher/<check>'
    title         text        NOT NULL,
    severity      text        NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    -- doc 04 §7.3 lifecycle state machine:
    -- new → triaged → validating → confirmed_open → remediation_claimed → verified_closed
    --        ↘ false_positive      ↘ accepted_risk      ↘ reopened → confirmed_open
    state         text        NOT NULL DEFAULT 'new'
                  CHECK (state IN ('new','triaged','validating','confirmed_open',
                                   'remediation_claimed','verified_closed',
                                   'false_positive','accepted_risk','reopened')),
    fingerprint   text,                                 -- doc 04 §7.2 dedup fingerprint (sha256)
    validation    jsonb       NOT NULL,                 -- {status: unvalidated|runtime_validated, verdict, method, evidence_ref, validated_at}
    risk          jsonb       NOT NULL,                 -- {score, tier: P1..P5, vector:{…}, epss, kev, factors} (doc 04 §8 risk-v1)
    evidence_ref  text,                                 -- s3://… (encrypted, tenant-scoped key)
    occurrence    int         NOT NULL DEFAULT 1,
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    task_id       text,                                 -- authoring Orchestrator task (attribution)
    compliance    jsonb,                                -- {frameworks: ['PCI-DSS:6.2', …]}
    legal_hold    boolean     NOT NULL DEFAULT false,   -- freezes the retention subtree (doc 09 §10)
    sensitive     boolean     NOT NULL DEFAULT false,   -- access-audited on every read (doc 09 §9.5)
    PRIMARY KEY (tenant_id, finding_id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE dp.findings_default PARTITION OF dp.findings DEFAULT;

CREATE INDEX findings_state_sev_idx  ON dp.findings (tenant_id, state, severity);
CREATE INDEX findings_asset_idx      ON dp.findings (tenant_id, asset_uid);
CREATE INDEX findings_task_idx       ON dp.findings (tenant_id, task_id);
CREATE INDEX findings_fingerprint_ix ON dp.findings (tenant_id, fingerprint);

-- Lifecycle transition history (doc 04 §7.3 states are persisted by 09).
CREATE TABLE dp.finding_state_transitions (
    id           bigserial   PRIMARY KEY,
    tenant_id    uuid        NOT NULL,
    finding_id   uuid        NOT NULL,
    from_state   text,
    to_state     text        NOT NULL,
    actor        jsonb       NOT NULL,                  -- {type: module|human|commander, id}
    task_id      text,                                  -- e.g. detect.revalidate task driving remediation_claimed → verified_closed/reopened
    note         text,
    ts           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_transitions_idx ON dp.finding_state_transitions (tenant_id, finding_id, ts);

-- ---------------------------------------------------------------------------
-- Ingest idempotency (doc 09 §2.2/§3.1): one row per accepted batch.
-- ---------------------------------------------------------------------------
CREATE TABLE dp.ingest_batches (
    idempotency_key  text        PRIMARY KEY,
    tenant_id        uuid        NOT NULL,
    task_id          text,                              -- R1+ batches must carry a gatekeeper Scope Token…
    scope_token_jti  text,                              -- …whose jti is recorded here after JWKS re-verification
    status           text        NOT NULL DEFAULT 'accepted'
                     CHECK (status IN ('accepted','rejected','partial')),
    reject_reason    text,                              -- RFC 9457 reason code (AUTHORIZATION_UNVERIFIABLE, …)
    counts           jsonb       NOT NULL DEFAULT '{}', -- {assets_upserted, edges_upserted, findings_inserted}
    received_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Data-access audit outbox (doc 09 §4.4): domain actions only, forwarded to
-- gatekeeper audit-service. No hash chain here (Ruling B).
-- ---------------------------------------------------------------------------
CREATE TABLE dp.audit_outbox (
    audit_id      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ts            timestamptz NOT NULL DEFAULT now(),
    tenant_id     uuid,
    actor         jsonb       NOT NULL,                 -- {type: commander|service|human, id}
    action        text        NOT NULL,                 -- ingest.batch|ingest.rejected|query.evidence_access|retention.purge|admin.action
    object_ref    text,
    params_hash   text,                                 -- sha256
    forwarded_at  timestamptz                           -- null = pending forward to gatekeeper
);
CREATE INDEX audit_outbox_pending_idx ON dp.audit_outbox (audit_id) WHERE forwarded_at IS NULL;

-- ---------------------------------------------------------------------------
-- Tenancy (doc 09 §4.3) — separate schema, blast-radius isolation.
-- scopes/roe_documents/issued_tokens are NOT here: they are gatekeeper's.
-- ---------------------------------------------------------------------------
CREATE TABLE tenancy.retention_profiles (
    retention_profile_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 text NOT NULL UNIQUE,
    policy               jsonb NOT NULL                 -- per-data-class retention rules (doc 09 §10 defaults)
);

CREATE TABLE tenancy.tenants (
    tenant_id            uuid PRIMARY KEY,              -- UUIDv7
    name                 text NOT NULL,
    tier                 text NOT NULL DEFAULT 'standard',
    data_region          text NOT NULL DEFAULT 'local',
    retention_profile_id uuid REFERENCES tenancy.retention_profiles (retention_profile_id),
    status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','offboarded')),
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenancy.workspaces (
    tenant_id     uuid NOT NULL REFERENCES tenancy.tenants (tenant_id),
    workspace_id  uuid NOT NULL DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id)
);

-- dp data-access grants only (platform-wide RBAC is gatekeeper rbac-service).
CREATE TABLE tenancy.grants (
    grant_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenancy.tenants (tenant_id),
    principal  text        NOT NULL,
    role       text        NOT NULL
               CHECK (role IN ('admin','analyst','viewer','service_discover','service_monitor',
                               'service_detect','service_alert','service_ddos','service_redteam',
                               'service_phish','commander')),
    granted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, principal, role)
);

-- Default fixed retention profile (doc 09 §10/§11 MVP: fixed profile).
INSERT INTO tenancy.retention_profiles (name, policy) VALUES (
    'default',
    '{
       "findings_open": "indefinite",
       "findings_resolved": "P2Y",
       "asset_attr_history_inline": "P90D",
       "asset_attr_history_archive": "P7Y",
       "events_hot": "P90D",
       "evidence_blobs": "finding+P90D"
     }'::jsonb
);

COMMIT;
