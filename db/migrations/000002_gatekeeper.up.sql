-- 000002_gatekeeper.up.sql
-- Gatekeeper stores (doc 11): roe-service, token-service (issued-token
-- registry), policy-service (decision records), rbac-service,
-- approval-service, revocation-service, audit-service (hash-chained,
-- append-only). Gatekeeper is the single PDP (Ruling B); nothing else owns
-- these tables.

BEGIN;

CREATE SCHEMA IF NOT EXISTS gatekeeper;

-- ---------------------------------------------------------------------------
-- RoE records (doc 11 §3.1 / doc 01 §5.4).
-- Immutable versions: edits create a new (roe_id, version); only `status`
-- may change in place (lifecycle: draft → pending_approval → active →
-- suspended → expired → revoked), enforced by trigger below.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.roe_records (
    roe_id          text        NOT NULL,
    version         integer     NOT NULL,
    org_id          text        NOT NULL,
    name            text        NOT NULL,
    status          text        NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft','pending_approval','active','suspended','expired','revoked')),
    created_by      text        NOT NULL,
    legal_artifact  jsonb,                              -- {kind, document_sha256, storage_uri, signers[], verified_by, verified_at}
                                                        -- MANDATORY + verified for max_risk_class R2/R3 (doc 11 §3.1)
    authorized_by   jsonb       NOT NULL,               -- {identity, role: customer_authorizer}
    approved_by     jsonb,                              -- operator approval (REQUIRED for R2/R3; four-eyes ref for R3)
    scope           jsonb       NOT NULL,               -- {asset_group_ids[], domains[], cidrs[], cloud_accounts[], explicit_excludes[]}
    constraints     jsonb       NOT NULL DEFAULT '{}',  -- {max_risk_class, allowed_capabilities[], rate_caps{},
                                                        --  blackout_windows[], jurisdictions_allowed[], data_classes[],
                                                        --  requires_approval_for[], azure_pentest_notification_id}
    valid_from      timestamptz NOT NULL,
    valid_until     timestamptz NOT NULL,
    signature       text,                               -- base64url(Ed25519 sign over JCS-canonical RoE)
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (roe_id, version),
    -- ≤ 90 days from valid_from; renewal = new version (doc 11 §3.1)
    CHECK (valid_until <= valid_from + interval '90 days')
);
CREATE INDEX roe_records_org_idx    ON gatekeeper.roe_records (org_id);
CREATE INDEX roe_records_status_idx ON gatekeeper.roe_records (status);

-- Resolved effective target list per RoE version (doc 11 §3.1: domains/CIDRs
-- resolved at activation, re-resolved on asset-inventory changes; tokens bind
-- to that resolved version).
CREATE TABLE gatekeeper.roe_effective_targets (
    roe_id       text        NOT NULL,
    roe_version  integer     NOT NULL,
    target       text        NOT NULL,                  -- canonical host / CIDR / domain
    target_kind  text        NOT NULL CHECK (target_kind IN ('domain','host','cidr','ip','cloud_account','asset_group')),
    excluded     boolean     NOT NULL DEFAULT false,    -- explicit_excludes always win
    resolved_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (roe_id, roe_version, target),
    FOREIGN KEY (roe_id, roe_version) REFERENCES gatekeeper.roe_records (roe_id, version)
);
CREATE INDEX roe_targets_lookup_idx ON gatekeeper.roe_effective_targets (target) WHERE NOT excluded;

-- Immutability: no DELETE; UPDATE may touch only status/updated_at
-- (revocation is a status change; everything else is a new version).
CREATE OR REPLACE FUNCTION gatekeeper.roe_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'roe_records is append-only: deletes are forbidden';
    END IF;
    IF NEW.roe_id          IS DISTINCT FROM OLD.roe_id
       OR NEW.version      IS DISTINCT FROM OLD.version
       OR NEW.org_id       IS DISTINCT FROM OLD.org_id
       OR NEW.name         IS DISTINCT FROM OLD.name
       OR NEW.created_by   IS DISTINCT FROM OLD.created_by
       OR NEW.legal_artifact IS DISTINCT FROM OLD.legal_artifact
       OR NEW.authorized_by IS DISTINCT FROM OLD.authorized_by
       OR NEW.approved_by  IS DISTINCT FROM OLD.approved_by
       OR NEW.scope        IS DISTINCT FROM OLD.scope
       OR NEW.constraints  IS DISTINCT FROM OLD.constraints
       OR NEW.valid_from   IS DISTINCT FROM OLD.valid_from
       OR NEW.valid_until  IS DISTINCT FROM OLD.valid_until
       OR NEW.signature    IS DISTINCT FROM OLD.signature THEN
        RAISE EXCEPTION 'roe_records versions are immutable: only status may change; create a new version instead';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END $$;

CREATE TRIGGER roe_records_immutable
BEFORE UPDATE OR DELETE ON gatekeeper.roe_records
FOR EACH ROW EXECUTE FUNCTION gatekeeper.roe_enforce_immutability();

-- ---------------------------------------------------------------------------
-- RBAC (doc 11 §3.5). Fixed v1 role set; grants are time-boxed (default 90 d)
-- and R0-audited. SoD constraints are enforced by rbac-service at assignment
-- and action time.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.rbac_roles (
    role         text   PRIMARY KEY,
    description  text   NOT NULL DEFAULT '',
    permissions  text[] NOT NULL DEFAULT '{}'           -- 'resource:action' pairs
);

INSERT INTO gatekeeper.rbac_roles (role, description, permissions) VALUES
    ('platform-admin',     'Platform administration',                                  ARRAY['*:*']),
    ('grc-verifier',       'Verifies legal artifacts',                                 ARRAY['legal:verify','audit:read']),
    ('roe-author',         'Authors RoE records',                                      ARRAY['roe:create','roe:update']),
    ('offensive-approver', 'Four-eyes approver for R3 and R2 stress.* production',     ARRAY['approval:grant','audit:read']),
    ('commander-svc',      'CAI / HexStrike service account',                          ARRAY['task:submit','mission:read']),
    ('module-svc',         'One account per subordinate module',                       ARRAY['task:execute']),
    ('auditor',            'Read-only, all orgs scoped; cannot combine with write roles', ARRAY['audit:read','roe:read','rbac:read']),
    ('operator',           'Kill switch, dashboards, RoE activation',                  ARRAY['revocation:issue','roe:activate','mission:read','audit:read']);

CREATE TABLE gatekeeper.rbac_bindings (
    grant_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          text        NOT NULL,
    principal       text        NOT NULL,               -- user email or service account id
    principal_kind  text        NOT NULL CHECK (principal_kind IN ('human','service')),
    role            text        NOT NULL REFERENCES gatekeeper.rbac_roles (role),
    granted_by      text        NOT NULL,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL DEFAULT (now() + interval '90 days'),  -- auto-expire (doc 11 §3.5)
    revoked_at      timestamptz,
    UNIQUE (org_id, principal, role)
);
CREATE INDEX rbac_bindings_principal_idx ON gatekeeper.rbac_bindings (principal) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Approvals (doc 11 §2.1.8): four-eyes for R3 and R2 stress.* on production;
-- approver ≠ RoE author ≠ requester; 72 h expiry; targets ⊆ approved set.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.approvals (
    approval_id   text        PRIMARY KEY,              -- appr_…
    org_id        text        NOT NULL,
    roe_id        text        NOT NULL,
    roe_version   integer     NOT NULL,
    task_id       text,                                 -- bound task (null = capability-level pre-approval)
    capability    text        NOT NULL,
    risk_class    text        NOT NULL CHECK (risk_class IN ('R2','R3')),
    targets       jsonb       NOT NULL,                 -- approved target set
    requester     text        NOT NULL,
    reason        text,
    status        text        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','granted','rejected','expired')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL DEFAULT (now() + interval '72 hours'),
    decided_at    timestamptz,
    FOREIGN KEY (roe_id, roe_version) REFERENCES gatekeeper.roe_records (roe_id, version)
);
CREATE INDEX approvals_status_idx ON gatekeeper.approvals (status) WHERE status = 'pending';

CREATE TABLE gatekeeper.approval_votes (
    approval_id  text        NOT NULL REFERENCES gatekeeper.approvals (approval_id),
    approver     text        NOT NULL,                  -- must hold offensive-approver; distinct per vote (SoD in service)
    decision     text        NOT NULL CHECK (decision IN ('approve','reject')),
    note         text,
    decided_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (approval_id, approver)
);

-- ---------------------------------------------------------------------------
-- Decision records (doc 11 §3.3). Persisted by policy-service; every allow/deny
-- is also published on authz.decisions.v1 / authz.denials.v1 and hash-chained
-- into audit_events. Doc 01's invariant: no task ≥ R1 dispatched without one.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.authz_decisions (
    decision_id     text        PRIMARY KEY,            -- dec_…
    request_id      text        NOT NULL UNIQUE,        -- req_…
    principal       jsonb       NOT NULL,               -- {kind, id, spiffe_id}
    task_id         text,
    parent_plan_id  text,
    capability      text        NOT NULL,
    targets         jsonb       NOT NULL,
    roe_id          text,
    roe_version     integer,
    risk_class      text        CHECK (risk_class IN ('R0','R1','R2','R3')),
    decision        text        NOT NULL CHECK (decision IN ('allow','deny')),
    reasons         jsonb       NOT NULL DEFAULT '[]',  -- [{code, detail}] — stable v1 enum, doc 11 §3.3
    eval_latency_ms integer,
    decided_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX authz_decisions_task_idx ON gatekeeper.authz_decisions (task_id);
CREATE INDEX authz_decisions_roe_idx  ON gatekeeper.authz_decisions (roe_id, decided_at);

-- ---------------------------------------------------------------------------
-- Issued-token registry (token-service, doc 11 §3.2). Enables revocation,
-- token-replay anomaly detection (jti reuse across tasks), and audit joins.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.issued_tokens (
    jti              text        PRIMARY KEY,           -- tok_…
    sub              text        NOT NULL,              -- agent / service account id
    task_id          text        NOT NULL,              -- task-bound: useless for any other task
    roe_id           text        NOT NULL,
    roe_version      integer     NOT NULL,
    risk_class       text        NOT NULL CHECK (risk_class IN ('R1','R2','R3')),
    capabilities     jsonb       NOT NULL,
    scope_bound      boolean     NOT NULL DEFAULT false,-- Ruling A watch-token form (monitor.watch / monitor.rescan only)
    manifest_uri     text        NOT NULL,              -- blob://tokens/<jti>/{targets|scope}.json
    manifest_sha256  text        NOT NULL,              -- for scope_bound tokens this IS the 'scope:sha256:' audit value
    target_count     integer,                           -- null for scope-bound manifests
    rate_caps        jsonb       NOT NULL DEFAULT '{}',
    approval_id      text        REFERENCES gatekeeper.approvals (approval_id),
    decision_id      text        NOT NULL REFERENCES gatekeeper.authz_decisions (decision_id),  -- no token without a grant
    kid              text        NOT NULL,              -- signing key id (JWKS rotation, two active keys max)
    issued_at        timestamptz NOT NULL DEFAULT now(),
    not_before       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,              -- ≤ 15 min after iat for all active classes (Ruling C5)
    revoked_at       timestamptz,
    CHECK (expires_at <= not_before + interval '15 minutes'),
    -- scope-bound extension is valid only for the R1 standing capabilities (Ruling A.1)
    CHECK (NOT scope_bound OR (risk_class = 'R1' AND capabilities <@ '["monitor.watch","monitor.rescan"]'::jsonb))
);
CREATE INDEX issued_tokens_task_idx    ON gatekeeper.issued_tokens (task_id);
CREATE INDEX issued_tokens_subject_idx ON gatekeeper.issued_tokens (sub, issued_at);
CREATE INDEX issued_tokens_active_idx  ON gatekeeper.issued_tokens (expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Revocations (revocation-service, doc 11 §2.1.7). Commands are broadcast on
-- tasks.revocations.v1; this table is the durable record consulted by
-- policy-service (via the Redis mirror) and PEPs.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.revocations (
    revocation_id  text        PRIMARY KEY,             -- rev_…
    scope          text        NOT NULL CHECK (scope IN ('global','roe','target','capability','token','agent')),
    scope_value    text        NOT NULL DEFAULT '',     -- roe_id / canonical target / capability / jti / agent_id; '' for global
    issued_by      text        NOT NULL,
    reason         text,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    lifted_at      timestamptz                          -- null = active
);
CREATE INDEX revocations_active_idx ON gatekeeper.revocations (scope, scope_value) WHERE lifted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Audit events (audit-service, doc 11 §3.4 / doc 01 §5.9).
-- Hash-chained, append-only. event_hash = sha256(prev_hash ||
-- canonical_json(event_without_hash)); the chain is built by audit-service,
-- one writer per org partition. Hot store partitioned by day (90-day
-- retention); default partition keeps inserts safe before daily partitions
-- are pre-created.
-- ---------------------------------------------------------------------------
CREATE TABLE gatekeeper.audit_events (
    event_id        text        NOT NULL,
    org_id          text        NOT NULL DEFAULT '',
    seq             bigint      NOT NULL,               -- chain position within the org partition
    prev_hash       text        NOT NULL,
    event_hash      text        NOT NULL,
    kind            text        NOT NULL,               -- authorization.decision|token.minted|token.revoked|roe.*|
                                                        -- approval.*|execution.*|revocation.issued|rbac.changed|admin.action|…
    actor           jsonb       NOT NULL,               -- {kind, id, spiffe_id?}
    subject         jsonb       NOT NULL DEFAULT '{}',  -- {mission_id?, task_id?, roe_id?}
    payload         jsonb,                              -- small payloads inline…
    payload_ref     text,                               -- …large ones by ref (blob://audit-payloads/…)
    payload_sha256  text,
    trace_id        text,
    occurred_at     timestamptz NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, recorded_at),
    UNIQUE (org_id, seq, recorded_at)
) PARTITION BY RANGE (recorded_at);

CREATE TABLE gatekeeper.audit_events_default PARTITION OF gatekeeper.audit_events DEFAULT;

CREATE INDEX audit_events_chain_idx ON gatekeeper.audit_events (org_id, seq);
CREATE INDEX audit_events_kind_idx  ON gatekeeper.audit_events (kind, recorded_at);
CREATE INDEX audit_events_task_idx  ON gatekeeper.audit_events ((subject->>'task_id'));

-- Append-only at the DB layer (doc 01 §10.4): no UPDATE, no DELETE.
CREATE OR REPLACE FUNCTION gatekeeper.audit_enforce_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is forbidden', TG_OP;
END $$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON gatekeeper.audit_events
FOR EACH ROW EXECUTE FUNCTION gatekeeper.audit_enforce_append_only();

-- INSERT-only role for the audit ingest hot path (defense in depth on top of
-- the trigger; ownership/grants to the migration user stay unchanged).
-- Roles are cluster-level in Postgres: guard creation so these migrations can
-- also be applied to additional databases in the same cluster (test/scratch
-- databases) without failing on re-creation. GRANTs are per-database and run
-- unconditionally.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegisbastion_audit_writer') THEN
        CREATE ROLE aegisbastion_audit_writer NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA gatekeeper TO aegisbastion_audit_writer;
GRANT SELECT, INSERT ON gatekeeper.audit_events TO aegisbastion_audit_writer;

COMMIT;
