-- 000005_alert.up.sql
-- Alert module `herald` stores (doc 05). Herald is the platform's SOLE
-- notification egress (Ruling C7): ingest → enrich → dedup → correlate →
-- route → dispatch, with escalation, delivery tracking, org-level egress
-- policy (§13.2 — deliberately NOT a gatekeeper token claim, Ruling B) and a
-- local append-only audit spool forwarded to gatekeeper's audit of record
-- (§5.8, doc 11 §3.4). Herald holds no authorization state of its own —
-- tokens/RoE/decisions live in the gatekeeper schema (000002).
--
-- MVP-A note: doc 05's Redis-backed hot state (dedup TTLs, leader lock) maps
-- to Postgres here — the MVP-A compose host has no Redis (same simplification
-- gatekeeper took, see services/gatekeeper README deviation 1). Dedup keeps
-- doc 05 §7.1's fail-open semantics in the service layer.

BEGIN;

CREATE SCHEMA IF NOT EXISTS alert;

-- ---------------------------------------------------------------------------
-- Alerts (doc 05 §5.2 AlertEvent v1 + pipeline outcome).
-- One row per accepted alert event; raw payload retained for audit/replay.
-- ---------------------------------------------------------------------------
CREATE TABLE alert.alerts (
    event_id                text        PRIMARY KEY,          -- evt_… (producer ULID; idempotent ingest key)
    org_id                  text        NOT NULL,
    source_module           text        NOT NULL
                            CHECK (source_module IN ('detect','monitor','discover','ddos-engine','ai-redteam','phish-catcher','commander')),
    source_event_id         text        NOT NULL,
    engagement_id           text,
    authorization_token_id  text,                             -- gatekeeper Scope Token jti (tok_…); mandatory per §5.2 rules
    title                   text        NOT NULL,
    description             text        NOT NULL DEFAULT '',
    severity                text        NOT NULL
                            CHECK (severity IN ('critical','high','medium','low','info')),
    effective_severity      text        NOT NULL
                            CHECK (effective_severity IN ('critical','high','medium','low','info')),
    confidence              text        NOT NULL CHECK (confidence IN ('confirmed','probable','possible')),
    category                text        NOT NULL
                            CHECK (category IN ('vuln','exposure','config-drift','new-asset','phishing','ai-exploit','stress-test','operational')),
    asset                   jsonb       NOT NULL,             -- {asset_id, kind, identifier, criticality?, owner_group?}
    evidence                jsonb,
    pii_classification      text        NOT NULL DEFAULT 'none'
                            CHECK (pii_classification IN ('none','pii','pci','hipaa')),
    occurred_at             timestamptz NOT NULL,
    received_at             timestamptz NOT NULL DEFAULT now(),
    fingerprint             text        NOT NULL,             -- sha256(org|module|hint|asset_id), §7.1
    fingerprint_hint        text        NOT NULL DEFAULT '',
    dedup_window_seconds    integer     NOT NULL DEFAULT 86400,
    renotify_every          integer     NOT NULL DEFAULT 0,
    requires_ack            boolean     NOT NULL DEFAULT false,
    labels                  jsonb       NOT NULL DEFAULT '{}',
    state                   text        NOT NULL DEFAULT 'open'
                            CHECK (state IN ('open','acknowledged','resolved','suppressed')),  -- §7.3
    dedup_verdict           text        NOT NULL DEFAULT 'new'
                            CHECK (dedup_verdict IN ('new','duplicate','renotify')),
    dedup_degraded          boolean     NOT NULL DEFAULT false,  -- fail-open stamp (§7.1)
    authz_status            text        NOT NULL DEFAULT 'none'
                            CHECK (authz_status IN ('none','pending','verified','held','rejected')),
    authz_retry_at          timestamptz,                        -- §12: JWKS-outage hold; retry then quarantine at +15 min
    authz                   jsonb,                            -- verified Scope Token claims snapshot (§5.7)
    incident_id             text,                             -- set by correlation (FK added after incidents)
    raw                     jsonb       NOT NULL              -- AlertEvent v1 as ingested
);
CREATE INDEX alerts_org_received_idx   ON alert.alerts (org_id, received_at DESC);
CREATE INDEX alerts_incident_idx       ON alert.alerts (incident_id);
CREATE INDEX alerts_fingerprint_idx    ON alert.alerts (fingerprint, received_at DESC);
CREATE INDEX alerts_state_idx          ON alert.alerts (org_id, state) WHERE state = 'open';

-- ---------------------------------------------------------------------------
-- Incidents (doc 05 §5.3). Correlation groups alerts; routing happens per
-- incident. Escalation state (policy, current step, next fire) lives here;
-- timers use DB now() (§12 clock-skew rule).
-- ---------------------------------------------------------------------------
CREATE TABLE alert.incidents (
    incident_id             text        PRIMARY KEY,          -- inc_…
    org_id                  text        NOT NULL,
    state                   text        NOT NULL DEFAULT 'open'
                            CHECK (state IN ('open','acknowledged','escalated','resolved','suppressed')),
    title                   text        NOT NULL,
    severity                text        NOT NULL
                            CHECK (severity IN ('critical','high','medium','low','info')),
    category                text        NOT NULL                -- representative (first alert's), for routing matchers
                            CHECK (category IN ('vuln','exposure','config-drift','new-asset','phishing','ai-exploit','stress-test','operational')),
    source_module           text        NOT NULL                -- representative (first alert's)
                            CHECK (source_module IN ('detect','monitor','discover','ddos-engine','ai-redteam','phish-catcher','commander')),
    asset                   jsonb       NOT NULL,               -- representative asset {asset_id, kind, identifier, criticality?, owner_group?}
    labels                  jsonb       NOT NULL DEFAULT '{}',  -- merged member labels (first wins per key)
    correlation_key         text        NOT NULL,             -- asset:<asset_id>|<finding-identity> (§7.2 key #1)
    alert_count             integer     NOT NULL DEFAULT 0,
    requires_ack            boolean     NOT NULL DEFAULT false,
    first_seen_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    ack                     jsonb,                            -- {by, at, note}
    escalation              jsonb       NOT NULL DEFAULT '{}',-- {policy_id, current_step, next_fire_at, repeat_count}
    escalation_exhausted    boolean     NOT NULL DEFAULT false,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_org_state_idx      ON alert.incidents (org_id, state);
CREATE INDEX incidents_correlation_idx    ON alert.incidents (org_id, correlation_key) WHERE state IN ('open','acknowledged','escalated');
CREATE INDEX incidents_escalation_due_idx ON alert.incidents (((escalation->>'next_fire_at')))
    WHERE requires_ack AND state IN ('open','escalated');

-- Join table: which alerts make up an incident (§5.3 alert_ids).
CREATE TABLE alert.incident_alerts (
    incident_id text NOT NULL REFERENCES alert.incidents (incident_id),
    event_id    text NOT NULL REFERENCES alert.alerts (event_id),
    attached_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, event_id)
);
ALTER TABLE alert.alerts
    ADD CONSTRAINT alerts_incident_fk FOREIGN KEY (incident_id) REFERENCES alert.incidents (incident_id);

-- ---------------------------------------------------------------------------
-- Routing policies (doc 05 §5.4). Ordered matchers, first-match-per-channel-
-- type wins (§8). Versioned; mutations require herald:admin (§13.7, enforced
-- in the service layer) and are audit-logged with request hashes.
-- ---------------------------------------------------------------------------
CREATE TABLE alert.routing_policies (
    policy_id                       text        PRIMARY KEY,  -- rp_…
    org_id                          text        NOT NULL,
    priority                        integer     NOT NULL,     -- ascending eval; ties → creation order
    enabled                         boolean     NOT NULL DEFAULT true,
    match                           jsonb       NOT NULL DEFAULT '{}',
        -- {severity_gte?, categories[]?, asset_criticality_gte?, source_modules[]?, labels_any?{}}
    targets                         jsonb       NOT NULL,     -- [{channel, destination, template?, mention?, evidence_grade?}]
    escalation_policy_id            text,                     -- esc_… (FK added after escalation_policies)
    suppress_if_acknowledged_within integer,                  -- seconds
    version                         integer     NOT NULL DEFAULT 1,
    created_by                      text        NOT NULL,
    created_at                      timestamptz NOT NULL DEFAULT now(),
    updated_at                      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX routing_policies_org_idx ON alert.routing_policies (org_id, priority, created_at) WHERE enabled;

-- ---------------------------------------------------------------------------
-- Escalation policies (doc 05 §5.5).
-- ---------------------------------------------------------------------------
CREATE TABLE alert.escalation_policies (
    policy_id                        text        PRIMARY KEY, -- esc_…
    org_id                           text        NOT NULL,
    steps                            jsonb       NOT NULL,    -- [{step, wait_seconds, targets[]}]
    repeat_last_step_every_seconds   integer     NOT NULL DEFAULT 0,  -- 0 = no repeat
    max_repeats                      integer     NOT NULL DEFAULT 0,
    stop_on                          jsonb       NOT NULL DEFAULT '["ack","resolved"]',
    version                          integer     NOT NULL DEFAULT 1,
    created_by                       text        NOT NULL,
    created_at                       timestamptz NOT NULL DEFAULT now(),
    updated_at                       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE alert.routing_policies
    ADD CONSTRAINT routing_policies_escalation_fk FOREIGN KEY (escalation_policy_id)
    REFERENCES alert.escalation_policies (policy_id);

-- ---------------------------------------------------------------------------
-- Deliveries (doc 05 §5.6 DeliveryRecord) — the recorded delivery outbox.
-- One row per delivery task; attempt history in `attempts`. Pending rows are
-- the dispatch queue (SELECT … FOR UPDATE SKIP LOCKED); status=dlq rows are
-- the replay source for `heraldctl replay`.
-- ---------------------------------------------------------------------------
CREATE TABLE alert.deliveries (
    delivery_id            text        PRIMARY KEY,           -- dlv_…
    org_id                 text        NOT NULL,
    incident_id            text        NOT NULL REFERENCES alert.incidents (incident_id),
    alert_ids              jsonb       NOT NULL DEFAULT '[]',
    channel                text        NOT NULL
                           CHECK (channel IN ('slack','teams','splunk-hec','syslog','webhook')),
    destination            text        NOT NULL,              -- #channel | https://… | host:port | index name
    template               text        NOT NULL DEFAULT 'default',
    payload                jsonb,                             -- rendered body snapshot (recorded outbox)
    urgency                text        NOT NULL DEFAULT 'normal'
                           CHECK (urgency IN ('low','normal','high','critical')),
    status                 text        NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','sent','failed','dlq')),
    attempt_count          integer     NOT NULL DEFAULT 0,
    max_attempts           integer     NOT NULL DEFAULT 6,
    attempts               jsonb       NOT NULL DEFAULT '[]', -- [{at, status, provider_response_code, latency_ms, error}]
    provider_response_code integer,
    latency_ms             integer,
    error                  text,
    idempotency_key        text        NOT NULL,              -- dispatcher-crash dedup (§12)
    escalation_step        integer,                           -- null = initial routing
    next_attempt_at        timestamptz NOT NULL DEFAULT now(),-- backoff schedule (1,2,4,8,16 min)
    sent_at                timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, idempotency_key)
);
CREATE INDEX deliveries_pending_idx  ON alert.deliveries (next_attempt_at) WHERE status IN ('pending','failed');
CREATE INDEX deliveries_incident_idx ON alert.deliveries (incident_id);
CREATE INDEX deliveries_org_idx      ON alert.deliveries (org_id, created_at DESC);
CREATE INDEX deliveries_dlq_idx      ON alert.deliveries (org_id) WHERE status = 'dlq';

-- ---------------------------------------------------------------------------
-- Dedup state (doc 05 §7.1). Postgres-backed sliding window for MVP-A (no
-- Redis on the compose host): fingerprint → {alert_id, count, last_seen} with
-- TTL = dedup_window_seconds (default 24 h, hard max 7 d). Service layer is
-- fail-open on store outage (dedup_degraded=true).
-- ---------------------------------------------------------------------------
CREATE TABLE alert.dedup_state (
    fingerprint      text        PRIMARY KEY,                 -- sha256(org|module|hint|asset_id)
    org_id           text        NOT NULL,
    alert_id         text        NOT NULL,                    -- first alert that claimed the fingerprint
    occurrence_count integer     NOT NULL DEFAULT 1,
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    CHECK (expires_at <= first_seen_at + interval '7 days')   -- hard max window (§7.1)
);
CREATE INDEX dedup_state_expiry_idx ON alert.dedup_state (expires_at);

-- ---------------------------------------------------------------------------
-- Acknowledgements (doc 05 §9). Callback tokens are single-use (nonce) with
-- 10-min expiry; acks stop escalation chains (stop_on).
-- ---------------------------------------------------------------------------
CREATE TABLE alert.acks (
    ack_id      text        PRIMARY KEY,                      -- ack_…
    org_id      text        NOT NULL,
    incident_id text        REFERENCES alert.incidents (incident_id),
    event_id    text        REFERENCES alert.alerts (event_id),
    actor       text        NOT NULL,
    note        text        NOT NULL DEFAULT '',
    nonce       text        NOT NULL UNIQUE,                  -- single-use callback nonce (§12)
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (incident_id IS NOT NULL OR event_id IS NOT NULL)
);
CREATE INDEX acks_incident_idx ON alert.acks (incident_id);

-- ---------------------------------------------------------------------------
-- Org-level egress policy (doc 05 §13.2). Herald-OWNED per Ruling B:
-- `approved_egress_channels` is deliberately not a gatekeeper token claim.
-- Delivery destinations must match an entry; out-of-policy destinations need
-- herald:admin and are audit-flagged (enforced in the service layer).
-- ---------------------------------------------------------------------------
CREATE TABLE alert.egress_policies (
    org_id      text        PRIMARY KEY,
    entries     jsonb       NOT NULL DEFAULT '[]',
        -- [{channel, pattern, internal?, evidence_grade?, secret_ref?}]
        -- pattern: exact host / host:port / "#channel" / syslog endpoint
    updated_by  text        NOT NULL,
    version     integer     NOT NULL DEFAULT 1,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Audit spool (doc 05 §5.8). Append-only locally; forwarded to gatekeeper's
-- hash-chained audit of record (audit.events bus subject) and stamped
-- forwarded_at. Same append-only enforcement as gatekeeper.audit_events.
-- ---------------------------------------------------------------------------
CREATE TABLE alert.audit_log (
    audit_id        text        PRIMARY KEY,                  -- aud_…
    org_id          text        NOT NULL DEFAULT '',
    ts              timestamptz NOT NULL DEFAULT now(),
    actor           jsonb       NOT NULL,                     -- {kind: service|commander|user, id}
    action          text        NOT NULL
                    CHECK (action IN ('ingest','ingest_reject','dedup_suppress','correlate','route',
                                      'deliver','deliver_failed','dlq','ack','escalate','resolve',
                                      'policy_create','policy_update','egress_update','authz_reject',
                                      'authz_hold','notify')),
    entity_ids      jsonb       NOT NULL DEFAULT '{}',        -- {event_id?, incident_id?, delivery_id?, policy_id?}
    decision_detail jsonb       NOT NULL DEFAULT '{}',        -- matched_policy_ids, verdicts, reject reason…
    request_hash    text        NOT NULL DEFAULT '',          -- sha256 of the canonical request/before-after
    forwarded_at    timestamptz
);
CREATE INDEX audit_log_ts_idx      ON alert.audit_log (ts);
CREATE INDEX audit_log_pending_idx ON alert.audit_log (ts) WHERE forwarded_at IS NULL;

CREATE OR REPLACE FUNCTION alert.audit_enforce_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- forwarded_at stamping is the only permitted mutation (spool semantics).
    IF TG_OP = 'UPDATE' AND OLD.forwarded_at IS NULL AND NEW.forwarded_at IS NOT NULL
       AND NEW.audit_id = OLD.audit_id
       AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
       AND NEW.ts IS NOT DISTINCT FROM OLD.ts
       AND NEW.actor IS NOT DISTINCT FROM OLD.actor
       AND NEW.action IS NOT DISTINCT FROM OLD.action
       AND NEW.entity_ids IS NOT DISTINCT FROM OLD.entity_ids
       AND NEW.decision_detail IS NOT DISTINCT FROM OLD.decision_detail
       AND NEW.request_hash IS NOT DISTINCT FROM OLD.request_hash THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'alert.audit_log is append-only: % is forbidden', TG_OP;
END $$;

CREATE TRIGGER audit_log_append_only
BEFORE UPDATE OR DELETE ON alert.audit_log
FOR EACH ROW EXECUTE FUNCTION alert.audit_enforce_append_only();

COMMIT;
