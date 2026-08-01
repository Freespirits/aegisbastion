# herald — AegisBastion Alert Module (doc 05)

The platform's **sole notification egress** (Ruling C7): no other module talks
to Slack/Teams/SIEM. herald ingests `AlertEvent v1` from the bus
(`detect.alert`, `monitor.alert`, `discover.alert`, `ddos.alert`,
`redteam.alert`, `phish.alert`, `alert.outbound`) and REST, enforces the
authorization context (gatekeeper Scope Token, **non-deferrable** §13.1),
enriches, dedups, correlates into incidents, routes per policy, escalates
unacked incidents, and delivers to **Slack, Teams, Splunk HEC, syslog
(CEF/LEEF), and generic HMAC-signed webhooks** — with a fully recorded
(mockable) delivery outbox and append-only audit spool forwarded to
gatekeeper's audit of record.

TypeScript on Node 22. Storage: Postgres 16 (`alert` schema,
`db/migrations/000005_alert.{up,down}.sql`, golang-migrate). Bus: NATS
JetStream. Token verification: `@aegisbastion/agent-sdk` (JWKS, EdDSA) — herald
mints nothing (Ruling B).

## Pipeline (doc 05 §3.2)

```
*.alert bus / POST /v1/alerts
  → C1 schema validation (ajv, schemas/alert/v1 — reject invalid at ingress)
  → occurred_at ±24 h check · idempotent on event_id
  → §13.1 authz-context enforcement (JWKS verify @ occurred_at, jti match,
    capability coverage, target-in-manifest/scope) — fail CLOSED
  → C2 enrich (data-platform GraphQL asset cache, 5 min TTL, fail-soft)
    effective severity = max(producer, criticality floor)
  → C3 dedup (fingerprint SHA-256(org|module|hint|asset), sliding window,
    renotify_every, fail-OPEN with dedup_degraded=true)
  → C4 correlate (deterministic key asset:<id>|<finding-identity> → Incident)
  → C5 route (priority-ordered policies, first-match-per-channel-type,
    org egress policy §13.2 fail-closed) → Delivery rows (recorded outbox)
  → C6 dispatch (per-destination token buckets, Handlebars templates, §13.3
    redaction by evidence grade, SSRF-guarded + DNS-pinned sends, HMAC-signed
    webhooks, backoff 1/2/4/8/16 min jitter, max 6 attempts → DLQ)
  → C7 escalate (unacked incidents, 5 s scan, cumulative step timers,
    repeats ≤ max_repeats, exhausted → org fail-safe SIEM webhook)
  → C9 audit (append-only alert.audit_log + hash-chained forward to
    audit.events) · lifecycle events → alerts.lifecycle · quarantines → alerts.dlq
```

## Bus contract

- **Consume** stream `ALERT_INGRESS` (durable `herald-ingest`, work-queue):
  every message is a CloudEvents 1.0 JSON envelope (type
  `com.aegisbastion.alert.v1`, `data` = AlertEvent v1). Poison messages are
  `term()`ed after an `ingest_reject` audit — never redelivered.
- **Scope Token transport (deviation 3):** the compact gatekeeper Scope Token
  JWT rides the **`Authorization-Token` NATS header** (REST: same-named HTTP
  header, or top-level `authorization_token` body field). Doc 05 §5.7 prose
  puts it in an in-event `authorization_token` field, but the ratified
  Phase-0 schema (`schemas/alert/v1/alert-event.schema.json`,
  `additionalProperties: false`) forbids that field; the header carries the
  same value without changing the contract.
- **Publish** `alerts.lifecycle` (CloudEvents `com.aegisbastion.alert.lifecycle.v1`,
  one per transition), `alerts.dlq` (`com.aegisbastion.alert.dlq.v1`: authz
  quarantines + exhausted deliveries), `audit.events` (platform
  `AuditEvent` proto envelopes via the SDK's hash-chained `AuditEmitter`).

## REST surface (doc 05 §5.10)

`GET /healthz` · `GET /readyz` · `POST /v1/alerts` · `POST /v1/notify` ·
`GET /v1/alerts` `GET /v1/alerts/{id}` · `GET /v1/incidents`
`GET /v1/incidents/{id}` · `POST /v1/incidents/{id}/resolve` ·
`POST /v1/acks` · `GET /v1/acks?token=…` (signed channel callback) ·
`GET/POST /v1/policies/routing` `PUT/DELETE /v1/policies/routing/{id}` ·
`GET/POST /v1/policies/escalation` `PUT /v1/policies/escalation/{id}` ·
`GET/PUT /v1/egress/{org}` (org egress policy, §13.2) ·
`POST /v1/routes/test` (dry-run) · `GET /v1/deliveries` · `GET /v1/status` ·
`GET /v1/metrics` (Prometheus).

List endpoints take an optional `org_id` filter; an absent/empty `org_id`
lists across orgs (control-plane read — the doc 10 alert-rules UI calls
`GET /v1/policies/routing` and `GET /v1/deliveries` unfiltered, Ruling C7).

Actor identity: `X-AegisBastion-Actor` header; mutations + `channel_override`
require an admin actor (`HERALD_ADMIN_ACTORS`, §13.7). See deviation 5.

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | — | Postgres DSN (schema-qualified `alert.*`; no search_path needed) |
| `NATS_URL` | `nats://localhost:4222` | JetStream |
| `HERALD_BUS_ENABLED` | `true` | `false` = in-process only (tests/dev) |
| `GATEKEEPER_JWKS_URL` | `http://localhost:8080/.well-known/gatekeeper-jwks.json` | gatekeeper JWKS (fail-closed §13.1) |
| `S3_ENDPOINT/ACCESS_KEY/SECRET_KEY/USE_TLS` | `localhost:9000` | MinIO token-manifests |
| `DP_QUERY_URL` | — | data-platform GraphQL base URL (herald appends `/v1/query`; empty = enrichment off, fail-soft) |
| `HERALD_DP_PRINCIPAL` / `HERALD_DP_TENANT` | `herald` / — | TPEL headers for dp queries (principal needs a `tenancy.grants` row, role `service_alert`; tenant header only when it holds several grants) |
| `HERALD_HTTP_LISTEN` | `:8086` | REST bind |
| `HERALD_DELIVERY_MODE` | `record` | `record` = outbox only (no egress); `live` = real sends |
| `ALERT_SLACK_WEBHOOK_URL` / `ALERT_TEAMS_WEBHOOK_URL` | — | default webhook for `#channel` destinations |
| `HERALD_ORG_SIEM_WEBHOOK_URL` | — | org fail-safe SIEM webhook (bootstrap policies, §8/§9) |
| `ALERT_WEBHOOK_SIGNING_SECRET` | — | fallback HMAC secret for signed webhooks |
| `HERALD_SECRET_<REF>` | — | per-endpoint secret resolution (egress `secret_ref`, §13.5) |
| `HERALD_ACK_SIGNING_SECRET` | falls back to webhook secret | ack callback token HMAC key (§12) |
| `HERALD_PUBLIC_BASE_URL` | `http://localhost:8086` | ack links in channel messages |
| `HERALD_ADMIN_ACTORS` | `cai,hexstrike-ai` | §13.7 admin actors |
| `HERALD_EGRESS_SEED_JSON` | — | `{org_id: EgressEntry[]}` seed for orgs without a DB egress policy |
| `HERALD_RATE_PER_SECOND` / `HERALD_RATE_BURST` | `1` / `20` | per-destination token buckets (§11) |
| `HERALD_AUTHZ_RETRY_MS` / `HERALD_AUTHZ_HOLD_QUARANTINE_MS` | `60000` / `900000` | §12 hold cadence / quarantine deadline |
| `HERALD_MAX_DELIVERY_ATTEMPTS` | `6` | §12 |
| `SCHEMA_DIR` | auto | override for the AlertEvent JSON Schemas dir (Docker: `/app/schemas/alert/v1`) |

## Deviations from doc 05 (all ratified-doc-driven or MVP-A simplifications)

1. **Redis → Postgres.** Doc 05's Redis hot state (dedup TTLs, token
   buckets, leader lock, caches) maps to Postgres (`alert.dedup_state`,
   atomic upsert) + in-process state — the MVP-A compose host has no Redis
   (same simplification gatekeeper took). §7.1 fail-open and §11 bucket
   semantics are preserved.
2. **K8s → single compose service** (Ruling C6). C1–C9 run in one process;
   the C7 "leader election" is trivially satisfied (single replica).
3. **Token transport header** (see Bus contract above) instead of §5.7's
   in-event field — the Phase-0 schema wins.
4. **Slack/Teams ack = signed link button**, not Slack-App interactivity:
   incoming webhooks cannot receive interactive posts, so the MVP ack button
   opens `GET /v1/acks?token=…` (HMAC, 10-min expiry, single-use nonce — the
   §12 guarantees are unchanged). Slack App bot-token interactivity is Later.
5. **REST authn via `X-AegisBastion-Actor` + admin list.** mTLS/SPIFFE + OIDC
   service tokens (doc 05 §10) land with MVP-B; the MVP-A compose host has no
   identity provider (dashboard's OIDC covers humans, not service-to-service).
6. **MCP server deferred.** The REST control API covers the full tool
   surface (read/ack/notify/route-test/policies); mounting under the HexStrike
   MCP gateway arrives when the gateway is deployed (doc 05 §15 explicitly
   allows REST-only for MVP).
7. **Not in MVP-A (doc 05 §15 Later list):** storm-guard digest mode
   (§7.2), rule-based correlation, ITSM/on-call adapters, Sentinel adapter,
   `POST /v1/webhooks/{id}/rotate-secret` (needs the platform secret store —
   MVP-A per-endpoint secrets resolve from env refs), digest/email channels.
8. **Audit forwarding vocabulary:** the platform `AuditEvent` proto has no
   herald-specific types; `authz_reject`/`authz_hold` forward as
   `SCOPE_VIOLATION`, everything else as `UNSPECIFIED` with
   `herald_action` in the payload. The complete record is the local
   append-only `alert.audit_log` spool (rows with `forwarded_at NULL` are
   pending reconciliation).
9. **Enrichment follows the BUILT data platform** (Ruling C4), not doc 05
   §3.1's assumed query shape: TPEL resolves the tenant from
   `X-DP-Principal` (`tenancy.grants`, role `service_alert`) — never from a
   query argument; assets are looked up by UUIDv7 `asset(uid:)` with an
   exact-`value` fallback via `assets(filter: { valuePrefix: … })`;
   `criticality`/`owner_group` are read from the Asset `attributes` JSON
   (the dp schema has no such top-level fields).

## Build, test, run

```bash
npm install                 # file: deps resolve to vendor/*.tgz
npm run typecheck           # tsc --noEmit (strict)
npm test                    # vitest: 122 tests (unit + pipeline + REST + pg integration)
npm run build               # tsc emit to dist/
npm start                   # node dist/main.js
node bin/smoke-dev.mjs      # end-to-end smoke vs the compose infra (19 checks:
                            # health, §13.7 admin gating, schema rejection,
                            # REST+bus ingest, dedup, outbox, authz fail-closed,
                            # dashboard surface, status/metrics)
```

`test/pgstore.integration.test.ts` runs against the compose Postgres
(`PG_TEST_DSN` override) and skips cleanly when unreachable.

Compose (from `deploy/`): `docker compose --profile infra up -d` then
`docker compose --profile infra --profile apps up -d --build alert`.
Migration pair verification (roll back + re-apply only 000005):
`services\alert\bin\migrate-dev.cmd down 1` / `up 1`.

Vendored build inputs: `vendor/*.tgz` (sdks/ts + gen/ts) and
`schemas/alert/v1/*.json` (mirror of the ratified schemas). Refresh after
upstream changes with `services/alert/bin/repack-vendor.sh`, then
`npm install`.
