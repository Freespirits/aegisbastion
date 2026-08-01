# services/discover — Discover Module (EASM ingestion, doc 02)

The platform's External Attack Surface Management (EASM) ingestion engine.
Given authorized seeds (apex domains, ASNs/CIDRs, cloud accounts), it maps the
externally visible footprint — domains, subdomains, IPs, netblocks, certs,
cloud resources — and emits a normalized, deduplicated, confidence-scored
asset graph for Monitor/Detect and the commanders.

**MVP-A scope (doc 00 §4 / doc 02 §8):** passive DNS + Certificate
Transparency + credentialed-cloud workers only. Active techniques
(`subdomain_active`, `cloud_public_probe` = `worker-active`) are accepted in
the order schema but dropped with `ACTIVE_NOT_ALLOWED`.

## Authorization posture (Rulings B + C5)

Gatekeeper (doc 11) is the **single PDP**; this module is a PEP client only:

- **Order intake (PEP-1-style re-check):** every order is authorized per
  technique via gatekeeper `policy-service.Authorize` — **fail-closed**:
  gatekeeper unreachable ⇒ intake fails (`502 GATEKEEPER_UNREACHABLE`);
  denied orders persist as `DENIED` with gatekeeper's reason codes.
- **Worker claim verification (PEP-2):** workers re-verify task-bound
  gatekeeper Scope Tokens via the platform Go SDK (`sdks/go/token` Ed25519
  vs gatekeeper JWKS at `GATEKEEPER_JWKS_URL`, task binding, capability,
  manifest/scope membership, revocation cache). R0 tasks carry no token
  (zero target contact by construction — connectors only contact third-party
  data sources). Refusals are dead-lettered to `discover.dlq` and
  audit-recorded (`SCOPE_VIOLATION`).
- **The module mints nothing** — no module-local tokens, scopes, or RoEs.

## Components

| Binary | Role |
|---|---|
| `cmd/orchestrator` | REST order intake, gate pre-check, planner, queue producer, **reducer**, status reporter, audit emitter/forwarder, janitor (time budgets, asset expiry) |
| `cmd/worker-passive` | Passive-source pool: securitytrails, virustotal, shodan_dns, rapiddns, wayback, bgpview, ripestat, rdap |
| `cmd/worker-ct` | CT pool: crt.sh, censys_ct |
| `cmd/worker-cloud` | Credentialed-cloud pool (read-only): AWS Resource Explorer + Organizations, Azure Resource Graph, GCP Cloud Asset Inventory |
| `cmd/discover-mcp` | MCP server (JSON-RPC over HTTP `POST /mcp`): tools `discover.submit_order` / `discover.get_status` / `discover.list_assets` / `discover.cancel`; resources `discover://orders/{id}`, `discover://scopes/{roe_id}` |

Packages: `pkg/{model,connectors,cloud,store,planner,pepclient,netguard}`
(pre-existing) plus `pkg/{queue,reducer,dpingest,auditfwd,evidence}` and
`internal/{config,runtime,service,worker,testutil}`.

## Data flow (doc 02 §2.3)

1. `POST /v1/discovery/orders` → validate → gatekeeper `Authorize` per
   technique (fail-closed) → persist `PENDING`/`DENIED` → planner fans out
   `(technique, source, seed)` tasks to per-technique lanes
   (`discover.tasks.passive|ct|cloud`, stream `DISCOVER_TASKS`, workqueue).
2. Worker pulls a task → order-state check → Scope Token verification
   (fail-closed) → connector run (rate-limited, circuit-broken, evidence
   archived to MinIO) → `RawFinding`s + done marker on `discover.results`.
3. Reducer consumes results → normalize → **scope re-check** (out-of-scope ⇒
   `discover.quarantined_findings`, never assets) → dedup/merge on
   `(tenant,type,value)` → upsert local `discover.assets` → **upsert into the
   data platform via `POST {DP_INGEST_URL}/v1/ingest/batch`** (Ruling C4 —
   dp is the system of record; discover never writes dp tables directly) →
   findings provenance → `AssetChange` on `hub.discover.asset.changed`.
4. Order finalization (`COMPLETED`/`PARTIAL`) →
   `hub.discover.order.status_changed` + optional `callback_url` webhook.

Dedup is two-layered (doc 02 §7.2): deterministic `Nats-Msg-Id`s collapse
worker re-emission at the stream; `(task, source, asset, observed_at bucket)`
collapses it at the store. All merges are idempotent upserts.

## Audit (doc 02 §6.4)

Every order submission, gate decision, task dispatch, refusal, cancellation,
finalization, and admin action is appended to `discover.audit_spool` FIRST
(bounded local durability) and forwarded by the audit forwarder to
gatekeeper's audit-service (the audit of record, doc 11 §3.4) via the
`audit.events` bus subject. Spool full (`DISCOVER_AUDIT_SPOOL_MAX`,
default 10000) ⇒ R1+ order intake pauses (fail-closed mirror of doc 11's
audit-gating rule).

## REST surface (orchestrator, `DISCOVER_HTTP_ADDR`, default :8083)

```
POST /v1/discovery/orders                    submit → 202 OrderStatus | 403 gate denial | 502 gatekeeper down
GET  /v1/discovery/orders/{id}               status + progress + gate record
GET  /v1/discovery/orders/{id}/assets?cursor=
POST /v1/discovery/orders/{id}/cancel        cooperative cancellation
GET  /v1/assets?tenant_id=&domain=&type=&since=&cursor=
POST /v1/admin/tenants/{id}/discover:disable platform-admin kill, executed THROUGH
                                             gatekeeper (per-RoE revocations)
GET  /healthz /readyz
```

Workers and discover-mcp also serve `/healthz` `/readyz`
(`DISCOVER_HEALTH_ADDR`, default :8090 for workers; MCP on
`DISCOVER_MCP_ADDR` :8087).

## Configuration (env)

See `internal/config/config.go` for the full set. Key knobs:

- `DATABASE_URL` + `DB_SEARCH_PATH=discover` (schema-per-context, migration
  `db/migrations/000004_module_stores.up.sql`)
- `NATS_URL`; `GATEKEEPER_GRPC_ADDR` + `GATEKEEPER_JWKS_URL`
- `DP_INGEST_URL` (empty ⇒ local-store-only mode) + `DP_PRINCIPAL`
  (TPEL principal with a `service_discover` grant per tenant)
- `S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY/S3_USE_TLS` (evidence bucket +
  token manifests)
- `DISCOVER_OFFLINE=true` + `DISCOVER_FIXTURES_DIR` — connectors replay
  recorded responses (`testdata/fixtures/<source>.json`,
  `cloud_<provider>.json`); no live egress, no DP, no evidence
- `DISCOVER_CONNECTORS_FILE` (`connectors.yaml` — per-tenant enable flags +
  rate specs), `DISCOVER_SOURCE_KEYS_FILE` (tenant → source API keys),
  `DISCOVER_CLOUD_CREDS_FILE` (tenant → cloud account credentials; MVP-A
  file-based vault stand-in, doc 02 §5)
- `DISCOVER_AUDIT_SPOOL_MAX`, `DISCOVER_ASSET_TTL` (expiry sweeper, default
  720h, 0 disables), `DISCOVER_STATUS_HEARTBEAT` (default 15s, doc 02 §3.3)
- `DISCOVER_ALLOW_PRIVATE_EGRESS` — TEST/FIXTURE HOOK ONLY (netguard must
  never allow private egress in deployment)

## Netguard (doc 02 §6.3)

Every live connector egress passes `pkg/netguard`: ports {53, 853, 80, 443}
only, RFC1918/loopback/link-local/reserved destinations hard-blocked at dial
time regardless of token contents. Credentialed-cloud enumeration is
read-only by construction — the AWS SDK middleware refuses any
non-`List|Get|Describe|Search|BatchGet` call.

## Build / test

```bash
cd services/discover
GOWORK=off go build ./...     # replace directives: ../../gen/go, ../../sdks/go
GOWORK=off go vet ./...
GOWORK=off go test ./...      # unit suites run anywhere; integration suites
                              # (reducer, worker round-trip, service intake)
                              # use the compose infra and SKIP when it's down

cd deploy && docker compose --profile infra up -d   # Postgres + NATS + MinIO
```

Test coverage of the doc 02 §9 requirements:

- recorded-fixture connector tests (`pkg/connectors`, no live API in CI);
- rate-spec compliance + token-bucket/quota + circuit-breaker tests;
- PEP wrapper matrix (`pkg/pepclient`): expired token, seed outside manifest,
  revoked RoE, JWKS unreachable, R1+ without token, forged signature, TTL >
  15 min, task binding — all fail closed;
- reducer AssetChange correctness, dedup on re-delivery, quarantine
  (out-of-scope / excluded / unscoped cloud account), corroboration, edges,
  DP ingest batches with idempotency keys, order finalization
  (`pkg/reducer`, integration);
- bus round-trip lane → worker → results → reducer → store + DP + AssetChange
  (`internal/worker`, integration) and the R1-without-token → DLQ + audit
  refusal path;
- intake gate allow/deny/down/active-drop/cancel against an in-process
  gatekeeper fake (`internal/service`, integration).

## Deviations (documented, minimal)

- **DISCOVER_TASKS stream is ensured by the module itself** (idempotent
  `AddStream` at orchestrator/mcp startup) instead of
  deploy/jetstream-bootstrap — it is module-internal plumbing (doc 02 §2.2,
  like doc 03's `MONITOR_JOBS`), and this keeps shared bootstrap files
  untouched. The cross-module `DISCOVER_EVENTS` stream stays bootstrap-owned.
- **In-process token buckets** per worker (doc 02 §5 lists Redis; the MVP-A
  Compose host has none — same deviation gatekeeper took). Redis lands with
  horizontal scaling (MVP-B).
- **MCP server is dependency-free** (hand-rolled JSON-RPC over HTTP POST
  `/mcp`; `mcp-go` is not vendored anywhere in the repo). Tools/resources
  wrap the same service layer as REST — no logic forks.
- **Admin tenant-disable maps to per-RoE revocations** — gatekeeper's
  RevocationScope (global/roe/target/capability) has no tenant scope at MVP;
  per-RoE is its finest module-relevant form, and the halt is recorded in
  the audit of record either way.
- **Workers consume module-internal lanes, not platform `task.assign.*`**
  — doc 02 §2/§3 defines Discover's own order→lane→results pipeline
  (DiscoveryOrder is the commander contract); the SDK is used for what it's
  canonical for here: token verification, manifest/scope evaluation, audit,
  bus, revocation cache.
