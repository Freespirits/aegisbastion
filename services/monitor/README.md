# monitor — doc 03

24/7 continuous monitoring: change detection, snapshot diffing, config drift,
new-asset and exposure detection, event streaming. One binary hosts M1–M7
(doc 03 §3.1): the Coordinator (agentsdk.Module for `monitor.watch`,
`monitor.rescan`, `monitor.baseline.set`, `monitor.feed.sync`), the embedded
scheduler, the probe worker pool, the diff + rules engines, the event
streamer, and the CT feed poller.

## Risk class & authorization (hard gate)

- `monitor.watch` / `monitor.rescan` are **R1** (Ruling A); `monitor.baseline.set`
  / `monitor.feed.sync` are R0. A mission whose RoE allows only R0 runs
  **passive-only mode** (Ruling A.1): feed ingestion + cached diffing, ZERO
  target contact. Cached diffing is the coordinator's `passiveSweep`: each
  watch-set-sync pass evaluates M5 baseline/exposure rules over every watched
  asset's cached snapshot set inline (no scan jobs, no token, no probes);
  sticky rule state makes repeated sweeps idempotent.
- Active probing rides **scope-bound watch tokens** (Ruling A.2):
  `scope_bound: true`, canonical RoE scope carried in the hashed MinIO
  manifest (`scope:sha256:`), 15-min TTL, continuously re-authorized via
  gatekeeper `RefreshToken` (coordinator `refreshLoop`). Revocation/kill
  propagates ≤ 5 s via the revocation channel (`tasks.revocations.v1`).
- Workers verify the job-carried token **per scan job** (EdDSA vs gatekeeper
  JWKS, task-bound jti, capability, manifest hash, exclusions-win scope
  evaluation via the SDK). A job without a valid in-scope token is
  **dead-lettered** (`monitor.scan_jobs_dead`) **and audit-logged**
  (SCOPE_VIOLATION) — fail-closed (doc 03 §9.2). Every probe additionally goes
  through `pep.Guard.AuthorizeTarget` before any network I/O; per-probe
  `TARGET_TOUCHED` audit records carry probe_type + token_jti (doc 03 §9.6).
- Probes are interface-driven (`probes.Probe`): production executors touch the
  network; `FixtureProbe` and loopback clients serve tests without network.

## Probes (doc 03 §6.1)

| probe | timeout | notes |
|---|---|---|
| `dns` | 10 s | A/AAAA/CNAME/MX/TXT/NS via 3 independent resolvers, quorum 2-of-3; CNAME chain walk; dangling-CNAME + takeable-service list v1. System resolver never used. |
| `tls` | 10 s | Handshake on 443; cert chain, negotiated version/cipher, ALPN; expiry leeway ±5 min. No vuln probing. |
| `http` | 15 s, body ≤ 256 KiB | GET / HTTPS→HTTP fallback + /robots.txt HEAD; fixed UA `AegisBastion-Monitor/0.1 (+roe:<roe_id>)`; SimHash-64 body hash; module-owned tech ruleset v1. |

`tcp_port` is Later (diff model + change types already mapped).

## Events (public contract, doc 03 §5)

- `monitor.changes` — MonitorChange v1 protobuf in the doc 01 §8.2 Envelope
  (stream MONITOR_EVENTS, durable 72 h). Full firehose.
- `monitor.alert` — AlertEvent v1 (schemas/alert/v1/) in a CloudEvents 1.0
  envelope (source `//aegisbastion/monitor`, type `com.aegisbastion.alert.v1`),
  work-queue to the Alert module. Mapping per doc 03 §5.3: alertable set +
  `alert_threshold` + confirmed/probable only; `authorization_token_id` from
  the watch token (mandatory for confirmed active-scan exposure alerts);
  passive-derived alerts carry the RoE id in labels and are downgraded to
  `probable`.
- `monitor.assets.new` — NewAssetCandidate v1 (in_scope / out_of_scope /
  excluded per doc 03 §9.4; excluded candidates are audit-only,
  customer-declared do-not-touch).

Module-internal: `monitor.scan.jobs` (JetStream WorkQueue, 5 min visibility,
max 3 redeliveries) — scheduler → workers, module-private JSON.

## Storage (schema `monitor`, db/migrations/000004)

11 migrated tables: `watch_assets` (persisted scheduler heap),
`snapshots_latest` (hot diff path), `snapshots_history` + `change_events`
(monthly RANGE partitions, insert-on-change), `event_outbox` (transactional
with the change insert), `dedup_window` (24 h fingerprint window),
`baselines` / `baseline_state` (sticky drift), `exposure_state`
(CLOSED→OPEN→CLOSED transitions only), `suppressions` (gate outbound emission
only — history is never deleted), `scan_jobs_dead` (DLQ). Raw bodies → MinIO
`monitor-raw` (zstd, PII-redacted pre-upload, 30 d lifecycle). Service-local
idempotent DDL at startup adds `pending_changes` (2-consecutive-probe
confirmation, doc 03 §7.1), `asset_candidates` (§9.4 metadata-only records),
`watch_assets.failing_since` (§12 persistence window), and current/next month
partitions.

## Rules engines (M5, doc 03 §7.3/§7.4)

Baseline rules (`http_header`, `http_redirect`, `tech_allowlist`, `port_set`,
`captured` from `monitor.baseline.set`) and the versioned exposure ruleset
`exposure_rules/v1` (25 rules, EXP-001…EXP-025). Drift/exposure state is
sticky — only transitions emit (`baseline.drift` / `baseline.drift_resolved`,
`exposure.opened` / `exposure.closed`).

**Deviation (recorded):** doc 03 §10 specifies OPA/Rego for M5. Ruling B
re-scoped doc 01's OPA use and the ratified Phase-0 gatekeeper ships a
hard-coded pipeline ("no custom OPA yet", doc 00 §3), so the
"aligns with doc 01 AuthZ" rationale no longer applies at MVP-A. The exact v1
rule semantics are implemented as data-driven, versioned rule definitions in
`internal/rules` behind a small interface; a Rego evaluator can replace the
evaluator without touching callers, rules, or state tables.

## M6 emission discipline

Dedup (24 h fingerprint window, repeats bump `count`), per-mission emission
cap (default 500/h) + global ceiling (10 k/min) with overflow aggregated into
`monitor.change_burst`, operator suppressions — all gate OUTBOUND emission
only; `change_events` history is append-only (zero event loss, doc 03 §15.5).
Transactional outbox relay publishes to the bus (500 msg/batch).

## Management API (doc 03 §13, HTTP :8084)

`GET /v1/watches[/{id}]`, `GET /v1/assets/{id}/timeline`,
`GET /v1/assets/{id}/snapshots`, `POST /v1/assets/{id}/rescan` (routed
THROUGH the Orchestrator via `PlannerService.SubmitTaskPlan` — the PEP path
is never bypassed), `POST/DELETE /v1/suppressions[/{id}]`,
`GET /v1/exposures`, `GET /v1/rules/exposures` (read-only at MVP),
`GET /healthz`, `GET /readyz`, `GET /metrics`.

## Configuration (env)

`DATABASE_URL` (required), `DB_SEARCH_PATH` (default `monitor`), `NATS_URL`,
`REGISTRY_ADDR`, `GATEKEEPER_GRPC_ADDR`, `GATEKEEPER_JWKS_URL` (optional HTTP
JWKS override), `S3_ENDPOINT` / `S3_ACCESS_KEY` / `S3_SECRET_KEY` / `S3_USE_TLS`,
`MONITOR_RAW_BUCKET` (default `monitor-raw`), `HTTP_PORT` (default 8084),
`WORKER_ID`, `REGION`, `MONITOR_WORKERS` (default 8),
`MONITOR_EGRESS_CAP_PER_MINUTE` (default 200, doc 03 §9.3 layer c),
`MONITOR_SCHEDULER_INTERVAL` (15 s), `MONITOR_WATCHSET_SYNC_INTERVAL` (1 min),
`MONITOR_CT_ENABLED` (true), `MONITOR_CT_BASE_URL`, `MONITOR_CT_INTERVAL` (5 min).

## Tests

- Unit: diff correctness + golden semantics (`internal/diff`), normalization
  (`internal/normalize`), probes via fixtures/loopback (`internal/probes`),
  change_type v1 enum coverage — all 30 values bidirectional
  (`internal/ctypes`), alert mapping validated against
  `schemas/alert/v1/*.schema.json` (`internal/alertmap`), fail-closed gate
  proofs — forged token / task-binding mismatch / out-of-scope / revocation
  (`internal/worker`), rules + CT classification (`internal/rules`,
  `internal/ctlog`).
- Integration (`internal/itest`, env-gated on `AEGISBASTION_TEST_DATABASE_URL` +
  `AEGISBASTION_TEST_NATS_URL` against `deploy/docker-compose.yml --profile infra`):
  store round-trip, outbox relay → bus round-trip on `monitor.changes` /
  `monitor.alert` (envelope + CloudEvents assertions; tolerates a live herald
  consuming `monitor.alert` by falling back to the exact outbox bytes), dedup
  replay exactly-once, suppression-keeps-history, emission cap + change_burst
  with zero event loss, end-to-end change (doc 03 §15.1: flipped DNS A record
  → exactly one `dns.records_changed` on the bus, per-probe authorization
  counted), passive-only zero-contact (doc 03 §15.3: fixture counters prove no
  probe ran while a cached expired cert still opens EXP-003, firing exactly
  once across sweeps).
