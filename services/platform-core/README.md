# services/platform-core — AegisBastion Platform Core (doc 01)

The command layer of the Connector Hub: Mission API, Task Orchestrator with
embedded Scheduler and the dispatch PEP, Agent Registry, and the kill
switch. One Go binary with subcommands; state in Postgres (schema
`platform`), bus on NATS JetStream, authorization delegated fail-closed to
gatekeeper (doc 11, the single PDP — Ruling B).

**Non-negotiable invariant (doc 01 §1):** no task with risk class ≥ R1 is
dispatched unless a gatekeeper authorization decision record exists and is
linked in the audit log. The orchestrator physically cannot enqueue an
unauthorized task — the dispatch PEP is fail-closed on every dependency
failure (doc 01 §13), and every authorization attempt is recorded in the
platform's hash-chained audit log (`platform.audit_events`).

## Subcommands

| Command | Purpose |
|---|---|
| `serve` | Run everything: gRPC (Mission/Planner/Agent services) + REST Mission API + orchestrator loops (scheduler, reaper, outbox relay, bus consumers). |
| `echo-planner` | Deterministic commander stub (testing): subscribes `StreamMissionEvents` for `ECHO_PLANNER_MISSION_ID` and submits one deterministic plan on `MISSION_ACTIVATED` through the real PlannerService gRPC contract. |
| `verify-audit-chain` | Recompute the audit hash chain and exit non-zero on any broken link. |

## Surfaces

- **REST Mission API** (`:8081`, doc 01 §7.3): `POST /v1/missions`,
  `GET /v1/missions/{id}`, `POST /v1/missions/{id}/pause|resume|kill`,
  `GET /v1/missions/{id}/audit?after_seq=&limit=`,
  `POST /v1/roe/approve`, `POST /v1/roe/revoke` (proxied to gatekeeper),
  `GET /healthz`, `GET /readyz`. Operator identity via `X-Operator-Id`
  header (MVP RBAC shim `PLATFORM_OPERATORS`; real RBAC is gatekeeper
  rbac-service).
- **gRPC** (`:50052`): `platform.v1.MissionService`, `PlannerService`
  (doc 01 §7.2), `AgentService` (doc 01 §8.3). Reflection enabled.
- **Bus** (doc 01 §8.1): publishes `task.assign.{agent}` (via transactional
  outbox, WorkQueue stream), `mission.events`; consumes `task.result`,
  `agent.heartbeat`, and gatekeeper's `tasks.revocations.v1` → maps to
  `control.kill` **core-NATS broadcast** (no JetStream durable, Ruling C11).

## How dispatch works (doc 01 §6.3)

1. Scheduler picks a QUEUED task (`SELECT … FOR UPDATE SKIP LOCKED` — the
   tasks table IS the queue, doc 01 §12); mission must be ACTIVE, no kill
   flag engaged, dependencies COMPLETED.
2. Capability match against the Agent Registry (ONLINE, risk ceiling ≥ task
   risk, capacity free; R3 requires `sandboxed`).
3. R2/R3: per-target intrusive leases in NATS KV `leases/target/{sha256}`
   (Ruling C12 platform-wide serializer; TTL = task deadline).
4. Per-RoE `max_concurrent_intrusive` bucket (Postgres-counted).
5. Dispatch PEP: `gatekeeper.v1.PolicyService.Authorize` **fail-closed**;
   on ALLOW, `TokenService.MintToken` (scope-bound form only for R1
   `monitor.watch`/`monitor.rescan`, Ruling A). Every attempt — ALLOW, DENY,
   or UNAVAILABLE — is written to the audit chain before any publish.
6. `QUEUED → DISPATCHED` + outbox row in one tx; `TASK_DISPATCHED` audit;
   assignment delivered via bus outbox relay AND in-process
   `StreamTasks` broker (same `TaskAssignment` payload, doc 01 §8.3).
7. Agent ACKs ≤ 10 s (else redelivery), reports `TaskResult`; Orchestrator
   validates `targets_touched` against the authorized set — an out-of-scope
   touch raises `SCOPE_VIOLATION`: agent quarantined, mission paused
   (doc 01 §10.5).
8. `monitor.watch` completions with `renewal_requested` enqueue a renewal
   task (the "cron for Monitor cadence", doc 01 C3), which re-runs the full
   gated path with a fresh decision and token.

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | — (required) | Postgres DSN |
| `DB_SEARCH_PATH` | `platform` | schema-per-context (doc 01 §11) |
| `NATS_URL` | `nats://localhost:4222` | JetStream bus |
| `GATEKEEPER_GRPC_ADDR` | `localhost:50051` | the single PDP |
| `PLATFORM_GRPC_PORT` / `PLATFORM_REST_PORT` | `50052` / `8081` | listeners |
| `PLATFORM_OPERATORS` | empty (dev: allow all) | comma-separated operator identities (RBAC shim) |
| `PLATFORM_COMMANDER_QUOTA` | `50` | in-flight budget per commander (doc 01 §4.2) |
| `PLATFORM_DEFAULT_MAX_CONCURRENT_INTRUSIVE` | `4` | per-RoE intrusive cap when RoE declares none |
| `PLATFORM_ACK_TIMEOUT` | `10s` | ACK window before redelivery (doc 01 §9.3) |
| `PLATFORM_AGENT_HEARTBEAT_TTL` | `30s` | registry presence TTL (doc 01 §8.1) |
| `PLATFORM_QUEUE_TTL` | `24h` | QUEUED → EXPIRED window |
| `PLATFORM_AUDIT_SPILL_FILE` | empty | last-resort audit spill (fsync before dispatch, doc 01 §13); when unset, a hard audit failure blocks dispatch |
| `PLATFORM_ARTIFACT_BUCKET` | `artifacts` | MinIO evidence bucket |
| `ENABLE_ECHO_PLANNER` / `ECHO_PLANNER_CAPABILITY` / `ECHO_PLANNER_TARGETS` | `false` / `monitor.feed.sync` / `localhost` | in-process commander stub for testing |

## Schema objects this service owns at runtime

Migrations `db/migrations/000001_platform_core` create missions/plans/
tasks/registry/outbox/kill_switches. The **audit chain table**
(`platform.audit_events`, doc 01 §5.9 — the command layer's operational
chain; the audit of record for authorization state is gatekeeper's) is
created idempotently at startup by `internal/bootstrap` — service-side to
avoid golang-migrate version collisions with the migrations wave; a later
proper migration can adopt it (all DDL is `IF NOT EXISTS`/`OR REPLACE`).
Append-only is enforced by a DB trigger (updates/deletes rejected,
doc 01 §10.4).

## Tests

```bash
# unit (hermetic)
GOWORK=off go test ./...

# integration (compose infra tier up: docker compose --profile infra up -d)
AEGISBASTION_TEST_DATABASE_URL="postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable" \
AEGISBASTION_TEST_NATS_URL="nats://localhost:4222" \
GOWORK=off go test ./... -count=1
```

Integration coverage includes **doc 01 §15 acceptance test 1** (gatekeeper
unreachable → zero R1+ dispatches, every attempt audited — uses a real gRPC
client dialed at a dead port), the R0-continues corollary (doc 01 §13),
lease mutual exclusion on the real NATS KV bucket, per-RoE concurrency
buckets, kill-switch mapping (ROE + global revocation → `control.kill` core
broadcast + DB flags + drain), plan-intake validation/idempotency/
delegation, scope-violation quarantine, and audit chain verification.

Cross-package integration suites serialize on a Postgres advisory lock
(`internal/itlock`) because every suite truncates the shared schema.

## Docker

```bash
cd deploy
docker compose build platform-core          # stages ../gen/go via additional_contexts
docker compose --profile infra --profile apps up -d --build platform-core
```
