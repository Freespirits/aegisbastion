# deploy/ — MVP-A local deployment (doc 01 §14, Ruling C6)

One Docker-Compose host carrying the full MVP-A stack: **Postgres 16 +
NATS JetStream + MinIO** plus the platform services.

## Quick start (infra tier only — works today)

```sh
cd deploy
cp .env.example .env        # optional; sane dev defaults are baked in
docker compose --profile infra up -d
```

This starts:

| Service | What | Ports (host) |
|---|---|---|
| `postgres` | PostgreSQL 16, single DB `aegisbastion`, schema-per-context | 5432 |
| `db-migrate` | one-shot: applies `../db/migrations` (golang-migrate) and exits | — |
| `nats` | NATS 2.11 with JetStream enabled | 4222 (client), 8222 (monitoring) |
| `jetstream-bootstrap` | one-shot: creates canonical streams/subjects + KV buckets and exits | — |
| `minio` | S3-compatible object storage | 9000 (API), 9001 (console) |
| `minio-init` | one-shot: creates buckets (`artifacts`, `evidence`, `token-manifests`, `legal-artifacts`, `audit-payloads`, `monitor-raw` w/ 30 d lifecycle) | — |

The two one-shot provisioners are idempotent — re-running `up` is safe.

Check the topology afterwards:

```sh
docker compose --profile infra logs jetstream-bootstrap
docker exec aegisbastion-mvp-a-postgres-1 psql -U aegisbastion -c '\dn'
```

## App tier (later waves)

`docker compose --profile infra --profile apps up -d --build` adds the
service containers — `gatekeeper`, `platform-core` (Mission API /
Orchestrator / Registry / Scheduler), `data-platform`, `discover`,
`monitor`, `detect`, `alert`, `dashboard`. They reference Dockerfiles at
`../services/<module>/Dockerfile` which the implementation waves add; until
then the `apps` profile intentionally does not build. Env wiring (DB schema
search path, NATS URL, MinIO creds, gatekeeper gRPC/JWKS addresses, ports)
is already in place in `docker-compose.yml` and documented per service.

## jetstream-bootstrap

`jetstream-bootstrap/` is a small Go program (also built as a one-shot
container by compose) that provisions the canonical JetStream topology —
streams for `task.assign.*`, `task.result`, `agent.heartbeat`,
`mission.events`, `audit.events`, the gatekeeper `*.v1` subjects
(`authz.decisions.v1`, `authz.denials.v1`, `tasks.revocations.v1`, …),
`monitor.*`, `detect.findings` + the `*.alert` ingress, the doc 05
`alerts.*` pipeline, `dp.>` ingest events, `hub.discover.*`,
`intel.feeds.phishing`, `stress.*` — plus KV buckets `leases` (per-target
intrusive leases, doc 01 §6.4 / Ruling C12), `rate_buckets`,
`agent_presence` (30 s registry TTL), `detect_dedup`.

`control.kill` is deliberately **not** a stream: doc 01 §8.1 defines it as
a core NATS broadcast (no persistence; 5 s ACK SLA).

Local build (no Docker):

```sh
cd jetstream-bootstrap && go build ./...
```

## Teardown

```sh
docker compose down        # keep data volumes
docker compose down -v     # wipe Postgres/NATS/MinIO data
```
