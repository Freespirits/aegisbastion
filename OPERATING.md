# AegisBastion Connector Hub

Monorepo for the AegisBastion security platform: authorized attack-surface
discovery, 24/7 monitoring, vulnerability detection, and alerting — all behind
a central authorization gatekeeper. The platform contract set (`proto/`,
`schemas/`) is the single source of truth; terse "doc NN §x.y" citations in
code comments refer to the project's internal design documents, which are not
distributed with this repository.

Ratified facts the whole repo honors:

- **NATS JetStream is the canonical bus** (Ruling C3).
- **The gatekeeper Scope Token is the only execution credential** (Ruling C5):
  Ed25519/EdDSA JWT, JWKS-verified, task-bound, `aud=aegisbastion.modules`, 15-min
  TTL for all active classes R1–R3, targets as hashed manifest — plus the Ruling
  A scope-bound watch-token extension, valid only for `monitor.watch` /
  `monitor.rescan`.
- **Gatekeeper (doc 11) is the single PDP** — everything else is a PEP (Ruling B).
- **Risk taxonomy is R0–R3** (doc 01; doc 11's T0–T2 map T0→R0, T1→R1, T2→R2∪R3).
- **MVP-A deploys as one Docker-Compose host** with Postgres 16 + NATS JetStream
  + MinIO (Ruling C6).
- **Asset/findings store is plain PostgreSQL** using doc 02 §4.1's relational
  schema, owned by doc 09 (Ruling C4).

## What AegisBastion is

AegisBastion lets security operators run offensive-flavored reconnaissance and
validation work against infrastructure they are *authorized* to touch — and
nothing else. A human-authored, legally anchored Rules-of-Engagement (RoE)
record is the root of all authority; every scan, probe, and alert traces back
to an RoE, an authorization decision, and a short-lived cryptographic token,
and every step lands in a hash-chained, append-only audit log. The MVP-A slice
(this repo) delivers the full pipeline — Discover → Monitor → Detect → Alert —
on one Docker Compose host.

**MVP-A module map:**

| Module | Directory | Port(s) (host) | Purpose |
|---|---|---|---|
| gatekeeper | `services/gatekeeper` | 8080 (admin REST + JWKS), 50051 (gRPC) | The single PDP: RoE, Scope Tokens, policy pipeline, RBAC, four-eyes approvals, revocation/kill switch, hash-chained audit |
| platform-core | `services/platform-core` | 8081 (Mission REST), 50052 (gRPC) | Mission API, Orchestrator + Scheduler, dispatch PEP, Agent Registry, kill switch |
| data-platform | `services/data-platform` | 8082 | System of record for assets/findings: Ingest API + GraphQL Query API + TPEL tenancy |
| discover | `services/discover` | 8083 (REST), 8087 (`discover-mcp`) | EASM ingestion: passive DNS + Certificate Transparency + credentialed-cloud workers |
| monitor | `services/monitor` | 8084 | 24/7 change detection: watch/rescan on scope-bound watch tokens, diff + rules engines |
| detect | `services/detect` | 8085 (health), 8090 (OOB service) | Vuln scanning (Nuclei/Nmap) + AVE validation + exploit-verification sandbox |
| alert (herald) | `services/alert` | 8086 | Sole notification egress: enrich → dedup → correlate → route → deliver (Slack/Teams/Splunk/syslog/webhook) |
| dashboard | `services/dashboard` | 3000 | Operator UI (Next.js BFF): assets, findings, missions, RoE, approvals, alert rules |
| phish-catcher | `modules/phish-catcher` | — (standalone) | Client-side phishing detection library, Node CLI, Chrome MV3 extension (hub loop is MVP-B) |
| commander adapters | `adapters/` | — (not in Compose) | HexStrike MCP (`mock`/`http`, MIT), Strix (Apache-2.0), PentestGPT (MIT), CAI (`stub` demo planner, **BYO** — research-use upstream, no CAI code vendored) |

**The security model in three bullets:**

- **One decider.** The gatekeeper is the platform's only Policy Decision Point.
  Missions, modules, the dashboard, and the commanders are all Policy
  Enforcement Points that ask the gatekeeper (or re-verify its tokens) and
  never decide anything themselves.
- **One credential.** Active work (risk classes R1–R3) runs only under a
  gatekeeper-minted Scope Token: an Ed25519-signed JWT, task-bound, audience
  `aegisbastion.modules`, hard-capped 15-minute TTL, with targets pinned to a
  sha256-hashed manifest in MinIO. Exclusions always win; unknown capabilities
  are denied.
- **Fail-closed everywhere.** Gatekeeper unreachable ⇒ no dispatch, no ingest,
  no alert delivery. Revocation propagates on `tasks.revocations.v1` /
  `control.kill` and halts target contact within 5 seconds. Every decision,
  denial, touch, and halt is appended to the hash-chained audit of record.

## Architecture at a glance

```
 commanders (planners — never authorizers)                    operator
 ┌──────────────────────┐  ┌──────────────┐                ┌───────────┐
 │ HexStrike MCP adapter│  │ CAI (BYO)    │                │ dashboard │ :3000
 │ (adapters/hexstrike- │  │ (adapters/cai│                └─────┬─────┘
 │  mcp, mock|http)     │  │  REST :8082) │                      │ BFF /api/*
 └──────────┬───────────┘  └──────┬───────┘                      ▼
            │ TaskPlan (gRPC PlannerService :50052)   gatekeeper / platform-core /
            ▼                                          data-platform / herald
 ┌───────────────────────────────────────────────────────────────────────┐
 │ platform-core :8081/:50052   Mission API · Orchestrator · Scheduler · │
 │                              dispatch PEP · Agent Registry · kill      │
 └───────────────┬───────────────────────────────────────────────────────┘
                 │ Authorize + MintToken (fail-closed, every R1+ task)
                 ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ gatekeeper :8080/:50051  the single PDP — RoE · Scope Tokens · policy │
 │ pipeline · RBAC · four-eyes approvals · revocations · hash-chained     │
 │ audit of record                                                        │
 └───────────────┬───────────────────────────────────────────────────────┘
                 │ Scope Token (Ed25519, 15-min TTL, hashed manifest)
                 ▼
 ┌─────────────────────────── modules (PEPs) ────────────────────────────┐
 │ discover :8083/:8087   passive DNS · CT · credentialed cloud          │
 │ monitor  :8084         watch/rescan on scope-bound watch tokens       │
 │ detect   :8085/:8090   nuclei/nmap · AVE · EVS · OOB canaries         │
 └───────────────┬───────────────────────────────────────────────────────┘
                 │ assets / findings / changes (Ingest API, Scope Token re-verified)
                 ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ data-platform :8082   Postgres dp/tenancy schemas · GraphQL · TPEL     │
 └───────────────┬───────────────────────────────────────────────────────┘
                 │ *.alert (CloudEvents, ALERT_INGRESS work-queue)
                 ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ herald :8086  sole notification egress → Slack · Teams · Splunk HEC ·  │
 │ syslog · HMAC-signed webhooks (delivery outbox + audit)                │
 └───────────────────────────────────────────────────────────────────────┘

 infra tier (Compose profile "infra"):
   Postgres 16 :5432 (one DB, schema-per-context) · NATS JetStream :4222
   (+ monitoring :8222) · MinIO :9000 (console :9001)
```

## Prerequisites

- **Docker Desktop with Compose v2+** (Windows/macOS) or Docker Engine +
  compose plugin (Linux). **Every service in `deploy/docker-compose.yml`
  belongs to a profile — you must pass `--profile` flags** or nothing starts
  (see Troubleshooting).
- **Go 1.25+** and **Node 20+** — development only (building services, running
  tests, regenerating contracts). The Docker path needs neither. herald runs
  on Node 22 in its container.
- **No other tooling to install:** `buf` is vendored at `bin/buf.exe`
  (v1.72.0) and the codegen plugins live in `bin/`. `make` is optional — the
  Makefile is a thin wrapper over the raw commands shown below.
- **Windows:** run commands from Git Bash (or PowerShell where noted). macOS /
  Linux work as-is; replace `bin/buf.exe` with a `buf` on your `PATH`.
- ~4 GB free RAM for the full stack; first `--build` downloads Go/Node base
  images and compiles everything (10–20 min on a cold cache).

## Quick start (Docker, ~5 min)

All compose commands run from `deploy/` (the compose project is named
`aegisbastion-mvp-a`).

### 1. Configure the environment

```bash
cd deploy
cp .env.example .env
```

The defaults in `.env` work out of the box for local dev. Two additions are
recommended — **they are not in `.env.example`, append them yourself**:

```bash
# append to deploy/.env
SESSION_SECRET=$(openssl rand -base64 32)   # or: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
DEV_AUTH_ENABLED=true                        # dashboard dev login shim (default is already true)
```

On Windows PowerShell, generate the secret with:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Also useful later (empty = feature off): `ALERT_SLACK_WEBHOOK_URL`,
`ALERT_WEBHOOK_SIGNING_SECRET`, `HERALD_ADMIN_ACTORS`, `OIDC_ISSUER_URL`,
`OIDC_CLIENT_ID`. See the Configuration reference.

### 2. Start the infra tier

```bash
docker compose --profile infra up -d
```

This starts Postgres 16, NATS + JetStream, MinIO, and three one-shot
provisioners (`db-migrate`, `jetstream-bootstrap`, `minio-init`). Verify:

```bash
# migrations applied — expect version 6
docker exec aegisbastion-mvp-a-postgres-1 \
  psql -U aegisbastion -d aegisbastion -tc "SELECT version FROM schema_migrations;"

# JetStream topology — 21 streams + 4 KV buckets, provisioner is idempotent
docker compose --profile infra logs jetstream-bootstrap
```

### 3. Build and start the app tier

```bash
docker compose --profile infra --profile apps up -d --build
```

> If you are working from a fresh clone and the build fails on a missing
> `gen/go` context, regenerate the contract stubs first (needs Go + Node):
> `npm install && make tools && make proto-gen` from the repo root, then
> re-run the compose command.

### 4. Health-check everything

| Service | Check | Expected |
|---|---|---|
| gatekeeper | `curl -fsS http://localhost:8080/healthz` | 200 |
| gatekeeper JWKS | `curl -fsS http://localhost:8080/.well-known/gatekeeper-jwks.json` | `{"keys":[…]}` |
| platform-core | `curl -fsS http://localhost:8081/healthz` | 200 |
| data-platform | `curl -fsS http://localhost:8082/healthz` | 200 |
| discover | `curl -fsS http://localhost:8083/healthz` | 200 |
| monitor | `curl -fsS http://localhost:8084/healthz` | 200 |
| detect | `curl -fsS http://localhost:8085/healthz` | 200 |
| alert (herald) | `curl -fsS http://localhost:8086/healthz` | 200 |
| discover-mcp | `curl -fsS http://localhost:8087/healthz` | 200 |
| dashboard | `curl -fsS http://localhost:3000/api/health` | 200 |
| NATS monitoring | `curl -fsS http://localhost:8222/healthz` | `{"status":"ok"}` |
| MinIO | `curl -fsS http://localhost:9000/minio/health/live` | 200 |

(Windows PowerShell 5.1 aliases `curl` to `Invoke-WebRequest`; use
`curl.exe` there, or Git Bash.)

Teardown: `docker compose down` (keep data) or `docker compose down -v` (wipe
Postgres/NATS/MinIO volumes).

## First end-to-end run

This walks the doc 00 §4 acceptance flow by hand: RoE → mission → discovery →
monitoring/detection → alert → revocation. Substitute your own domain for
`example.com` (use infrastructure you are authorized to test — the platform
enforces that, but so does the law).

### (a) Log into the dashboard

Open http://localhost:3000 — you are redirected to `/login`. With
`DEV_AUTH_ENABLED=true` (the compose default) the dev login form accepts any
principal (the shared `DEV_AUTH_TOKEN` is unset in compose). Log in as
`op_jane@example.com`; when gatekeeper's rbac-service has no grant for you,
the session falls back to the `operator` role (`DEV_AUTH_FALLBACK_ROLES`).

### (b) Create and activate an RoE

The gatekeeper admin REST is protojson (`snake_case`) and unauthenticated on
the compose network at MVP-A. First grant yourself the RBAC roles (RoE
creation enforces `roe:create`, and you'll want `operator` for the
revocation CLI's `revocation:issue` check):

```bash
curl -fsS -X POST http://localhost:8080/v1/rbac/grants \
  -H 'content-type: application/json' \
  -d '{"org_id":"org_acme","principal":"op_jane@example.com","principal_kind":"human","role":"roe-author","granted_by":"bootstrap"}'

curl -fsS -X POST http://localhost:8080/v1/rbac/grants \
  -H 'content-type: application/json' \
  -d '{"org_id":"org_acme","principal":"op_jane@example.com","principal_kind":"human","role":"operator","granted_by":"bootstrap"}'
```

Then create the RoE (draft, version 1). The body is the
`gatekeeper.v1.RulesOfEngagement` message; adjust the timestamps:

```bash
curl -fsS -X POST http://localhost:8080/v1/roe \
  -H 'content-type: application/json' \
  -d '{
    "org_id": "org_acme",
    "name": "example.com external assessment",
    "created_by": "op_jane@example.com",
    "authorized_by": {"identity": "ciso@example.com", "role": "customer_authorizer", "at": "2026-08-01T00:00:00Z"},
    "scope": {"domains": ["example.com", "*.example.com"], "explicit_excludes": []},
    "constraints": {
      "max_risk_class": "RISK_CLASS_R1",
      "allowed_capabilities": ["recon.*", "monitor.*"]
    },
    "valid_from": "2026-08-01T00:00:00Z",
    "valid_until": "2026-08-15T00:00:00Z"
  }'
```

Note the returned `roe_id` (`roe_…`), then activate it (this resolves the
versioned effective target list that tokens bind to):

```bash
curl -fsS -X POST http://localhost:8080/v1/roe/roe_YOUR_ID/activate \
  -H 'content-type: application/json' -d '{"version": 1}'
```

The same flow is available in the dashboard under `/authorizations` (with
step-up confirmation).

### (c) Four-eyes approval (required only for R2/R3 work)

An R0/R1 RoE like the one above activates directly. R2/R3 capabilities
additionally need a verified legal artifact (`grc-verifier` role) and, where
`requires_approval_for` binds, a granted four-eyes approval (approver ≠
author ≠ requester, 72 h expiry). Request and approve:

```bash
# request (requester cannot approve their own request)
curl -fsS -X POST http://localhost:8080/v1/approvals \
  -H 'content-type: application/json' \
  -d '{"roe_id":"roe_YOUR_ID","roe_version":1,"capability":"detect.scan.web",
       "risk_class":"RISK_CLASS_R2","targets":["example.com"],"requester":"op_jane@example.com"}'

# approve via the gatekeeper CLI (runs inside the container, dials localhost:50051)
docker compose exec gatekeeper gatekeeper approvals list --state pending
docker compose exec gatekeeper gatekeeper approvals approve \
  --id appr_… --approver user_second@example.com --note "reviewed scope + LoA"
```

(The approver must hold the `offensive-approver` role — grant it via
`/v1/rbac/grants` as above. The `/approvals` dashboard page exposes the same
queue.)

### (d) Create a mission

```bash
curl -fsS -X POST http://localhost:8081/v1/missions \
  -H 'content-type: application/json' \
  -H 'X-Operator-Id: op_jane@example.com' \
  -d '{"name":"example-surface","owning_commander":"COMMANDER_CAI",
       "objective":"map and watch example.com","roe_id":"roe_YOUR_ID",
       "priority":"PRIORITY_P1_OPERATOR"}'
```

New missions are `DRAFT`; activate with `POST /v1/missions/{id}/resume`.
Platform-core validates the RoE against gatekeeper at admission and pins
`roe_version`; every subsequent task dispatch re-authorizes fail-closed.

### (e) Watch assets and changes flow

Submit a passive discovery order (Discover's own commander contract; the
dispatch PEP path is used for platform tasks, orders go through Discover's
intake gate which calls the same gatekeeper `Authorize`):

```bash
curl -fsS -X POST http://localhost:8083/v1/discovery/orders \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"TENANT_UUID","requested_by":{"commander":"cai","agent_id":"cai-stub","human_principal":"op_jane@example.com"},
       "seeds":[{"type":"domain","value":"example.com"}],
       "techniques":["passive_dns","ct"],
       "authorization":{"roe_id":"roe_YOUR_ID"},
       "options":{"max_depth":1,"max_assets":100,"max_tasks":20,"time_budget_sec":600,"priority":"normal","dedup_against_existing":false}}'
```

**One-time data-platform tenancy bootstrap** (needed before Discover can push
assets into dp, before herald can enrich, and before the dashboard can query):
dp resolves tenants from grants, and its admin shim is disabled unless
`DP_ADMIN_PRINCIPALS` is set — so seed directly:

```bash
docker exec -i aegisbastion-mvp-a-postgres-1 psql -U aegisbastion -d aegisbastion <<'SQL'
INSERT INTO tenancy.tenants (name) VALUES ('acme') RETURNING tenant_id;
-- then, with the returned UUID:
INSERT INTO tenancy.grants (tenant_id, principal, role) VALUES
  ('TENANT_UUID', 'svc-discover',        'service_discover'),
  ('TENANT_UUID', 'op_jane@example.com', 'analyst');
SQL
```

(Use the returned UUID as `TENANT_UUID` in the order above and as
`X-DP-Tenant` where needed. herald's enrichment grant has a ready-made,
idempotent seed — see step (f).)

Then watch the flow:

- **Order status:** `curl -fsS http://localhost:8083/v1/discovery/orders/{id}`
  (the `gate` field shows gatekeeper's decision and reason codes).
- **Dashboard:** `/assets` (attack-surface map) and `/findings`.
- **GraphQL directly** (TPEL: the principal resolves the tenant):

```bash
curl -fsS -X POST http://localhost:8082/v1/query \
  -H 'content-type: application/json' -H 'X-DP-Principal: op_jane@example.com' \
  -d '{"query":"{ assets(first: 10) { edges { node { id type value firstSeen } } } }"}'
```

- **Bus:** subjects `hub.discover.asset.changed`, `monitor.changes`,
  `monitor.assets.new`, `detect.findings`, `dp.asset.created`. Inspect stream
  state at `http://localhost:8222/jsz?streams=true` (or with the `nats` CLI if
  you have it locally: `nats sub monitor.changes --server nats://localhost:4222`).

Monitor watches are issued by commander plans through the Orchestrator (R1,
scope-bound watch tokens, continuously re-authorized). Detect scans (R1–R2)
follow the full gated path: dispatch PEP decision → token mint → per-target
lease → scan → validated finding.

### (f) See an alert delivered

herald is the only component allowed to notify. Out of the box
`HERALD_DELIVERY_MODE` is `record` — every delivery is persisted to the
recorded outbox but **nothing leaves the host**. To get real egress:

1. Set `ALERT_SLACK_WEBHOOK_URL` (Slack incoming webhook) and/or
   `ALERT_WEBHOOK_SIGNING_SECRET` (HMAC for generic webhooks) in `deploy/.env`.
2. Add `HERALD_DELIVERY_MODE: "live"` to the `alert` service's `environment:`
   block in `deploy/docker-compose.yml` (the compose file does not pass it
   through from `.env`).
3. Grant herald its dp enrichment principal (idempotent; re-run after adding
   tenants):

```bash
docker exec -i aegisbastion-mvp-a-postgres-1 \
  psql -U aegisbastion -d aegisbastion -f - < ../services/data-platform/seeds/herald-service-alert.sql
```

4. Create a routing rule (policy mutations require an admin actor —
   `HERALD_ADMIN_ACTORS`, default `cai,hexstrike-ai`; add
   `op_jane@example.com` in `deploy/.env` or use the header below):

```bash
curl -fsS -X POST http://localhost:8086/v1/policies/routing \
  -H 'content-type: application/json' -H 'X-AegisBastion-Actor: hexstrike-ai' \
  -d '{"org_id":"org_acme","priority":100,"enabled":true,
       "match":{"severity_gte":"medium"},
       "targets":[{"channel":"slack","destination":"#aegisbastion-alerts"}]}'
```

Dry-run the rule with `POST /v1/routes/test`, and inspect the recorded outbox
at `GET /v1/deliveries` — or use the dashboard's `/alert-rules` page, which
wraps all three. The next `monitor.alert` / `detect.alert` event matching the
rule produces a delivery row (and a real Slack message in `live` mode).

### (g) Revoke the RoE mid-watch — the ≤5 s halt

```bash
docker compose exec gatekeeper gatekeeper revoke \
  --scope roe --key roe_YOUR_ID --by op_jane@example.com --reason "engagement paused"
```

(Equivalently `POST /v1/roe/{id}/revoke`, or `POST /v1/revocations` for
global/target/capability scopes.) The revocation broadcasts on
`tasks.revocations.v1`; the Orchestrator maps it to the `control.kill`
core-NATS broadcast; modules' PEP guards halt target contact within 5 seconds
and dead-letter any job whose token no longer verifies. The halt — like every
step above — is in the hash-chained audit: verify with
`curl -fsS http://localhost:8080/v1/audit/verify` or per-mission at
`GET http://localhost:8081/v1/missions/{id}/audit`.

**What works with zero real credentials vs. what needs them:** everything
above runs on dev defaults — dev-auth login, RBAC grants via REST, passive
connectors that need no API key (crt.sh, rapiddns, wayback, bgpview, ripestat,
rdap), recorded alert deliveries, the `mock` HexStrike adapter, fixture
scanners in detect. Real credentials are needed for: keyed passive sources
(SecurityTrails, VirusTotal, Shodan — `DISCOVER_SOURCE_KEYS_FILE`),
credentialed-cloud enumeration (`DISCOVER_CLOUD_CREDS_FILE`), Slack/Teams
webhooks, live scanner binaries (`DETECT_SCANNER_MODE=exec`), and OIDC login
(`OIDC_ISSUER_URL` / `OIDC_CLIENT_ID`).

## Configuration reference

All env wiring lives in `deploy/docker-compose.yml`; local-dev defaults in
`deploy/.env.example`. Schema-per-Postgres-context is set via `DB_SEARCH_PATH`
per service. The important per-service knobs:

| Service | Env var | Default / compose value | Notes |
|---|---|---|---|
| gatekeeper | `GATEKEEPER_SIGNING_KEY_FILE` | `/run/secrets/gatekeeper_ed25519.key` | Created on first boot if absent — **mount a volume/secret there for stable keys**, else tokens from previous containers become unverifiable |
| gatekeeper | `GATEKEEPER_SIGNING_KEY_PASSPHRASE` | — | Seals the key at rest (scrypt + AES-GCM) |
| gatekeeper | `TOKEN_TTL` | `15m` | Hard cap (Ruling C5); larger values refused |
| gatekeeper | `DP_INVENTORY_URL` | unset | Unset = R2/R3 verified-inventory check skipped (Phase-0 deviation); set `http://data-platform:8082` to enable |
| platform-core | `PLATFORM_OPERATORS` | empty (allow all) | Dev RBAC shim for `X-Operator-Id`; set a CSV in real use |
| platform-core | `PLATFORM_COMMANDER_QUOTA` | `50` | In-flight budget per commander |
| data-platform | `DP_ADMIN_PRINCIPALS` | empty (admin API off) | CSV allowed to call `/v1/admin/tenants`; unset ⇒ bootstrap tenants via psql (see walkthrough) |
| discover | `DP_INGEST_URL` / `DP_PRINCIPAL` | `http://data-platform:8082` / `svc-discover` | Empty ingest URL = local-store-only mode |
| discover | `DISCOVER_CONNECTORS_FILE` | `/etc/discover/connectors.yaml` | Baked into the image; per-connector enable flags + rate specs |
| discover | `DISCOVER_SOURCE_KEYS_FILE` / `DISCOVER_CLOUD_CREDS_FILE` | unset | Tenant→API-key / tenant→cloud-credential files (MVP-A vault stand-in); keyed connectors are skipped without them |
| discover | `DISCOVER_OFFLINE` + `DISCOVER_FIXTURES_DIR` | `false` | Replay recorded connector fixtures — no live egress, no dp, no evidence |
| monitor | `MONITOR_WORKERS` / `MONITOR_EGRESS_CAP_PER_MINUTE` | `8` / `200` | Probe pool size / egress ceiling |
| detect | `DETECT_FINDINGS_FALLBACK` | `true` (compose) | Findings go to the local `detect.findings_fallback` store; to publish into dp also set `DP_INGEST_URL=http://data-platform:8082` and flip this to `false` |
| detect | `DETECT_SCANNER_MODE` | `fixture` | `exec` runs real `nuclei`/`nmap` (`DETECT_NUCLEI_BIN` / `DETECT_NMAP_BIN`) |
| detect | `DETECT_EVS_RUNNER` | `local` (compose) | Process-isolated exploit-verification runner; `gvisor` needs a runsc host |
| alert | `HERALD_DELIVERY_MODE` | `record` | `record` = outbox only, no egress; `live` = real sends (**not wired from `.env` — set it in the compose `alert` environment**) |
| alert | `HERALD_ADMIN_ACTORS` | `cai,hexstrike-ai` | CSV allowed to mutate policies / use `channel_override`; the dashboard forwards your session principal — add it here |
| alert | `ALERT_SLACK_WEBHOOK_URL` / `ALERT_WEBHOOK_SIGNING_SECRET` | empty (channel off) | Read from `deploy/.env` at delivery time |
| alert | `HERALD_DP_PRINCIPAL` / `HERALD_DP_TENANT` | `herald` / — | Needs a `service_alert` tenancy grant — use `services/data-platform/seeds/herald-service-alert.sql` |
| dashboard | `SESSION_SECRET` | empty | Required unless dev auth is on (set it anyway) |
| dashboard | `DEV_AUTH_ENABLED` / `DEV_AUTH_TOKEN` / `DEV_AUTH_FALLBACK_ROLES` | `true` / unset / `operator` | Dev login shim — never enable outside local dev |
| dashboard | `OIDC_ISSUER_URL` / `OIDC_CLIENT_ID` | empty (login = dev shim only) | Production authn path |

**Secrets handling:** everything in `deploy/.env` is a local-dev default —
never reuse any of it anywhere real. Channel secrets resolve from env at
delivery time (`HERALD_SECRET_<REF>` per-endpoint overrides exist). **Key
custody:** MVP-A uses a sealed Ed25519 file key for gatekeeper signing
(doc 00 §5 Q1 — see the table row above); Azure Key Vault custody arrives with
MVP-B (doc 12), together with mTLS/SPIFFE service identity.

## Using the pieces

### Dashboard tour (`http://localhost:3000`)

- `/` — overview: backend status pills, session, affordances.
- `/assets` — attack-surface map: tenant-scoped asset list + neighborhood
  graph (dp `assetNeighborhood`, depth ≤ 4).
- `/findings` — triage queue with doc 04 §7.3 lifecycle transitions;
  sensitive findings render digests only.
- `/missions` — gated launch (scope preflight → type-to-confirm → step-up),
  pause/resume/kill, per-mission audit trail.
- `/authorizations` — RoE list/create/activate/suspend/revoke (gatekeeper
  admin REST; no local RoE state).
- `/approvals` — four-eyes approval queue (segregation-of-duties enforced).
- `/alert-rules` — herald routing-policy CRUD, route dry-run, delivery log
  (client only; the dashboard never dispatches a notification).

### gatekeeper CLI

The same binary that serves is the approver/kill-switch CLI; run it inside
the container (`docker compose exec gatekeeper gatekeeper …`) or build it
locally (`GOWORK=off go build ./cmd/gatekeeper` in `services/gatekeeper`):

```bash
gatekeeper approvals list [--state pending] [--roe-id roe_…] [--addr host:port]
gatekeeper approvals show --id appr_…
gatekeeper approvals approve --id appr_… --approver user_… [--note …]
gatekeeper approvals reject  --id appr_… --approver user_… [--note …]
gatekeeper revoke --scope global|roe|target|capability [--key …] --by user_… [--reason …]
```

### phish-catcher (standalone)

Zero-egress, client-side phishing detection — library, CLI, and Chrome MV3
extension; the hub loop is MVP-B. From `modules/phish-catcher`:

```bash
npm install
npm run build
node bin/phish-catcher.mjs scan ./samples/*.eml --json   # exit 0 clean · 1 suspicious · 2 malicious · 3 error
node bin/phish-catcher.mjs scan urls.txt --bundle intel.sb --pin <b64url-key>
node bin/phish-catcher.mjs verify-bundle intel.sb --pin <b64url-key>

npm run build:ext && npm run pack:ext   # → release/phish-ext/
```

Load `modules/phish-catcher/release/phish-ext/` at `chrome://extensions` →
"Load unpacked". Intel ships to the client as signed, versioned bundles
(Ed25519 over JCS, pinned keys, monotonic versions, 14-day freshness →
degraded mode); no inspected content ever leaves the client.

### Commander adapters (`adapters/`)

Not part of the Compose stack — run them on the host against the platform's
gRPC surface. Four commanders: **HexStrike** (`adapters/hexstrike-mcp`, MIT),
**Strix** (`adapters/strix`, Apache-2.0), **PentestGPT**
(`adapters/pentestgpt`, MIT), and **CAI** (`adapters/cai`,
bring-your-own-license — CAI is research-use-only from Alias Robotics, so the
adapter ships only a built-in deterministic `stub` demo planner and vendors
no CAI code; a customer holding an Alias Robotics commercial license plugs
their own backend in behind the `app.Planner` seam). Attribution and
obligations: `adapters/THIRD_PARTY_LICENSES.md`.

Regenerate stubs first if needed (`make proto-gen`), then:

```bash
cd adapters

# HexStrike adapter — mock mode (default): deterministic canned results, no
# HexStrike install needed; HEXSTRIKE_MODE=http fronts a real server
# (HEXSTRIKE_SERVER_URL, default http://127.0.0.1:8888).
PLANNER_ADDR=localhost:50052 GOWORK=off go run ./hexstrike-mcp/cmd/hexstrike-mcp   # MCP over stdio

# Strix and PentestGPT adapters — see adapters/strix/README.md and
# adapters/pentestgpt/README.md for their run modes and configuration.

# CAI adapter — stub demo planner (BYO: no CAI code vendored; a real backend
# requires the operator's Alias Robotics commercial license).
# Deterministic passive-only stub plans (REST, CAI_LISTEN_ADDR :8082).
PLANNER_ADDR=localhost:50052 GOWORK=off go run ./cai/cmd/cai
curl -fsS -X POST http://localhost:8082/v1/intents \
  -H 'content-type: application/json' \
  -d '{"mission_id":"msn_…","objective":"map example.com","targets":["example.com"]}'
```

All are planners, not authorizers: they submit `TaskPlan`s to
`PlannerService` and never see a Scope Token.

### data-platform GraphQL

`POST /v1/query` with TPEL headers (`X-DP-Principal`, plus `X-DP-Tenant` when
the principal holds several grants). Read-only: `asset`, `assets`,
`assetNeighborhood(depth ≤ 4)`, `finding`, `findings`, `taskRollup`; cursor
pagination, page ≤ 500. Finding lifecycle transitions go through
`POST /v1/findings/{id}/transitions`.

### herald policy API

`GET/POST /v1/policies/routing`, `PUT/DELETE /v1/policies/routing/{id}`,
`POST /v1/routes/test` (dry-run), `GET /v1/deliveries` (recorded outbox),
`GET /v1/alerts` / `GET /v1/incidents` / `POST /v1/acks`. Actor identity via
`X-AegisBastion-Actor`; mutations require a `HERALD_ADMIN_ACTORS` principal.
Full surface (including escalation policies and org egress policy) is in
`services/alert/README.md`.

## Development

### Repo layout

```
proto/       buf module — the platform contract set (single source of truth)
  aegisbastion/platform/v1/    Mission, TaskPlan/TaskSpec, TaskAssignment/TaskResult,
                           bus Envelope, AuditEvent, AgentManifest, PlannerService,
                           AgentService, MissionService (doc 01 §5, §7, §8, §9)
  aegisbastion/gatekeeper/v1/  ROEService, TokenService (Authorization Token v1.1
                           claim set), PolicyService (Authorize + deny codes),
                           ApprovalService (four-eyes), RevocationService,
                           AuditService (doc 11 §3, Rulings A/B.4/C5)
  aegisbastion/monitor/v1/     MonitorChange, NewAssetCandidate, change_type enum (doc 03 §4–5)
  aegisbastion/detect/v1/      FindingReport, ScanParams, validation verdicts, risk-v1 (doc 04 §4)
schemas/     JSON Schemas (draft 2020-12) for the JSON-wire contracts
  alert/v1/                AlertEvent v1 + CloudEvents 1.0 envelope (doc 05 §5)
  gatekeeper/v1/           Scope Token v1.1 claims, canonical scope manifest
  examples/                *.valid.json / *.invalid.json test instances
gen/         Generated stubs (regenerate; do not edit)
  go/        protoc-gen-go + protoc-gen-go-grpc output (Go module)
  ts/        protoc-gen-es output (npm workspace @aegisbastion/gen)
db/          Postgres migrations 000001–000006 (golang-migrate) + seeds in services/data-platform/seeds/
deploy/      Docker-Compose host + jetstream-bootstrap (21 streams, 4 KV buckets)
services/    gatekeeper, platform-core, data-platform, discover, monitor, detect, alert, dashboard
modules/     phish-catcher (standalone at MVP-A)
adapters/    Commander adapters (hexstrike-mcp, strix, pentestgpt, cai) — one Go module, one binary per adapter; cai is BYO (research-use upstream, no CAI code vendored)
sdks/        Agent SDK: sdks/go (canonical) + sdks/ts (@aegisbastion/agent-sdk)
infra/       IaC (MVP-B Azure track)
bin/         Vendored tooling (buf v1.72.0, protoc-gen-*) — binaries gitignored
scripts/     validate-schemas.mjs (ajv, draft 2020-12)
```

### Regenerating contracts

```bash
# one-time: codegen plugins + npm deps           (make tools)
GOBIN="$PWD/bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
GOBIN="$PWD/bin" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
npm install

# lint + generate Go and TS stubs into gen/      (make proto-gen)
bin/buf.exe lint proto
PATH="$PWD/bin:$PATH" bin/buf.exe generate proto --template proto/buf.gen.yaml

# verify generated code compiles                 (make build-gen)
cd gen/go && go build ./...
node node_modules/typescript/bin/tsc --noEmit -p gen/ts/tsconfig.json

# validate JSON Schemas + example instances      (make schemas-validate)
node scripts/validate-schemas.mjs
```

After regenerating, re-vendor the Go services whose images build from
`vendor/` (e.g. gatekeeper):
`(cd services/gatekeeper && GOWORK=off go mod tidy && GOWORK=off go mod vendor)`.

### Running module tests

Every Go service is its own module built with `GOWORK=off` (there is no go.work):

```bash
cd services/gatekeeper          # or platform-core, discover, monitor, detect, data-platform
GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./...
```

Unit suites run anywhere. Integration suites target the compose infra tier
(`docker compose --profile infra up -d`) and skip cleanly when it is down;
they pick it up via `AEGISBASTION_TEST_DATABASE_URL` /
`AEGISBASTION_TEST_NATS_URL` (platform-core, monitor), or
`DP_TEST_DATABASE_URL` (data-platform).

TypeScript packages use npm workspaces / vitest:

```bash
cd services/alert          # npm install && npm run typecheck && npm test
cd services/dashboard      # npm install && npm run typecheck && npm test
cd sdks/ts                 # npm run typecheck && npm test
cd modules/phish-catcher   # npm install && npm run typecheck && npm test
```

**Windows Git Bash caveat:** if basic coreutils (`ls`, `grep`) fail with exit
code 127 in your Git Bash, the Git for Windows installation is broken —
reinstall it, or run the affected commands in PowerShell. Nothing in this
repo requires those coreutils beyond convenience.

### Adding a module

Write an agent against the platform agent SDK — never hand-roll contract
items (doc 01 §9 item 4). In Go (`sdks/go`, package docs in `sdks/go/doc.go`)
you implement three methods — `Plan` (validate params), `Run` (do the work),
`Abort` (halt ≤ 5 s on kill) — and the SDK does everything else: registry
registration + heartbeats, task consumption, Scope Token verification against
gatekeeper JWKS, manifest/scope evaluation with exclusions-first matching,
rate caps, revocation cache, kill switch, per-probe `TARGET_TOUCHED` audit
records, and result reporting. During `Run`, every network target contact
goes through `Task.AuthorizeTarget`, which is the full fail-closed PEP-2
chain. TypeScript modules use `@aegisbastion/agent-sdk` (`sdks/ts`) with the
same contract. Then add a Dockerfile under `services/<module>/`, a compose
service in the `apps` profile, and (if you own new state) a migration in
`db/migrations`.

## Troubleshooting

- **`no such service: db-migrate` / nothing starts.** Every compose service
  is behind a profile; `docker compose up -d` without `--profile infra` (and
  `--profile apps` for the services) matches nothing. Always pass both flags
  as shown in Quick start.
- **Docker daemon cold start.** The first `up` after boot can fail with
  connection errors while Docker Desktop starts; wait for the daemon and
  re-run — the provisioners are idempotent.
- **JetStream streams missing** (services log stream-not-found errors):
  re-run the bootstrapper, it is idempotent:
  `docker compose --profile infra up -d jetstream-bootstrap` (or just re-run
  the whole `--profile infra up -d`). Check `docker compose --profile infra
  logs jetstream-bootstrap` for the "21 streams … 4 KV buckets" line.
- **Migration "dirty" state** (a failed migration leaves
  `schema_migrations.dirty = true`): inspect and force the version, then
  re-apply. From `deploy/`:
  `docker run --rm --network aegisbastion-mvp-a_default -v "$PWD/../db/migrations:/migrations:ro" migrate/migrate:4 -path=/migrations -database "postgres://aegisbastion:aegisbastion-dev@postgres:5432/aegisbastion?sslmode=disable" force 6`
  (use the version of the failed migration), then `… up`. See `db/README.md`.
- **Dashboard 401s.** Sessions live in a sealed httpOnly cookie: after
  changing `SESSION_SECRET` or wiping containers, log in again. Without
  `DEV_AUTH_ENABLED=true`, the dashboard needs a real `SESSION_SECRET` and an
  OIDC issuer. Dev login accepts any principal only while `DEV_AUTH_TOKEN` is
  unset.
- **herald policy mutations return 403.** Mutations require the
  `X-AegisBastion-Actor` header to name a principal in `HERALD_ADMIN_ACTORS`
  (default `cai,hexstrike-ai`). The dashboard forwards your logged-in
  principal — add it to `HERALD_ADMIN_ACTORS` in `deploy/.env` and recreate
  the `alert` container.
- **data-platform GraphQL 403 `GRANT_REQUIRED`.** TPEL resolves the tenant
  from `X-DP-Principal` against `tenancy.grants` — fail-closed. Seed a grant
  for your principal (walkthrough step (e)); for herald's enrichment use
  `services/data-platform/seeds/herald-service-alert.sql`. A principal with
  several tenants must send `X-DP-Tenant`.
- **herald records deliveries but nothing arrives.** That is
  `HERALD_DELIVERY_MODE=record` (the default) — set it to `live` in the
  compose `alert` environment plus real channel credentials.
- **All Scope Tokens rejected after a gatekeeper rebuild.** The signing key
  file (`/run/secrets/gatekeeper_ed25519.key`) is not mounted by default, so a
  fresh container mints a fresh key. Mount a volume or Docker secret at that
  path for stable keys.
- **Port reference:**

| Port | Service | Port | Service |
|---|---|---|---|
| 3000 | dashboard | 8085 | detect (health) |
| 50051 | gatekeeper gRPC | 8086 | alert (herald) |
| 50052 | platform-core gRPC | 8087 | discover-mcp |
| 5432 | Postgres | 8090 | detect OOB service |
| 4222 | NATS client | 8222 | NATS monitoring |
| 8080 | gatekeeper HTTP (admin + JWKS) | 9000 | MinIO S3 API |
| 8081 | platform-core Mission REST | 9001 | MinIO console |
| 8082 | data-platform | | |
| 8083 | discover | | |
| 8084 | monitor | | |

## What's NOT in MVP-A

Per doc 00 §4, explicitly out of scope for this slice:

- **Stress-testing engine (doc 06)** — MVP-B (the `STRESS` stream topology is
  pre-provisioned; the module is not).
- **Agentic red-team (doc 08)** beyond doc 01's sandboxed R3 gate-proof stub.
- **The entire Azure/AKS track (doc 12)** — MVP-B, including Key Vault key
  custody and mTLS/SPIFFE.
- **Active discovery techniques** (doc 02 `worker-active`): `subdomain_active`
  and `cloud_public_probe` orders are accepted but dropped with
  `ACTIVE_NOT_ALLOWED`.
- **Phish-Catcher hub loop (doc 07)** — the library/CLI/extension ship
  standalone; hub transport exists behind a feature flag and is inert by
  default.
- Also deferred: `tcp_port` probe and cloud drift (03 Later), ZAP/headless
  validation (04 Later), storm-guard digest mode and ITSM/on-call adapters
  (05 Later), Neo4j/AGE/Timescale/Kafka/Cosmos (Rulings C4/C6), multi-region
  and hard multi-tenancy beyond the single cohort, and any dashboard surface
  beyond the thin slice.

## Contract decisions other modules must know

- **Service names** are lint-conformant (`MissionService`, `PlannerService`,
  `AgentService`); doc 01's sketches say "Mission API / PlannerAPI / AgentAPI".
- **RPC request/response wrappers** follow the `XxxRequest`/`XxxResponse`
  convention (buf STANDARD); doc 01's `SubmitTaskPlan(TaskPlan) → PlanVerdict`
  becomes `SubmitTaskPlan(SubmitTaskPlanRequest) → SubmitTaskPlanResponse`
  carrying `PlanDecision` + per-task `TaskVerdict`s.
- **Token `rate_caps`:** one claim set; `max_rps` (doc 01 spelling) ≡ `rps`
  (doc 11 spelling) — schemas and protos use `max_rps` + `max_concurrent`.
- **Scope-bound watch tokens:** the manifest carries the canonical RoE scope
  document (`schemas/gatekeeper/v1/scope-manifest.schema.json`, JCS/RFC 8785
  serialized); its sha256 IS the `scope:sha256:<hash>` audit value. Valid only
  for `monitor.watch`/`monitor.rescan` at R1 — the JSON Schema rejects any other
  use (see the negative tests in `schemas/examples/`).
- **AlertEvent v1** is JSON-schema only (CloudEvents 1.0 envelope, fixed
  `type: com.aegisbastion.alert.v1`, `source: //aegisbastion/<module>`); producers map
  per doc 03 §5.3 (monitor.alert) and Ruling C8 (detect.alert).
  `authorization_token_id` (Scope Token `jti`) is mandatory for confirmed
  active-scan vuln/exposure alerts and for ddos-engine/ai-redteam sources —
  enforced in the schema. (On the bus the token itself rides the
  `Authorization-Token` NATS header — the schema forbids an in-event field.)
