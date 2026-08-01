# gatekeeper — AegisBastion's single PDP (doc 11)

One deployable Go binary implementing the full gatekeeper MVP (doc 11 §9,
doc 00 §3 Phase 0): **roe-service**, **token-service** (+JWKS),
**policy-service** (the platform's single Policy Decision Point),
**rbac-service**, **approval-service** (+ approver CLI), **revocation-service**
(kill switch) and **audit-service** (hash-chained, append-only).

It is the only component that *decides*; everything else on the platform is a
PEP that enforces its decisions or re-verifies its Scope Tokens (Ruling B).

## Layout

```
cmd/gatekeeper/        binary: `serve` (default) + approver/kill-switch CLI
internal/config/       env configuration (compose-compatible)
internal/keys/         MVP-A Ed25519 file-key custody (sealed file key, doc 00 §5 Q1)
internal/store/        pgx pool, DB_SEARCH_PATH=gatekeeper (schema-per-context)
internal/bus/          NATS JetStream publisher (platform Envelope, doc 01 §8.2)
internal/roe/          ROEService: CRUD, immutable versions, ≤90-day window,
                       legal-artifact anchoring, effective-scope resolution
internal/token/        TokenService: EdDSA Scope Tokens (Authorization Token v1.1),
                       MinIO manifests (bucket token-manifests), Mint/Exchange(C9)/
                       Refresh-as-reauthorization/Revoke/GetJWKS
internal/policy/       PolicyService: hard-coded pipeline steps 1–11 (doc 11 §3.3),
                       fail-closed everywhere, DecisionEvents on
                       authz.decisions.v1 / authz.denials.v1
internal/rbac/         8 seeded roles, time-boxed grants, SoD enforcement
internal/approval/     four-eyes approvals (distinct approvers, SoD, 72 h expiry)
internal/revocation/   global/RoE/target/capability (+token) revocations,
                       tasks.revocations.v1 broadcast
internal/audit/        audit-service: hash chain (sha256(prev_hash ||
                       JCS(event))), VerifyChain, audit.events bus ingest
internal/admin/        HTTP: /.well-known/gatekeeper-jwks.json, /healthz,
                       /readyz, admin REST façade (/v1/roe, /v1/approvals,
                       /v1/revocations, /v1/rbac/grants, /v1/audit/verify)
internal/scopecanon/   doc 01 §10.1 canonicalized matching; exclusions always win
internal/capreg/       capability → risk-class registry (R0–R3, Ruling B.4)
internal/blackout/     RRULE subset (FREQ=DAILY/WEEKLY, BYHOUR, BYDAY), fail-closed
internal/ratelimit/    decision-time token buckets (step 10)
internal/inventory/    R2/R3 verified-inventory client (module 09, cached 5 min)
internal/e2e/          integration tests against the compose infra profile
```

## Contracts consumed/produced

- **gRPC** `aegisbastion.gatekeeper.v1` on `:50051` — `PolicyService.Authorize`,
  `TokenService` (MintToken/ExchangeToken/RefreshToken/RevokeToken/GetJWKS),
  `ROEService`, `ApprovalService`, `RevocationService`, `AuditService`.
- **HTTP** `:8080` — JWKS (`/.well-known/gatekeeper-jwks.json`), health,
  admin REST (same services, protojson bodies).
- **Bus** (JetStream, proto `platform.v1.Envelope`): publishes
  `authz.decisions.v1`, `authz.denials.v1`, `roe.events.v1`,
  `tasks.revocations.v1`, `authz.approvals.v1`; consumes `audit.events`.
  `control.kill` is intentionally not used here (core NATS broadcast owned by
  the Orchestrator, Ruling C11).
- **Object storage**: token manifests in MinIO bucket `token-manifests`
  (`blob://tokens/<jti>/{targets,scope}.json`), JCS-canonical, sha256-pinned.

## Configuration (env)

| Var | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | required |
| `DB_SEARCH_PATH` | `gatekeeper` | schema-per-context |
| `NATS_URL` | — | required |
| `S3_ENDPOINT` / `S3_ACCESS_KEY` / `S3_SECRET_KEY` / `S3_USE_TLS` | — | MinIO |
| `GATEKEEPER_SIGNING_KEY_FILE` | `gatekeeper_ed25519.key` | created on first boot if absent |
| `GATEKEEPER_SIGNING_KEY_PASSPHRASE` | — | seals the key file at rest (scrypt + AES-GCM) |
| `TOKEN_ISSUER` / `TOKEN_AUDIENCE` | `gatekeeper.platform` / `aegisbastion.modules` | |
| `TOKEN_TTL` | `15m` | hard-capped at 15 min (Ruling C5); larger values are refused |
| `MANIFEST_BUCKET` / `MANIFEST_URI_PREFIX` | `token-manifests` / `blob://` | |
| `GATEKEEPER_GRPC_LISTEN` / `GATEKEEPER_HTTP_LISTEN` | `:50051` / `:8080` | |
| `DP_INVENTORY_URL` | — | unset = Phase-0 skip of the R2/R3 inventory check (see deviations) |
| `CAPABILITY_REGISTRY_FILE` | — | JSON overrides for capability → risk class |

## CLI

```
gatekeeper approvals list [--state pending] [--addr host:port]
gatekeeper approvals show --id appr_…
gatekeeper approvals approve --id appr_… --approver user_… [--note …]
gatekeeper approvals reject  --id appr_… --approver user_… [--note …]
gatekeeper revoke --scope global|roe|target|capability [--key …] --by user_… [--reason …]
```

## Build, test, run

```bash
# unit + integration tests (integration skips when infra is absent)
docker compose -f deploy/docker-compose.yml --profile infra up -d
cd services/gatekeeper
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./...

# Docker image (compose builds with context services/gatekeeper; the module
# replaces gen/go OUTSIDE the context, so the image builds from vendor/ —
# refresh after proto regeneration or dependency changes:)
GOWORK=off go mod tidy && GOWORK=off go mod vendor
docker compose -f deploy/docker-compose.yml --profile infra --profile apps up -d --build gatekeeper
```

## Deviations from the docs (all deliberate, MVP-A scoped)

1. **No Redis** (doc 11 §5). The MVP-A Compose host (doc 00 §4) has no Redis;
   the revocation set lives in Postgres (`gatekeeper.revocations`, consulted
   directly by the pipeline), and rate buckets are in-process (single binary).
   Redis lands with horizontal scaling (MVP-B).
2. **R2/R3 verified-inventory check (pipeline step 4)** is skipped while
   module 09 does not exist; wire `DP_INVENTORY_URL` to enable it (fail-closed
   HTTP client, 5-min cache, ready today).
3. **Revocation `expires_at`** has no column in migration 000002 (db/ is owned
   by the migrations task). Expiry is honored in-process; after a restart an
   expired revocation becomes permanent-until-lifted — the fail-*safe*
   direction for a kill switch.
4. **Caller identity (pipeline step 1)** is validated structurally +
   RBAC-bound (mTLS/SPIFFE arrives with MVP-B per doc 11 §5); gRPC is
   plaintext on the private compose network. Requests carrying a
   `task.commander` must present that commander's service identity.
5. **Capability → risk-class mapping** comes from a built-in registry seeded
   from doc 01 §5.3 + Ruling A (`internal/capreg`), file-overridable. Unknown
   capabilities are denied (fail-closed).
6. **Asset-group resolution** in `roe_effective_targets` stores the group
   reference; expansion against module 09's inventory lands with
   data-platform.
7. **RRULE support** is the subset the docs use (`FREQ=DAILY|WEEKLY`,
   `BYHOUR` ranges/lists/wrap-around, `BYDAY`). Unsupported rules fail closed
   (treated as active blackout).
8. **`audit.anomalies.v1`** is not published (anomaly detection is doc 11
   Later item 4, not MVP §9).
9. **kid rotation**: one active key at MVP-A (two-max, 30-day rotation +
   JWKS denylist are MVP-B with KMS custody).
10. **Container key persistence**: compose points
    `GATEKEEPER_SIGNING_KEY_FILE` at `/run/secrets/gatekeeper_ed25519.key`;
    without a mounted secret the binary generates a fresh key on first boot
    (tokens from previous containers become unverifiable). Mount a volume or
    Docker secret at that path for stable keys; set
    `GATEKEEPER_SIGNING_KEY_PASSPHRASE` to seal it.
