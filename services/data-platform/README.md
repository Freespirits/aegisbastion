# data-platform (dp) — doc 09

System of record for **assets and findings only** (Rulings B/C4). dp holds no
RoE records, scopes, tokens, approvals or authorization audit — those are
gatekeeper's (doc 11). dp exposes **no authorization decision API**; the only
authorization-adjacent behavior is the ingest-time re-verification of
gatekeeper-issued Scope Tokens (defense in depth, doc 09 §2.2 — dp never
grants, it re-verifies gatekeeper's grant).

## Surfaces

One HTTP server (`DP_HTTP_PORT`, compose 8082):

| Route | Purpose |
|---|---|
| `POST /v1/ingest/batch` | Idempotent asset/edge/finding batches (doc 09 §2.2/§3.1). R1+ output (risk_class R1–R3 or detect/ai-redteam/ddos-sim findings) must carry a gatekeeper Scope Token: Ed25519 signature via gatekeeper JWKS, expiry (≤15 min TTL), task binding, target ∈ manifest/scope (doc 01 §10.1 matching, exclusions win). Fail-closed ⇒ RFC 9457 `AUTHORIZATION_UNVERIFIABLE`. |
| `POST /v1/query` | GraphQL Query API (gqlgen, read-only; doc 09 §5): `asset`, `assets`, `assetNeighborhood(depth ≤ 4)`, `finding`, `findings`, `taskRollup`. Cursor pagination, page ≤ 500. |
| `GET /v1/tasks/{id}/rollup` | Ingest-side task attribution rollup (doc 09 §3.1). |
| `POST /v1/findings/{id}/transitions` | Lifecycle transitions (doc 04 §7.3 enum of record, persisted by 09). |
| `POST /v1/inventory/verify` | Verified-inventory existence check for gatekeeper's policy pipeline (doc 11 §3.3 step 4); network-internal, boolean answers only. |
| `POST /v1/admin/tenants`, `GET /v1/admin/tenants`, `POST …/{id}/grants`, `POST …/{id}/workspaces` | Tenancy bootstrap (MVP admin shim, gated by `DP_ADMIN_PRINCIPALS`). |
| `GET /healthz`, `GET /readyz` | Liveness / readiness (postgres, nats, gatekeeper JWKS informational). |

## Tenancy (TPEL, doc 09 §2.3/§9.6)

Every `/v1/*` request (except `/v1/inventory/verify` and health) resolves its
tenant from the caller's credential, never from the payload: `X-DP-Principal`
is looked up in `tenancy.grants`; a principal with several tenant grants must
disambiguate via `X-DP-Tenant`. Every store query carries the resolved
`tenant_id` — cross-tenant access is impossible by construction. Payload
`tenant_id` fields that disagree with the credential are rejected
(`TENANT_MISMATCH`). Real caller authentication (OIDC/mTLS) is the edge PEP's
concern (docs 10/12); these grants govern dp data access only.

## Bus

Consumes (JetStream durables, at-least-once, idempotent via event-id keys):
`detect.findings` (FindingReport → dp.findings), `monitor.assets.new`
(NewAssetCandidate → dp.assets), `hub.discover.asset.changed` (AssetChange →
dp.assets). Publishes CloudEvents 1.0 JSON with the `tenantid` extension:
`dp.asset.created`, `dp.asset.attribute_changed`, `dp.finding.created`,
`dp.finding.state_changed`, `dp.task.rollup_finalized`, `retention.purged`
(stream DP_EVENTS). JetStream down ⇒ spill file + ordered relay (doc 09 §8).

Data-access audit (doc 09 §4.4): `ingest.batch`, `ingest.rejected`,
`query.metadata`, `query.evidence_access`, `retention.purge`, `admin.action`
rows land in `dp.audit_outbox` (same tx as the action) and are forwarded to
`audit.events` for gatekeeper's hash-chained audit of record (envelope-wrapped
`platform.v1.AuditEvent`, idempotent on `event_id`; the dp action travels as
payload `dp_action` because the platform audit enum has no data-access kind).

## Stores (db/migrations/000003)

- `dp.assets` / `dp.asset_edges` — doc 02 §4.1 schema verbatim (Ruling C4),
  temporal merge (`first_seen`/`last_seen`, attr overlay), provenance rows.
- `dp.findings` — monthly RANGE partitions (`EnsureFindingPartitions` keeps
  current+next month; default partition covers gaps), fingerprint dedup
  (doc 04 §7.2), lifecycle enforced per doc 04 §7.3 with
  `dp.finding_state_transitions` history.
- `tenancy.tenants/workspaces/grants/retention_profiles` — dp-local data
  access grants only (platform RBAC is gatekeeper's).
- `dp.ingest_batches` — idempotency ledger (retries are no-ops).

## Retention (doc 09 §10/§11)

Fixed profile per tenant (defaults in migration 000003). `purge-retention`
subcommand (or `DP_RETENTION_TICK` loop): terminal findings older than
`findings_resolved` (default P2Y) are deleted; evidence blobs of terminal
findings outliving `finding+P90D` are removed from MinIO and their refs
cleared; open findings are kept indefinitely; `legal_hold` freezes the
subtree. Every purge is audited (counts + sha256 of purged ids) before
deletion and announced on `retention.purged`.

## Config (env)

`DATABASE_URL` (required), `DB_SEARCH_PATH` (`dp,tenancy`), `NATS_URL`,
`DP_HTTP_PORT` (8082), `GATEKEEPER_JWKS_URL`, `S3_ENDPOINT/S3_ACCESS_KEY/
S3_SECRET_KEY/S3_USE_TLS`, `DP_MANIFEST_BUCKET` (token-manifests),
`DP_ADMIN_PRINCIPALS` (CSV; empty = admin API disabled), `DP_EVENT_SPILL_FILE`,
`DP_EVENT_RELAY_TICK`, `DP_AUDIT_FORWARD_TICK`, `DP_RETENTION_TICK` (0 =
manual), `DP_ENABLE_CONSUMERS`, `DP_MAX_QUERY_PAGE` (500),
`DP_MAX_TRAVERSAL_DEPTH` (4), `DP_INSTANCE_ID`.

## Run

```sh
docker compose --profile infra up -d          # from deploy/
GOWORK=off go run ./cmd/data-platform serve   # needs DATABASE_URL etc.
GOWORK=off go run ./cmd/data-platform purge-retention
```

GraphQL regeneration (after editing `internal/queryapi/schema.graphqls`):

```sh
cd internal/queryapi && GOWORK=off go run github.com/99designs/gqlgen generate
```

## Tests

Unit tests run anywhere; integration tests need the compose Postgres
(`docker compose --profile infra up -d`) and pick it up via
`DP_TEST_DATABASE_URL` or the default local DSN:

```sh
GOWORK=off go test ./...
```
