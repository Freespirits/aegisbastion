# dashboard — AegisBastion operator UI (doc 10)

The single human-facing surface of the Connector Hub, MVP-A thin slice
(doc 00 §4): **OIDC + RBAC + step-up**, attack-surface map and findings
workflows via the data platform (09), gated task launch via the platform-core
Mission API (01), RoE management via the gatekeeper admin-api (11), the
four-eyes plan-approval queue, mission pause/resume/kill, and the alert-rules
UI as a client of herald (05).

This module owns **no domain data** (Rulings B/C4/C7): authorization
decisions, RoE records, RBAC state and the audit of record are gatekeeper's;
assets/findings are the data platform's; task lifecycle is platform-core's;
notification egress is herald's. The dashboard renders the gate — it never
decides.

## Architecture

Next.js (App Router, TypeScript strict). The SPA talks **only** to this app's
own `/api/*` BFF routes; those server-side routes proxy to the owning backend
services with the session-derived identity, so no backend URL or token ever
reaches the browser beyond the sealed httpOnly session cookie (doc 10 §2.1).

```
browser ──► /api/* (BFF, this app) ──► gatekeeper :8080   admin REST (GATEKEEPER_URL)
                                  ──► platform-core :8081 Mission REST (PLATFORM_CORE_URL)
                                  ──► data-platform :8082 GraphQL /v1/query + transitions (DATA_PLATFORM_URL)
                                  ──► herald :8086        control API (HERALD_URL)
```

### Surfaces consumed (verified against the running services)

| Backend | Endpoints | Notes |
|---|---|---|
| gatekeeper admin REST | `GET/POST /v1/roe`, `POST /v1/roe/{id}/activate|suspend|revoke`, `GET /v1/approvals`, `POST /v1/approvals/{id}/decide`, `GET /v1/rbac/grants` | protojson snake_case; RoE CRUD per Ruling B (no local RoE tables) |
| platform-core Mission REST | `POST /v1/missions`, `GET /v1/missions/{id}`, `POST /v1/missions/{id}/pause|resume|kill`, `GET /v1/missions/{id}/audit` | identity via `X-Operator-Id` = session principal |
| data-platform | `POST /v1/query` (GraphQL), `POST /v1/findings/{id}/transitions` | TPEL headers `X-DP-Principal` (+`X-DP-Tenant` when `DASHBOARD_TENANT_ID` set) |
| herald control API | `GET/POST /v1/policies/routing`, `POST /v1/routes/test`, `GET /v1/deliveries` | **client only** (Ruling C7) — this module never dispatches a notification |

Authn: OIDC authorization-code flow (`OIDC_*` env; discovery + issuer-JWKS
id_token verification via `jose`) or the **dev static-token shim** behind
`DEV_AUTH_ENABLED` (never for prod). RBAC: gatekeeper's eight roles
(doc 11 §3.5) are resolved from `rbac-service` grants at login and mapped to
workspace affordances in `src/lib/roles.ts` — the UI stores no role data.
Step-up (doc 10 §7.2): **placeholder WebAuthn ceremony** — the modal and the
real ≤5-minute server-side window gate RoE create/activate/suspend/revoke,
approval decisions, mission launch, resume and kill (pause is deliberately
ungated: a halt must stay fast).

Preflight scope check (doc 10 §7.1 step 1): `/api/preflight` fetches the RoE
from gatekeeper and evaluates targets locally with the platform's canonical
matching (exact-host/longest-prefix, CIDR containment, **exclusions always
win**) — **non-authoritative UX only**; the dispatch PEP's call to gatekeeper
`policy-service.Authorize` is the decision, and its denial reason codes are
surfaced verbatim.

## Pages

- `/` — overview: backend status pills, session/affordances
- `/assets` — attack-surface map: tenant-scoped asset list + Cytoscape
  neighborhood graph (doc 09 `assetNeighborhood`, depth ≤ 4)
- `/findings` — triage queue, lifecycle history, doc 04 §7.3 transitions
  (RBAC-gated), sensitive findings render digests only (doc 10 §7.3)
- `/missions` — gated launch (preflight + type-to-confirm + step-up),
  pause/resume/kill, mission audit trail
- `/authorizations` — RoE list/create/activate/suspend/revoke
- `/approvals` — four-eyes approval queue (SoD: approver ≠ requester/author)
- `/alert-rules` — herald routing-policy CRUD, route dry-run, delivery log

## Configuration

All env (see `.env.example`): `GATEKEEPER_URL`, `PLATFORM_CORE_URL`,
`DATA_PLATFORM_URL`, `HERALD_URL`, `SESSION_SECRET` (required outside dev),
`DASHBOARD_ORG_ID`, optional `DASHBOARD_TENANT_ID`, `OIDC_*`, and the dev shim
flags `DEV_AUTH_ENABLED` / `DEV_AUTH_TOKEN` / `DEV_AUTH_FALLBACK_ROLES`.

## Build, test, run

```bash
cd services/dashboard
npm install
npm run typecheck    # tsc --noEmit (strict)
npm test             # vitest: login guard, RBAC buttons, findings list, scope preflight
npm run build        # next build (standalone output)
npm run dev          # dev server on :3000

# against the platform (from repo root):
docker compose -f deploy/docker-compose.yml --profile infra up -d
# + gatekeeper :8080, platform-core :8081, data-platform :8082 (see their READMEs)
cp .env.example .env.local   # then npm run dev

# container:
docker build -t aegisbastion/dashboard .
docker run -p 3000:3000 --env-file .env aegisbastion/dashboard
```

## Deviations (deliberate, MVP-A scoped)

1. **Preflight is a local evaluator, not a gRPC dry-run.** gatekeeper
   `policy-service.Authorize(dry_run=true)` is exposed on gRPC only; the
   admin REST façade has no dry-run endpoint. doc 10 §7.1 step 1 makes the
   BFF preflight UX-only and never authoritative, so the dashboard implements
   the same scope semantics locally (`src/lib/preflight.ts`) and labels them
   as such. Wiring a connect/gRPC client to the real dry-run is the follow-up.
2. **"Task launch" = mission creation.** The platform-core REST surface
   exposes the Mission API (create/get/pause/resume/kill/audit); per-task
   submission is planner/commander territory (gRPC). The launch flow creates
   a mission bound to an RoE; the dispatch PEP gates every resulting task.
3. **No mission list endpoint** exists on the Mission REST API, so the
   console keeps a UI-local recent-ids list (doc 10 §4.1 UI-local state).
4. **WebAuthn ceremony is a placeholder** per the assignment: the server-side
   ≤5-min step-up window and the mandatory checks on sensitive routes are
   real; the browser ceremony is an acknowledgement modal. Real attestation
   verification + downstream `acr` enforcement land with the production IdP.
5. **Plain CSS instead of Tailwind+shadcn** to keep the MVP-A build minimal
   and hermetic; the component kit swap is cosmetic and later.
6. **No SSE realtime fan-out** (doc 10 §2.1 RealtimeSvc is a separate
   service in the doc's full architecture; MVP-A thin slice polls on page
   load/actions). The realtime subscriber is a follow-up against JetStream.
7. **Audit viewer** is limited to the per-mission hash-chained trail (the
   only audit read surface exposed over REST); gatekeeper's cross-platform
   audit query is gRPC-only at MVP-A.
