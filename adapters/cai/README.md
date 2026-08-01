# cai — CAI commander adapter (bring-your-own-license)

> ## ⚠ Licensing — read before production use
>
> **CAI (Alias Robotics S.L.) is licensed RESEARCH-USE ONLY.** Commercial or
> production use of this adapter against a real CAI backend **requires the
> operator to hold a valid Alias Robotics commercial license**.
>
> **AegisBastion vendors NO CAI code.** This directory contains only
> AegisBastion-owned code: a deterministic demo planner plus the
> REST/PlannerService plumbing around it. A real CAI integration is
> **bring-your-own (BYO)**: the customer installs and licenses CAI themselves
> and plugs it in behind the `app.Planner` interface (see *Integration seam*
> below).

The adapter is a commander (doc 01 §4.1, §7.1): a **planner, never an
authorizer**. It submits `TaskPlan`s to the platform-core
`PlannerService` (gRPC, doc 01 §7.2); only the dispatch PEP + gatekeeper
authorize. It never sees, mints, or verifies Scope Tokens.

## Default: `CAI_MODE=stub` (demo planner)

The only built-in planner mode. Accepts mission intents over REST and answers
with a fixed, clearly-marked **stub plan** — a deterministic Discover passive
order (doc 02's passive techniques, all R0, no target contact):
`recon.passive_dns` → `recon.ct` / `recon.subdomain_passive` /
`recon.ip_netblock` → `recon.cloud_credentialed`. Plan id and idempotency key
are derived from a hash of the intent, so the same intent always yields the
same plan. Every task carries `params.stub=true, generator="cai-stub-v1"`
plus a `plan_note`, so a stub plan can never be mistaken for real CAI output
in audit records or the dashboard.

The stub is pure AegisBastion code and exercises the full end-to-end flow
(mission → plan → verdict → replan) with no CAI installation.

## Integration seam (BYO)

The seam is the **`app.Planner` interface** (`app/planner.go`):

```go
type Planner interface {
	PlanMission(in Intent) (*platformv1.TaskPlan, error)
}
```

A customer holding a valid Alias Robotics commercial license integrates their
CAI deployment by adding another `Planner` implementation that calls their
licensed CAI backend and maps its output to a `TaskPlan`, then selecting it
in `app.NewPlanner`. The REST surface and the PlannerService submission path
stay unchanged. That integration code is the customer's, licensed by them —
it is never vendored into this repository.

## REST surface (doc 01 §7.1 + the stub entry point)

- `POST /v1/intents` — `{mission_id, objective, targets[]}` → plan +
  submission verdict (`502` with the plan attached if the Orchestrator is
  unreachable).
- `POST /v1/plans` — the surface a real CAI backend calls with its own
  already-formed plans; works today in stub mode (`submitted_by=cai`).
- `GET /v1/missions/{id}`, `GET /v1/capabilities?name_prefix=&max_risk_class=`
  — PlannerService read proxies.
- `GET /healthz`, `GET /readyz`.

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `PLANNER_ADDR` | `127.0.0.1:50052` | platform-core PlannerService gRPC host:port |
| `CAI_MODE` | `stub` | Planner mode. Only `stub` exists; anything else fails fast. |
| `CAI_LISTEN_ADDR` | `:8082` | REST listen address |

## Build & run

```bash
# from adapters/ (GOWORK=off — repo-root go.work interferes)
GOWORK=off go build ./cai/...
GOWORK=off go vet ./cai/...
GOWORK=off go test ./cai/...

# run against a local platform-core
PLANNER_ADDR=localhost:50052 GOWORK=off go run ./cai/cmd/cai
curl -fsS -X POST http://localhost:8082/v1/intents \
  -H 'content-type: application/json' \
  -d '{"mission_id":"msn_…","objective":"map example.com","targets":["example.com"]}'

# container image (build context = repo root; regenerate gen/ first)
docker build -f adapters/cai/Dockerfile -t aegisbastion/cai .
```

See `adapters/THIRD_PARTY_LICENSES.md` for the full third-party attribution
and obligation table.
