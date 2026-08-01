# adapters/ — Commander Adapters

The platform commanders (doc 01 §4.1) are external brains; these adapters
normalize them into the platform contract. All are **planners, not
authorizers**: they submit `TaskPlan`s to the Orchestrator's
`aegisbastion.platform.v1.PlannerService` (proto `platform/v1/planner.proto`,
doc 01 §7.2) and nothing else decides anything. The dispatch PEP/gatekeeper
owns authorization; the adapters never see, mint, or verify Scope Tokens
(Ruling B).

One Go module (`adapters/go.mod`), one binary per adapter:

| Adapter | Binary | Native surface | Mode | Upstream license |
|---------|--------|----------------|------|------------------|
| `hexstrike-mcp/` | `hexstrike-mcp` | MCP server (stdio, JSON-RPC 2.0) | `mock` (default) / `http` — live | MIT (0x4m4/hexstrike-ai) |
| `strix/` | `strix` | REST/JSON | live | Apache-2.0 |
| `pentestgpt/` | `pentestgpt` | REST/JSON | live | MIT (Grey_D/PentestGPT) |
| `cai/` | `cai` | REST/JSON | `stub` (default demo planner) / **BYO** | **Research-use only** (Alias Robotics — commercial license required) |

Third-party attribution and obligations for every upstream: see
[`THIRD_PARTY_LICENSES.md`](./THIRD_PARTY_LICENSES.md).

## hexstrike-mcp — HexStrike commander adapter

Fronts an operator-installed HexStrike AI backend (0x4m4/hexstrike-ai,
MCP-native per `hexstrike-ai-mcp.json`) as a platform commander.

**MCP tools** (doc 01 §7.1 set, plus the execution bridge):

- `submit_task_plan` — build a `TaskPlan` (`submitted_by=hexstrike`) and call
  `PlannerService.SubmitTaskPlan`; returns the `PlanVerdict`
  (ACCEPTED/PARTIAL/REJECTED + per-task verdicts). Verdicts are recorded in an
  in-memory ledger.
- `get_mission_status` — `PlannerService.GetMissionStatus` proxy.
- `list_capabilities` — `PlannerService.ListCapabilities` proxy.
- `request_scope_change` — `PlannerService.RequestScopeChange` proxy (operator
  queue; never auto-granted).
- `execute_approved_task` — translate one Orchestrator-**accepted** task
  (by `plan_id` + `task_key`) into HexStrike tool calls
  (`POST {server}/api/tools/<tool>`) and map the results back to a
  `TaskResult` (doc 01 §5.7). Refuses anything the verdict did not accept —
  that refusal is the planner-not-authorizer gate.

**Capability → tool mapping** (static, explicit; anything unmapped is
refused): `recon.port_scan`/`detect.scan.network` → `api/tools/nmap`,
`detect.scan.web` → `api/tools/nuclei`, `web.dirbust` → `api/tools/gobuster`,
`web.nikto` → `api/tools/nikto`, `web.sqlmap` → `api/tools/sqlmap`.

**Env:** `PLANNER_ADDR` (default `127.0.0.1:50052` — platform-core PlannerService), `HEXSTRIKE_MODE`
(`mock` default — deterministic canned results, no HexStrike install needed;
`http` fronts the real server), `HEXSTRIKE_SERVER_URL` (default
`http://127.0.0.1:8888`), `HEALTH_ADDR` (default `:8081`, serves `/healthz`
and `/readyz`). stdout is MCP protocol; logs go to stderr.

## strix — Strix commander adapter

Fronts the Strix backend (usestrix/strix, Apache-2.0, operator-installed,
not vendored) as a platform commander. See `adapters/strix/README.md` for
modes, capability mapping, and configuration.

## pentestgpt — PentestGPT commander adapter

Fronts PentestGPT (GreyDGL/PentestGPT, MIT by Grey_D, operator-installed,
not vendored) as a platform commander. See `adapters/pentestgpt/README.md` for
modes, capability mapping, and configuration.

## cai — CAI commander adapter (bring-your-own-license)

> **Licensing:** CAI (Alias Robotics S.L.) is
> **research-use only** — commercial/production use against a real CAI
> backend requires the operator to hold a valid **Alias Robotics commercial
> license**. **AegisBastion vendors no CAI code**; a real integration is
> bring-your-own (BYO). See [`cai/README.md`](./cai/README.md) and
> [`THIRD_PARTY_LICENSES.md`](./THIRD_PARTY_LICENSES.md).

The default (and only built-in) planner is `CAI_MODE=stub`: a deterministic
demo planner, pure AegisBastion code, that accepts mission intents and
answers with a fixed, clearly-marked **stub plan** — a Discover passive order
(doc 02's passive techniques, all R0): `recon.passive_dns` → `recon.ct` /
`recon.subdomain_passive` / `recon.ip_netblock` →
`recon.cloud_credentialed`. Plan id and idempotency key are derived from a
hash of the intent, so the same intent always yields the same plan. Every
task carries `params.stub=true, generator="cai-stub-v1"` plus a `plan_note`.

**BYO seam:** the `app.Planner` interface
(`PlanMission(Intent) (*platformv1.TaskPlan, error)`). A customer with a
valid Alias Robotics commercial license plugs their CAI integration in as
another Planner implementation, selected in `app.NewPlanner`; the REST
surface and submission path stay unchanged.

**REST** (doc 01 §7.1 surface + the stub entry point):

- `POST /v1/intents` — `{mission_id, objective, targets[]}` → stub plan +
  submission verdict (`502` with the plan attached if the Orchestrator is
  unreachable).
- `POST /v1/plans` — the surface a real, licensed CAI backend calls with its
  own plans; works today in stub mode (`submitted_by=cai`).
- `GET /v1/missions/{id}`, `GET /v1/capabilities?name_prefix=&max_risk_class=`
  — PlannerService read proxies.
- `GET /healthz`, `GET /readyz`.

**Env:** `PLANNER_ADDR` (default `127.0.0.1:50052` — platform-core PlannerService), `CAI_MODE` (`stub` only —
anything else fails fast), `CAI_LISTEN_ADDR` (default `:8082`).

## Shared internals

- `internal/plannerclient` — the gRPC client side of `PlannerService` (plus
  the `/readyz` probe). MVP-A transport is plaintext gRPC inside the Compose
  network; mTLS adapter auth (doc 01 §7.1) lands with the platform-CA work.
- `internal/taskspec` — shared commander-JSON → `TaskPlan` translation
  (schema-level validation only; policy stays downstream).
- `internal/plannerfake` — in-memory `PlannerService` server for tests,
  coded strictly to the generated stubs.
- `internal/health`, `internal/ids`, `internal/config`.

## Build & test

```bash
# from repo root, regenerate contracts first (gen/ is gitignored):
bin/buf.exe generate proto --template proto/buf.gen.yaml

cd adapters
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./...

# container images (build context = repo root):
docker build -f adapters/hexstrike-mcp/Dockerfile -t aegisbastion/hexstrike-mcp .
docker build -f adapters/cai/Dockerfile -t aegisbastion/cai .
```

`adapters/integration/` runs the adapters over their real wire protocols
(MCP stdio, REST) against an in-memory `PlannerService` over bufconn gRPC —
the closest stand-in for the Orchestrator until `services/` ships; the
adapters see no difference because they code strictly to the generated
client stubs.
