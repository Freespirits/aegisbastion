# strix — Strix commander adapter

Fronts an operator-installed [Strix](https://github.com/usestrix/strix)
backend as an AegisBastion platform commander (doc 01 §4.1,
§7.1). Strix is an agentic AI pentest CLI: autonomous agents hunt
vulnerabilities against a target and **validate every finding with a working
proof-of-exploit** — exactly the commander value the platform lost when CAI
became bring-your-own-license.

The adapter is a **planner, not an authorizer**: it submits `TaskPlan`s to
the Orchestrator's `aegisbastion.platform.v1.PlannerService` (gRPC,
`PLANNER_ADDR`) and translates only Orchestrator-**accepted** tasks into
Strix scans. The dispatch PEP/gatekeeper owns authorization; the adapter
never sees, mints, or verifies Scope Tokens (Ruling B).

Native surface: **MCP server over stdio** (newline-delimited JSON-RPC 2.0),
reusing the `adapters/hexstrike-mcp/mcp` protocol package. stdout is MCP
protocol; logs go to stderr.

## MCP tools

The doc 01 §7.1 set, plus the execution bridge:

- `submit_task_plan` — build a `TaskPlan` and call
  `PlannerService.SubmitTaskPlan`; returns the `PlanVerdict`
  (ACCEPTED/PARTIAL/REJECTED + per-task verdicts). Verdicts are recorded in
  an in-memory ledger.
- `get_mission_status` — `PlannerService.GetMissionStatus` proxy.
- `list_capabilities` — `PlannerService.ListCapabilities` proxy.
- `request_scope_change` — `PlannerService.RequestScopeChange` proxy
  (operator queue; never auto-granted).
- `execute_approved_task` — translate one Orchestrator-**accepted** task
  (by `plan_id` + `task_key`) into Strix scans (one non-interactive
  `strix` run per target) and map the findings back to a `TaskResult`
  (doc 01 §5.7). Refuses anything the verdict did not accept — that refusal
  is the planner-not-authorizer gate.

## Modes

| Mode | `STRIX_MODE` | What happens |
|------|--------------|--------------|
| mock | default | Deterministic canned findings, clearly marked (`"mock": true`, id `MOCK-001`). No Strix install, no target contact. Identical input → identical output. |
| live | `live` | Shells out to the `strix` CLI: `strix --target <t> --non-interactive --scan-mode <quick\|standard\|deep> --instruction <text>`, one run per target, then parses `strix_runs/<run>/vulnerabilities.json`. Strix exit codes: 0 = clean run, 2 = findings, other = failure. |

Live mode needs Strix installed and configured (`STRIX_LLM`, `LLM_API_KEY`,
Docker running — Strix sandboxes its agents in containers); those are
inherited from the adapter process environment.

## Capability → Strix mapping

Static and explicit (app/translate.go); anything unmapped is **refused, not
improvised**. TaskSpec params may only override `instruction` and
`scan_mode` — unknown params never leak into an invocation.

| Capability | Risk | Strix invocation | Findings |
|------------|------|------------------|----------|
| `recon.port_scan` | R1 | `--scan-mode quick`, recon-only instruction (no exploitation) | informational |
| `recon.web_surface` | R1 | `--scan-mode quick`, web attack-surface enumeration | informational |
| `detect.scan.web` | R2 | `--scan-mode standard`, OWASP-class web hunt | PoC-validated |
| `detect.scan.api` | R2 | `--scan-mode standard`, API authn/authz/injection/data-exposure | PoC-validated |
| `detect.scan.full` | R2 | `--scan-mode deep`, full-surface pentest | PoC-validated |

Results map back to `TaskResult`: `SUCCEEDED` only if every per-target scan
completed; findings land in the summary per target with `severity_counts`;
`metrics.targets_touched` is the honest list of scanned targets.

## Env

| Var | Default | Meaning |
|-----|---------|---------|
| `PLANNER_ADDR` | `127.0.0.1:50052` | platform-core PlannerService gRPC |
| `STRIX_MODE` | `mock` | `mock` \| `live` |
| `STRIX_BIN` | `strix` | strix CLI executable (live mode; must resolve on PATH) |
| `STRIX_WORK_DIR` | `strix_work` | parent dir for per-scan working dirs (live mode) |
| `HEALTH_ADDR` | `:8087` | serves `/healthz` and `/readyz` |

## Build & test

```bash
cd adapters
GOWORK=off go build ./strix/...
GOWORK=off go vet ./strix/...
GOWORK=off go test ./strix/...

# container image (build context = repo root):
docker build -f adapters/strix/Dockerfile -t aegisbastion/strix .
```

## License

Strix is **Apache-2.0** (usestrix/strix) — cleared for commercial use by the
license audit, unlike CAI (research-use only, now bring-your-own-license).
Attribution is recorded in `adapters/THIRD_PARTY_LICENSES.md`.

## Commander identity

`platform/v1/types.proto` defines `COMMANDER_STRIX = 3`, mapped by
platform-core's `commanderName` / `commanderMaxRisk` to the "strix" commander
with an R0–R2 proposal band (doc 01 §4.1). The adapter submits under that
identity (`app.CommanderID`), so the real Orchestrator accepts Strix plans
and attributes them to Strix in audit and mission-ownership checks.
