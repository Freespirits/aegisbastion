# AegisBastion

**Authorized attack-surface management with a hard authorization core.**
AegisBastion lets security operators run offensive-flavored reconnaissance,
monitoring, and vulnerability validation against infrastructure they are
*authorized* to touch — and nothing else. A human-authored, legally anchored
Rules-of-Engagement (RoE) record is the root of all authority; every scan,
probe, and alert traces back to an RoE, an authorization decision, and a
short-lived cryptographic token, and every step lands in a hash-chained,
append-only audit log.

This repo is the MVP-A slice: the full **Discover → Monitor → Detect → Alert**
pipeline on one Docker Compose host, plus the commander adapters that plan
(but never authorize) work.

## The security model in three bullets

- **One decider.** The gatekeeper (`services/gatekeeper`) is the platform's
  only Policy Decision Point. Missions, modules, the dashboard, and the
  commanders are all Policy Enforcement Points that ask the gatekeeper (or
  re-verify its tokens) and never decide anything themselves.
- **One credential.** Active work (risk classes R1–R3) runs only under a
  gatekeeper-minted Scope Token: an Ed25519-signed JWT, task-bound, audience
  `aegisbastion.modules`, hard-capped 15-minute TTL, targets pinned to a
  sha256-hashed manifest. Exclusions always win; unknown capabilities are
  denied.
- **Fail-closed everywhere.** Gatekeeper unreachable ⇒ no dispatch, no ingest,
  no alert delivery. Revocation propagates on `tasks.revocations.v1` /
  `control.kill` and halts target contact within 5 seconds. Every decision,
  denial, touch, and halt is appended to the hash-chained audit of record.

## What's in the box

| Piece | Directory | What it does |
|---|---|---|
| gatekeeper | `services/gatekeeper` | The single PDP: RoE lifecycle, Scope Token minting, policy pipeline, RBAC, four-eyes approvals, revocation/kill switch, hash-chained audit |
| platform-core | `services/platform-core` | Mission API, Orchestrator + Scheduler, dispatch PEP, Agent Registry; validates commander TaskPlans against RoE, commander risk bands, and quotas |
| data-platform | `services/data-platform` | System of record for assets/findings: Ingest API + GraphQL query API + tenant-permission resolution (Postgres) |
| discover | `services/discover` | External attack-surface discovery: passive DNS, Certificate Transparency, credentialed-cloud enumeration |
| monitor | `services/monitor` | 24/7 change detection on scope-bound watch tokens: snapshot diffing, new-asset and exposure detection |
| detect | `services/detect` | Vulnerability scanning (Nuclei/Nmap) with active validation to kill false positives + exploit-verification sandbox |
| alert (herald) | `services/alert` | Sole notification egress: enrich → dedup → correlate → route → deliver (Slack/Teams/Splunk/syslog/webhook), recorded outbox by default |
| dashboard | `services/dashboard` | Operator UI (Next.js): assets, findings, missions, RoE/authorizations, approvals, alert rules |
| commander adapters | `adapters/` | AI planners that propose TaskPlans to the Orchestrator — HexStrike MCP, Strix, PentestGPT, and a bring-your-own CAI seam. Planners, never authorizers: they never see a Scope Token |
| phish-catcher | `modules/phish-catcher` | Standalone zero-egress client-side phishing detection: library, Node CLI, Chrome MV3 extension |

Commanders are bound to risk bands (doc 01 §4.1, enforced fail-closed by
`commanderMaxRisk` in platform-core): CAI, Strix, and PentestGPT may propose
R0–R2 (recon/detect); HexStrike may propose R0–R3. Every plan task is
validated against the capability registry, the RoE's max risk class, allowed
capabilities, and scope/exclusions before it is queued — rejected tasks come
back with per-task reasons for replanning.

## Quick start

```bash
cd deploy
cp .env.example .env                      # append SESSION_SECRET (see OPERATING.md)
docker compose --profile infra up -d      # Postgres 16 + NATS JetStream + MinIO + provisioners
docker compose --profile infra --profile apps up -d --build
curl -fsS http://localhost:8080/healthz   # gatekeeper … and the rest of the health table
```

Then walk the full acceptance flow by hand — RoE → mission → discovery →
monitoring/detection → alert → mid-watch revocation (the ≤5 s halt). **The
full operating guide — quick start, end-to-end walkthrough, configuration
reference, CLI, troubleshooting, and development workflow — lives in
[`OPERATING.md`](OPERATING.md).**

## Project origins

AegisBastion grew out of a set of open-source offensive-security and
AI-planner projects, which now sit behind the platform's authorization core
as commander adapters or standalone modules. **No upstream code is vendored
into this repository** — the adapters are AegisBastion-owned clients that
talk to operator-installed upstream software:

| Upstream project | Role in AegisBastion | Upstream license |
|---|---|---|
| **HexStrike-AI** (0x4m4) | `adapters/hexstrike-mcp` — MCP-native offensive orchestration planner (R0–R3) | MIT |
| **Strix** (usestrix) | `adapters/strix` — agentic AI pentest planner (R0–R2) | Apache-2.0 |
| **PentestGPT** (GreyDGL) | `adapters/pentestgpt` — LLM-guided pentest planner (R0–R2) | MIT |
| **CAI** (Alias Robotics S.L.) | `adapters/cai` — bring-your-own seam only: ships a deterministic stub demo planner, vendors no CAI code; a real backend requires the operator's Alias Robotics commercial license (research-use-only upstream) | Research-use only (BYO commercial license) |

Attribution and obligations are recorded in
[`adapters/THIRD_PARTY_LICENSES.md`](adapters/THIRD_PARTY_LICENSES.md). The
platform contract set (`proto/`, `schemas/`) is the single source of truth;
terse "doc NN §x.y" citations in code comments refer to the project's
internal design documents, which are not distributed with this repository.

## Development

Every Go service is its own module built with `GOWORK=off` (no go.work);
TypeScript packages use npm workspaces / vitest. The full Go test suite:

```bash
for m in adapters services/platform-core services/gatekeeper services/data-platform \
         services/detect services/monitor services/discover gen/go sdks/go \
         deploy/jetstream-bootstrap; do
  (cd "$m" && GOWORK=off go test ./...)
done
```

Contracts (proto + JSON Schema) are the single source of truth — regenerate
with `make proto-gen` (vendored `bin/buf.exe`); see `OPERATING.md` for the
full workflow, repo layout, and how to add a module against the agent SDKs
(`sdks/go`, `sdks/ts`).

## License

AegisBastion itself is released under the **MIT License** — see
[`LICENSE`](LICENSE). Upstream projects referenced by the adapters remain
under their own licenses as listed in Project origins and
`adapters/THIRD_PARTY_LICENSES.md`; note in particular that CAI's upstream is
research-use only and any real CAI backend is the operator's licensing
responsibility.
