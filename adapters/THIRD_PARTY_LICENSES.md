# Third-party licenses & attribution — commander adapters

This file records the upstream projects each commander adapter fronts, their
licenses, where the upstream code lives, and the obligations that follow.
**No upstream code is vendored into this repository** — the adapters are
AegisBastion-owned clients that talk to operator-installed upstream software.

| Upstream | Adapter | License | Upstream lives at | Vendored? | Obligations |
|----------|---------|---------|-------------------|-----------|-------------|
| **hexstrike-ai** (0x4m4) | `adapters/hexstrike-mcp` | MIT | Operator-installed upstream (0x4m4/hexstrike-ai), not vendored | No | Preserve the MIT copyright + permission notice in any distribution that includes upstream code. |
| **strix** | `adapters/strix` | Apache-2.0 | Operator-installed upstream (usestrix/strix), not vendored | No | Preserve the Apache-2.0 license + copyright notices; retain any `NOTICE` file contents; mark modified files if upstream code is ever redistributed. |
| **PentestGPT** (Grey_D) | `adapters/pentestgpt` | MIT | Operator-installed upstream (GreyDGL/PentestGPT), not vendored | No | Preserve the MIT copyright + permission notice in any distribution that includes upstream code. |
| **cai** (Alias Robotics S.L.) | `adapters/cai` | **Research-use only** (Alias Robotics license) | Customer-installed upstream (AliasRobotics/cai), not vendored | **No — BYO** | **Commercial/production use requires a valid Alias Robotics commercial license held by the operator.** AegisBastion ships only a built-in deterministic stub planner (`CAI_MODE=stub`, no CAI code); the real CAI integration is bring-your-own and plugs in behind the `app.Planner` seam. |

## Notes

- **MIT / Apache-2.0 adapters** (hexstrike-mcp, strix, pentestgpt): the
  adapter code itself is AegisBastion-owned and does not embed upstream
  source, so no upstream notices are reproduced here. If any upstream code
  is ever copied in, the corresponding license text and notices must be
  added to this file and to the distribution.
- **CAI adapter**: research-use-only upstream. The stub mode is a pure
  AegisBastion demo planner and carries no CAI licensing obligations. Any
  deployment wired to a real CAI backend is the operator's responsibility —
  they must hold the Alias Robotics commercial license. See
  `adapters/cai/README.md` and the `app.Planner` seam comments in
  `adapters/cai/app/planner.go`.
- Upstream software is installed by the operator per its own license terms;
  this repository contains no upstream source.
