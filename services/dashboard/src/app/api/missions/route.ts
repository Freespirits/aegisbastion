// Gated task launch → platform-core Mission API (doc 10 §2.2 Flow B). At
// MVP-A the exposed Mission API surface is mission creation bound to an RoE;
// the Orchestrator's dispatch PEP gates every resulting task through
// gatekeeper policy-service (Ruling B.2 PEP-1) — this module decides nothing.
// Launch is a sensitive action: step-up + tasks.launch affordance.

import { platformCore } from "@/lib/backends";
import { requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function POST(req: Request) {
  const g = await requireStepUp("tasks.launch");
  if (!g.ok) return g.response;
  const body = await readJson<Record<string, unknown>>(req);
  if (!body || typeof body.name !== "string" || body.name.trim() === "") {
    return problem(400, "Bad Request", "name is required");
  }
  if (typeof body.roe_id !== "string" || body.roe_id.trim() === "") {
    return problem(400, "Bad Request", "roe_id is required — every mission is bound to an RoE (doc 01 §5.1)");
  }
  if (typeof body.objective !== "string" || body.objective.trim() === "") {
    return problem(400, "Bad Request", "objective is required");
  }
  // created_by is stamped server-side from the session (the Mission API also
  // falls back to the X-Operator-Id header, which the proxy sets).
  const payload = { ...body, created_by: g.session.sub };
  return forward(platformCore.createMission(g.session, payload));
}
