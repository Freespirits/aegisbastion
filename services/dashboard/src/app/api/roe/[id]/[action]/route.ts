// RoE lifecycle actions → gatekeeper admin-api. activate/suspend/revoke are
// sensitive (doc 10 §7.2): step-up + roe.approve affordance. Revocation is
// immediate and kills in-flight tasks under the RoE (doc 01 §10.5) — the UI
// wraps it in type-to-confirm friction.

import { gatekeeper } from "@/lib/backends";
import { requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

const ACTIONS = new Set(["activate", "suspend", "revoke"]);

export async function POST(req: Request, ctx: { params: Promise<{ id: string; action: string }> }) {
  const { id, action } = await ctx.params;
  if (!ACTIONS.has(action)) return problem(404, "Not Found", `unknown RoE action "${action}"`);
  const g = await requireStepUp("roe.approve");
  if (!g.ok) return g.response;
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  return forward(gatekeeper.roeAction(id, action as "activate" | "suspend" | "revoke", body));
}
