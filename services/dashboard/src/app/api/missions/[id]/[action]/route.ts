// Mission pause/resume/kill → platform-core Mission API (doc 01 §7.3, §10.5).
// Pause is NOT step-up gated (a halt control must stay fast); resume and kill
// are sensitive (doc 10 §7.2: commander resume; kill is terminal).

import { platformCore } from "@/lib/backends";
import { requireCapability, requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

const ACTIONS = new Set(["pause", "resume", "kill"]);

export async function POST(req: Request, ctx: { params: Promise<{ id: string; action: string }> }) {
  const { id, action } = await ctx.params;
  if (!ACTIONS.has(action)) return problem(404, "Not Found", `unknown mission action "${action}"`);
  const g =
    action === "pause"
      ? await requireCapability("missions.control")
      : await requireStepUp("missions.control");
  if (!g.ok) return g.response;
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  if (action === "kill" && typeof body.reason !== "string") {
    return problem(400, "Bad Request", "kill requires a reason (recorded in the KILL_SWITCH audit event)");
  }
  return forward(platformCore.missionAction(g.session, id, action as "pause" | "resume" | "kill", body));
}
