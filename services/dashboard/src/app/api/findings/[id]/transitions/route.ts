// Finding lifecycle transitions → data-platform POST /v1/findings/{id}/transitions
// (doc 04 §7.3 edges enforced authoritatively by 09; Ruling C4).

import { dataPlatform } from "@/lib/backends";
import { requireCapability } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";
import { FINDING_STATES } from "@/lib/types";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireCapability("findings.triage");
  if (!g.ok) return g.response;
  const { id } = await ctx.params;
  const body = await readJson<{ to_state?: string; note?: string; task_id?: string }>(req);
  if (!body?.to_state || !(FINDING_STATES as readonly string[]).includes(body.to_state)) {
    return problem(400, "Bad Request", `to_state must be one of ${FINDING_STATES.join("|")}`);
  }
  return forward(
    dataPlatform.findingTransition(g.session, id, {
      to_state: body.to_state,
      ...(body.note ? { note: body.note } : {}),
      ...(body.task_id ? { task_id: body.task_id } : {}),
    }),
  );
}
