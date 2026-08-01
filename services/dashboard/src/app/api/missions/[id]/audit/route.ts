// Mission hash-chained audit trail → platform-core (doc 01 §5.9). The audit
// of record is gatekeeper's; this is the mission-scoped chain view
// (auditor affordance, doc 10 §4.4).

import { platformCore } from "@/lib/backends";
import { requireCapability } from "@/lib/guard";
import { forward } from "@/lib/http";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireCapability("audit.view");
  if (!g.ok) return g.response;
  const { id } = await ctx.params;
  const afterSeq = new URL(req.url).searchParams.get("after_seq") ?? undefined;
  return forward(platformCore.missionAudit(g.session, id, afterSeq));
}
