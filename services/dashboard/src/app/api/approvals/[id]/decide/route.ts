import { gatekeeper } from "@/lib/backends";
import { requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireStepUp("roe.approve");
  if (!g.ok) return g.response;
  const { id } = await ctx.params;
  const body = await readJson<{ approved?: boolean; note?: string }>(req);
  if (typeof body?.approved !== "boolean") {
    return problem(400, "Bad Request", "approved (boolean) is required");
  }
  return forward(
    gatekeeper.decideApproval(id, {
      approver: g.session.sub,
      approved: body.approved,
      ...(body.note ? { note: body.note } : {}),
    }),
  );
}
