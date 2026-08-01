import { gatekeeper } from "@/lib/backends";
import { requireSession } from "@/lib/guard";
import { forward } from "@/lib/http";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const { id } = await ctx.params;
  return forward(gatekeeper.getRoe(id));
}
