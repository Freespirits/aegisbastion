// Delivery log → herald GET /v1/deliveries (herald's data; read-only here).

import { herald } from "@/lib/backends";
import { requireSession } from "@/lib/guard";
import { forward } from "@/lib/http";

export async function GET(req: Request) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const ruleId = new URL(req.url).searchParams.get("rule_id") ?? undefined;
  return forward(herald.deliveries(ruleId));
}
