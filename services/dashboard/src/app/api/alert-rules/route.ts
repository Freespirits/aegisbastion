// Alert-rules → herald control API (doc 05 §4.1). CLIENT ONLY (Ruling C7):
// this module CRUDs routing policies and renders herald's delivery log; it
// never dispatches a notification.

import { herald } from "@/lib/backends";
import { requireCapability, requireSession } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function GET() {
  const g = await requireSession();
  if (!g.ok) return g.response;
  return forward(herald.listRoutingPolicies());
}

export async function POST(req: Request) {
  const g = await requireCapability("alert-rules.manage");
  if (!g.ok) return g.response;
  const policy = await readJson<Record<string, unknown>>(req);
  if (!policy || typeof policy !== "object") {
    return problem(400, "Bad Request", "routing policy body required (doc 05 §5.4)");
  }
  return forward(herald.createRoutingPolicy(g.session, { ...policy, created_by: g.session.sub }));
}
