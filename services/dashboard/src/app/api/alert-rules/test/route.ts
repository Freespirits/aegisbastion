// Route dry-run → herald POST /v1/routes/test (doc 05 §4.1: returns matched
// policies and would-be targets WITHOUT delivering).

import { herald } from "@/lib/backends";
import { requireCapability } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function POST(req: Request) {
  const g = await requireCapability("alert-rules.manage");
  if (!g.ok) return g.response;
  const sample = await readJson<Record<string, unknown>>(req);
  if (!sample || typeof sample !== "object") {
    return problem(400, "Bad Request", "sample event body required");
  }
  return forward(herald.testRoute(sample));
}
