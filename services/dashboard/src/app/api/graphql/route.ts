// GraphQL read proxy → data-platform /v1/query (doc 09 §5). Read-only: the
// dashboard forwards queries verbatim under the SESSION principal (TPEL
// resolves the tenant server-side — doc 09 §2.3; the tenant is never taken
// from the client payload).

import { dataPlatform } from "@/lib/backends";
import { requireSession } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function POST(req: Request) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const body = await readJson<{ query?: string; variables?: Record<string, unknown> }>(req);
  if (!body?.query || typeof body.query !== "string") {
    return problem(400, "Bad Request", "query is required");
  }
  if (body.query.length > 64_000) {
    return problem(400, "Bad Request", "query too large");
  }
  // No mutations through this façade (doc 10 §4.5: read-only).
  if (/^\s*mutation\b/i.test(body.query)) {
    return problem(400, "Bad Request", "the GraphQL façade is read-only (doc 10 §4.5)");
  }
  return forward(dataPlatform.graphql(g.session, body.query, body.variables));
}
