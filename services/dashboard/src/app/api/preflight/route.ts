// Non-authoritative preflight scope dry-run (doc 10 §7.1 step 1 — UX only,
// NEVER authoritative; the dispatch PEP's call to gatekeeper policy-service
// is the decision). Fetches the RoE from gatekeeper admin-api and evaluates
// the target set with the platform's canonical matching semantics locally
// (exclusions always win). See src/lib/preflight.ts.

import { gatekeeper } from "@/lib/backends";
import { requireSession } from "@/lib/guard";
import { problem, readJson } from "@/lib/http";
import { evaluateScope, scopeConfirmToken, type RoeScope } from "@/lib/preflight";
import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const body = await readJson<{ roe_id?: string; targets?: string[] }>(req);
  if (!body?.roe_id || !Array.isArray(body.targets) || body.targets.length === 0) {
    return problem(400, "Bad Request", "roe_id and a non-empty targets array are required");
  }
  if (body.targets.length > 500) {
    return problem(400, "Bad Request", "targets exceeds 500 entries");
  }
  let roeRes: Response;
  try {
    ({ res: roeRes } = await gatekeeper.getRoe(body.roe_id));
  } catch (err) {
    return problem(503, "Backend Unavailable", String(err), { backend: "gatekeeper" });
  }
  if (!roeRes.ok) {
    return new NextResponse(await roeRes.text(), {
      status: roeRes.status,
      headers: { "content-type": roeRes.headers.get("content-type") ?? "application/json" },
    });
  }
  const { roe } = (await roeRes.json()) as { roe?: { status?: string; scope?: RoeScope } };
  const scope = roe?.scope ?? {};
  return NextResponse.json({
    roe_id: body.roe_id,
    roe_status: roe?.status ?? "UNKNOWN",
    authoritative: false,
    notice:
      "Non-authoritative UX preflight (doc 10 §7.1 step 1). The dispatch decision is made by gatekeeper policy-service; denials there are final.",
    confirm_token: scopeConfirmToken(scope),
    results: evaluateScope(scope, body.targets),
  });
}
