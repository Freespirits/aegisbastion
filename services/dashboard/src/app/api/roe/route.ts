// RoE list + create → gatekeeper admin-api /v1/roe (Ruling B: no local RoE
// storage; the dashboard is a client of roe-service). Create requires the
// roe-author affordance AND step-up (doc 10 §7.2).

import { gatekeeper } from "@/lib/backends";
import { requireSession, requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function GET(req: Request) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const url = new URL(req.url);
  const status = url.searchParams.get("status") ?? undefined;
  const pageToken = url.searchParams.get("page_token") ?? undefined;
  return forward(gatekeeper.listRoes(g.session.orgId, status, pageToken));
}

export async function POST(req: Request) {
  const g = await requireStepUp("roe.author");
  if (!g.ok) return g.response;
  const roe = await readJson<Record<string, unknown>>(req);
  if (!roe || typeof roe.name !== "string" || roe.name.trim() === "") {
    return problem(400, "Bad Request", "name is required");
  }
  // The record is created under the session's org and author — client-supplied
  // tenancy/identity fields are never trusted (doc 10 §6).
  const record = { ...roe, org_id: g.session.orgId, created_by: g.session.sub };
  return forward(gatekeeper.createRoe(record));
}
