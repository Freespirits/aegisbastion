// Approval queue → gatekeeper approval-service via admin-api (doc 11 §2.1.8:
// four-eyes, SoD, 72 h expiry). Deciding is a sensitive action: step-up +
// roe.approve affordance; the approver identity is ALWAYS the session
// principal (never client-supplied — SoD depends on it).

import { gatekeeper } from "@/lib/backends";
import { requireSession, requireStepUp } from "@/lib/guard";
import { forward, problem, readJson } from "@/lib/http";

export async function GET(req: Request) {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const url = new URL(req.url);
  return forward(
    gatekeeper.listApprovals({
      state: url.searchParams.get("state") ?? undefined,
      roeId: url.searchParams.get("roe_id") ?? undefined,
      pageToken: url.searchParams.get("page_token") ?? undefined,
    }),
  );
}
