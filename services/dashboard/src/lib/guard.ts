// Route-handler guards: session required, capability re-check (defense in
// depth — authoritative enforcement is downstream), and the step-up window
// for sensitive actions (doc 10 §7.2).

import { NextResponse } from "next/server";
import { problem } from "@/lib/http";
import { getSession, hasStepUp, type Session } from "@/lib/session";
import { hasCapability, type Capability } from "@/lib/roles";

export type GuardResult =
  | { ok: true; session: Session }
  | { ok: false; response: NextResponse };

export async function requireSession(): Promise<GuardResult> {
  const session = await getSession();
  if (!session) return { ok: false, response: problem(401, "Unauthorized", "login required") };
  return { ok: true, session };
}

export async function requireCapability(cap: Capability): Promise<GuardResult> {
  const g = await requireSession();
  if (!g.ok) return g;
  if (!hasCapability(g.session.roles, cap)) {
    return {
      ok: false,
      response: problem(403, "Forbidden", `role set lacks the "${cap}" affordance`, {
        reason_code: "FORBIDDEN_ROLE",
      }),
    };
  }
  return g;
}

/** Sensitive actions additionally demand a ≤5-min-old step-up (doc 10 §7.2). */
export async function requireStepUp(cap: Capability): Promise<GuardResult> {
  const g = await requireCapability(cap);
  if (!g.ok) return g;
  if (!hasStepUp(g.session)) {
    return {
      ok: false,
      response: problem(
        403,
        "Step-Up Required",
        "this action requires a fresh (≤5 min) step-up authentication",
        { reason_code: "STEP_UP_REQUIRED" },
      ),
    };
  }
  return g;
}
