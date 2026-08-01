// WebAuthn step-up — PLACEHOLDER FLOW (assignment scope: "WebAuthn step-up
// placeholder flow for sensitive actions"). doc 10 §7.2 requires a ≤5-min-old
// phishing-resistant re-auth for: RoE create/revoke, approving plans with
// offensive steps, offensive launches, commander resume.
//
// What is real here: the server-side step-up window (5-min TTL bound into the
// sealed session) and the mandatory check on every sensitive API route
// (requireStepUp in @/lib/guard). What is placeholder: the ceremony itself —
// the client posts an acknowledgement instead of a verified WebAuthn
// assertion. Wiring navigator.credentials + attestation verification (and the
// downstream `acr` claim check by gatekeeper) is the production follow-up.

import { NextResponse } from "next/server";
import { env } from "@/env";
import { problem } from "@/lib/http";
import { getSession, hasStepUp, setSessionCookie } from "@/lib/session";

export async function GET() {
  const session = await getSession();
  if (!session) return problem(401, "Unauthorized", "login required");
  return NextResponse.json({
    active: hasStepUp(session),
    until: session.stepUpUntil ?? null,
    placeholder: true,
  });
}

export async function POST(req: Request) {
  const session = await getSession();
  if (!session) return problem(401, "Unauthorized", "login required");
  let body: { acknowledge?: boolean };
  try {
    body = await req.json();
  } catch {
    return problem(400, "Bad Request", "JSON body expected");
  }
  if (body.acknowledge !== true) {
    return problem(400, "Bad Request", "step-up acknowledgement required (placeholder ceremony)");
  }
  const next = {
    ...session,
    stepUpUntil: Math.floor(Date.now() / 1000) + env().stepUpTtlSeconds,
  };
  await setSessionCookie(next);
  return NextResponse.json({ active: true, until: next.stepUpUntil, placeholder: true });
}
