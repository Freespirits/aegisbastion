// Dev static-token login shim (doc 10 MVP-A: "dev mode static-token shim
// behind a flag"). Disabled unless DEV_AUTH_ENABLED=true; never for prod —
// production login is the OIDC flow (/api/auth/oidc/start).

import { NextResponse } from "next/server";
import { env } from "@/env";
import { resolveRoles } from "@/lib/backends";
import { problem } from "@/lib/http";
import { setSessionCookie, type Session } from "@/lib/session";

export async function POST(req: Request) {
  const e = env();
  if (!e.devAuthEnabled) {
    return problem(404, "Not Found", "dev login shim is disabled");
  }
  let body: { principal?: string; org_id?: string; token?: string };
  try {
    body = await req.json();
  } catch {
    return problem(400, "Bad Request", "JSON body expected");
  }
  if (e.devAuthToken && body.token !== e.devAuthToken) {
    return problem(401, "Unauthorized", "invalid dev token");
  }
  const principal = (body.principal ?? "").trim();
  if (!principal) {
    return problem(400, "Bad Request", "principal is required");
  }
  const orgId = (body.org_id ?? "").trim() || e.orgId;
  // Roles come from gatekeeper rbac-service when reachable (doc 10 §7.2: the
  // UI stores no role data locally); otherwise the configured dev fallback.
  const resolved = await resolveRoles(orgId, principal);
  const roles = resolved ?? e.devAuthFallbackRoles;
  const session: Session = {
    sub: principal,
    name: principal,
    orgId,
    roles,
    dev: true,
    iat: Math.floor(Date.now() / 1000),
  };
  await setSessionCookie(session);
  return NextResponse.json({ ok: true, roles, rolesFrom: resolved ? "gatekeeper" : "fallback" });
}
