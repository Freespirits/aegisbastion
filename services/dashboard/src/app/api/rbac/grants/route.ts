// Current principal's gatekeeper RBAC grants (doc 11 §3.5) — lets the UI
// refresh its affordance mapping without re-login. Roles are gatekeeper's;
// the dashboard stores none locally (doc 10 §7.2).

import { resolveRoles } from "@/lib/backends";
import { requireSession } from "@/lib/guard";
import { capabilitiesOf } from "@/lib/roles";
import { NextResponse } from "next/server";

export async function GET() {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const roles = await resolveRoles(g.session.orgId, g.session.sub);
  if (roles === null) {
    return NextResponse.json(
      { stale: true, roles: g.session.roles, capabilities: [...capabilitiesOf(g.session.roles)] },
      { status: 200 },
    );
  }
  return NextResponse.json({ stale: false, roles, capabilities: [...capabilitiesOf(roles)] });
}
