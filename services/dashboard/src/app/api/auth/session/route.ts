import { NextResponse } from "next/server";
import { env } from "@/env";
import { getSession, hasStepUp } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";

/** Session introspection for client components (no secrets — capabilities only). */
export async function GET() {
  const session = await getSession();
  const e = env();
  if (!session) {
    return NextResponse.json({
      authenticated: false,
      oidcEnabled: !!e.oidc,
      devAuthEnabled: e.devAuthEnabled,
    });
  }
  return NextResponse.json({
    authenticated: true,
    oidcEnabled: !!e.oidc,
    devAuthEnabled: e.devAuthEnabled,
    session: {
      sub: session.sub,
      name: session.name,
      orgId: session.orgId,
      roles: session.roles,
      dev: session.dev,
    },
    capabilities: [...capabilitiesOf(session.roles)],
    stepUp: { active: hasStepUp(session), until: session.stepUpUntil ?? null },
  });
}
