// OIDC callback: code exchange + id_token verification (issuer JWKS via
// jose), then session creation with roles resolved from gatekeeper
// rbac-service (doc 10 §7.2 — no role data stored locally).

import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { env } from "@/env";
import { resolveRoles } from "@/lib/backends";
import { discover } from "@/lib/oidc";
import { setSessionCookie, type Session } from "@/lib/session";

function redirectHome(path: string): NextResponse {
  const e = env();
  const base = e.oidc ? new URL(e.oidc.redirectUri).origin : "http://localhost:3000";
  return NextResponse.redirect(`${base}${path}`);
}

export async function GET(req: Request) {
  const e = env();
  if (!e.oidc) return redirectHome("/login?error=oidc_disabled");
  const url = new URL(req.url);
  const errParam = url.searchParams.get("error");
  if (errParam) return redirectHome(`/login?error=${encodeURIComponent(errParam)}`);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const store = await cookies();
  const pendingRaw = store.get("aegisbastion_oidc")?.value;
  store.delete("aegisbastion_oidc");
  if (!code || !state || !pendingRaw) return redirectHome("/login?error=bad_callback");
  let pending: { state: string; nonce: string };
  try {
    pending = JSON.parse(pendingRaw);
  } catch {
    return redirectHome("/login?error=bad_callback");
  }
  if (pending.state !== state) return redirectHome("/login?error=state_mismatch");

  try {
    const disco = await discover(e.oidc.issuer);
    const tokenRes = await fetch(disco.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: e.oidc.redirectUri,
        client_id: e.oidc.clientId,
        ...(e.oidc.clientSecret ? { client_secret: e.oidc.clientSecret } : {}),
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) return redirectHome("/login?error=token_exchange");
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) return redirectHome("/login?error=no_id_token");

    const jwks = createRemoteJWKSet(new URL(disco.jwks_uri));
    const { payload } = await jwtVerify(tokens.id_token, jwks, {
      issuer: disco.issuer,
      audience: e.oidc.clientId,
    });
    if (payload.nonce !== pending.nonce) return redirectHome("/login?error=nonce_mismatch");
    const sub = typeof payload.sub === "string" ? payload.sub : "";
    if (!sub) return redirectHome("/login?error=no_subject");
    const name =
      (typeof payload.name === "string" && payload.name) ||
      (typeof payload.email === "string" && payload.email) ||
      sub;

    // Roles: gatekeeper rbac-service is the source of truth (doc 11 §3.5).
    // When unreachable, degrade to read-only rather than locking operators
    // out of situational awareness (doc 10 §8: reads stay up).
    const roles = (await resolveRoles(e.orgId, sub)) ?? [];
    const session: Session = {
      sub,
      name,
      orgId: e.orgId,
      roles,
      dev: false,
      iat: Math.floor(Date.now() / 1000),
    };
    await setSessionCookie(session);
    return redirectHome("/");
  } catch {
    return redirectHome("/login?error=oidc_failed");
  }
}
