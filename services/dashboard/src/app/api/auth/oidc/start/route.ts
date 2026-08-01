// OIDC authorization-code flow against the env-configured platform IdP
// (doc 10 §5: "OIDC (platform IdP) + WebAuthn step-up"). Server-side only;
// the browser sees nothing but redirects and the sealed session cookie.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { env } from "@/env";
import { problem } from "@/lib/http";
import { discover } from "@/lib/oidc";

export async function GET() {
  const e = env();
  if (!e.oidc) return problem(404, "Not Found", "OIDC is not configured");
  const disco = await discover(e.oidc.issuer);
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const store = await cookies();
  store.set("aegisbastion_oidc", JSON.stringify({ state, nonce }), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 600,
  });
  const url = new URL(disco.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", e.oidc.clientId);
  url.searchParams.set("redirect_uri", e.oidc.redirectUri);
  url.searchParams.set("scope", e.oidc.scopes);
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  return NextResponse.redirect(url.toString());
}
