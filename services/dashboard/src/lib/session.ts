// Encrypted session cookie (doc 10 §2.1: Redis sessions at scale; at MVP-A the
// session is an encrypted httpOnly cookie — the only credential the browser
// ever holds). Sessions carry NO backend tokens: the BFF proxies with its own
// identity headers, so there is nothing to steal beyond the sealed cookie.

import { createHash } from "node:crypto";
import { cookies } from "next/headers";
import { SignJWT, jwtVerify } from "jose";
import { env } from "@/env";

export interface Session {
  /** Authenticated principal, e.g. "op_jane@example.com" (OIDC sub or dev id). */
  sub: string;
  /** Display name / email claim when available. */
  name: string;
  /** Owning org (tenancy boundary for gatekeeper calls). */
  orgId: string;
  /** Gatekeeper rbac-service roles resolved at login (doc 11 §3.5). */
  roles: string[];
  /** True when the session came from the dev static-token shim. */
  dev: boolean;
  /** Epoch seconds until which a step-up assertion is valid (≤5 min, doc 10 §7.2). */
  stepUpUntil?: number;
  /** Epoch seconds of login. */
  iat: number;
}

const SESSION_TTL_S = 8 * 3600;

function key(): Uint8Array {
  // Derive a stable 256-bit key from the configured secret.
  return createHash("sha256").update(env().sessionSecret, "utf8").digest();
}

export async function sealSession(s: Session): Promise<string> {
  return new SignJWT({ ...s })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(s.iat)
    .setExpirationTime(s.iat + SESSION_TTL_S)
    .sign(key());
}

export async function unsealSession(token: string): Promise<Session | null> {
  try {
    const { payload } = await jwtVerify(token, key(), { algorithms: ["HS256"] });
    const { sub, name, orgId, roles, dev, stepUpUntil, iat } = payload as Record<string, unknown>;
    if (typeof sub !== "string" || sub === "") return null;
    return {
      sub,
      name: typeof name === "string" ? name : sub,
      orgId: typeof orgId === "string" && orgId ? orgId : env().orgId,
      roles: Array.isArray(roles) ? (roles as string[]) : [],
      dev: dev === true,
      stepUpUntil: typeof stepUpUntil === "number" ? stepUpUntil : undefined,
      iat: typeof iat === "number" ? iat : Math.floor(Date.now() / 1000),
    };
  } catch {
    return null;
  }
}

/** Current session from the request cookie, or null (route handlers, server components). */
export async function getSession(): Promise<Session | null> {
  const store = await cookies();
  const raw = store.get(env().sessionCookie)?.value;
  if (!raw) return null;
  return unsealSession(raw);
}

/** Persist the session cookie on the response (route handlers). */
export async function setSessionCookie(s: Session): Promise<void> {
  const store = await cookies();
  store.set(env().sessionCookie, await sealSession(s), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_TTL_S,
  });
}

export async function clearSessionCookie(): Promise<void> {
  const store = await cookies();
  store.delete(env().sessionCookie);
}

/** True when a ≤5-min-old step-up assertion is present (doc 10 §7.2). */
export function hasStepUp(s: Session | null, nowS = Math.floor(Date.now() / 1000)): boolean {
  return !!s?.stepUpUntil && s.stepUpUntil > nowS;
}
