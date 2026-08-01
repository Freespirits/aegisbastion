/**
 * Gatekeeper Scope Token verification (Authorization Token v1.1 — doc 01 §5.5
 * as amended by Ruling A, converged with doc 11 §3.2; Ruling C5).
 *
 * The Scope Token is the ONLY execution credential: Ed25519/EdDSA JWT,
 * JWKS-verified, task-bound (jti), audience "aegisbastion.modules", 15-minute TTL
 * for ALL active classes R1–R3. Verification is fully local (cached JWKS).
 *
 * Clock policy (doc 11 §7): 60 s leeway on nbf/exp; iat more than 120 s in the
 * future is rejected as skew/tamper. Everything here is fail-closed.
 */

import { errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { PepError } from "./errors.js";

export const TOKEN_ISSUER = "gatekeeper.platform";
export const TOKEN_AUDIENCE = "aegisbastion.modules";
/** Ruling C5: uniform 15-minute TTL for all active classes R1–R3. */
export const MAX_TOKEN_TTL_SECONDS = 900;
/** Doc 11 §7: 60 s leeway on nbf/exp. */
export const CLOCK_LEEWAY_SECONDS = 60;
/** Doc 11 §7: PEPs reject tokens with skew > 120 s and alert. */
export const MAX_CLOCK_SKEW_SECONDS = 120;

/** Ruling A: scope-bound watch tokens are valid ONLY for these R1 capabilities. */
export const SCOPE_BOUND_CAPABILITIES = new Set(["monitor.watch", "monitor.rescan"]);

export type RiskClassName = "R1" | "R2" | "R3";

/** Reference to the hashed target manifest (doc 01 §5.5, doc 11 §3.2). */
export interface TargetManifestRef {
  hash_alg: "sha256";
  manifest_uri: string;
  manifest_sha256: string;
  count?: number;
}

/** Rate caps embedded in the token (max_rps ≡ rps — one claim set). */
export interface TokenRateCaps {
  max_rps?: number;
  max_concurrent?: number;
}

/**
 * The Scope Token claim set as it appears in the JWT payload (JSON wire form,
 * doc 01 §5.5 / doc 11 §3.2 — field names are the exact JWT claim names).
 */
export interface ScopeTokenClaims {
  iss: typeof TOKEN_ISSUER;
  aud: typeof TOKEN_AUDIENCE;
  /** Token id; also the authorization_token_id carried by AlertEvent v1. */
  jti: string;
  /** Executing agent/workload. */
  sub: string;
  /** Task this token is bound to (single-purpose). */
  task_id: string;
  roe_id: string;
  roe_version: number;
  risk_class: RiskClassName;
  capabilities: string[];
  targets: TargetManifestRef;
  /** Ruling A scope-bound watch-token form (R1 monitor.watch/rescan only). */
  scope_bound?: boolean;
  rate_caps?: TokenRateCaps;
  /** Four-eyes approval ref — mandatory for R3 / R2 stress.* on production. */
  approval_id?: string;
  iat: number;
  nbf?: number;
  exp: number;
}

export interface VerifyTokenOptions {
  /** JWKS key resolver (see JwksCache.getKey). */
  getKey: JWTVerifyGetKey;
  /** The task this token is being used for — must equal the task_id claim. */
  expectedTaskId?: string;
  /** Override "now" (Unix seconds) — for tests. */
  nowSeconds?: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function failClaims(message: string, detail: Record<string, unknown> = {}): never {
  throw new PepError("TOKEN_MALFORMED", message, detail);
}

/** Validate the decoded payload's shape and claim-level rules. Fail-closed. */
export function parseScopeTokenClaims(payload: unknown, nowSeconds: number): ScopeTokenClaims {
  if (!isRecord(payload)) failClaims("payload is not an object");

  if (payload.iss !== TOKEN_ISSUER) {
    throw new PepError("TOKEN_ISSUER_INVALID", `unexpected iss: ${String(payload.iss)}`);
  }
  if (payload.aud !== TOKEN_AUDIENCE) {
    throw new PepError("TOKEN_AUDIENCE_INVALID", `unexpected aud: ${String(payload.aud)}`);
  }
  for (const field of ["jti", "sub", "task_id", "roe_id"] as const) {
    if (typeof payload[field] !== "string" || payload[field] === "") {
      failClaims(`missing or invalid claim: ${field}`);
    }
  }
  if (typeof payload.roe_version !== "number" || !Number.isInteger(payload.roe_version) || payload.roe_version < 1) {
    failClaims("missing or invalid claim: roe_version");
  }
  if (payload.risk_class !== "R1" && payload.risk_class !== "R2" && payload.risk_class !== "R3") {
    // R0 requires no per-target token (doc 11 §1); anything else is invalid.
    throw new PepError("TOKEN_RISK_CLASS_INVALID", `unexpected risk_class: ${String(payload.risk_class)}`);
  }
  if (
    !Array.isArray(payload.capabilities) ||
    payload.capabilities.length === 0 ||
    !payload.capabilities.every((c) => typeof c === "string" && c !== "")
  ) {
    failClaims("missing or invalid claim: capabilities");
  }
  if (!isRecord(payload.targets)) failClaims("missing or invalid claim: targets");
  const targets = payload.targets;
  if (targets.hash_alg !== "sha256") failClaims("targets.hash_alg must be sha256");
  if (typeof targets.manifest_uri !== "string" || targets.manifest_uri === "") {
    failClaims("missing or invalid claim: targets.manifest_uri");
  }
  if (typeof targets.manifest_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(targets.manifest_sha256)) {
    failClaims("missing or invalid claim: targets.manifest_sha256 (expected 64 lowercase hex chars)");
  }
  if (targets.count !== undefined && (typeof targets.count !== "number" || targets.count < 0)) {
    failClaims("invalid claim: targets.count");
  }
  if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
    failClaims("missing or invalid claims: iat/exp");
  }
  // Ruling C5: TTL ≤ 15 min for ALL active classes.
  if (payload.exp - payload.iat > MAX_TOKEN_TTL_SECONDS) {
    throw new PepError("TOKEN_TTL_EXCEEDED", `token TTL ${payload.exp - payload.iat}s exceeds ${MAX_TOKEN_TTL_SECONDS}s`, {
      ttl: payload.exp - payload.iat,
    });
  }
  // Doc 11 §7 clock-skew guard: iat implausibly far in the future → tamper/replay.
  if (payload.iat > nowSeconds + MAX_CLOCK_SKEW_SECONDS) {
    throw new PepError("TOKEN_NOT_YET_VALID", "iat is more than 120s in the future (clock skew or tamper)", {
      iat: payload.iat,
    });
  }
  if (payload.scope_bound !== undefined && typeof payload.scope_bound !== "boolean") {
    failClaims("invalid claim: scope_bound");
  }
  if (payload.scope_bound === true) {
    // Ruling A narrow applicability: R1 standing watch capabilities only.
    const capabilities = payload.capabilities as string[];
    if (payload.risk_class !== "R1" || !capabilities.every((c) => SCOPE_BOUND_CAPABILITIES.has(c))) {
      throw new PepError(
        "TOKEN_SCOPE_BOUND_MISUSE",
        "scope_bound tokens are valid only for R1 monitor.watch / monitor.rescan",
        { risk_class: payload.risk_class, capabilities },
      );
    }
  }
  if (payload.rate_caps !== undefined) {
    if (!isRecord(payload.rate_caps)) failClaims("invalid claim: rate_caps");
    for (const k of ["max_rps", "max_concurrent"] as const) {
      const v = payload.rate_caps[k];
      if (v !== undefined && (typeof v !== "number" || v < 0)) failClaims(`invalid claim: rate_caps.${k}`);
    }
  }
  if (payload.approval_id !== undefined && typeof payload.approval_id !== "string") {
    failClaims("invalid claim: approval_id");
  }

  return payload as unknown as ScopeTokenClaims;
}

/**
 * Verify a compact Scope Token JWT against the cached JWKS and return its
 * validated claims. Throws PepError on ANY failure — fail-closed.
 *
 * Checks (doc 01 §5.5/§10, doc 11 §3.2/§7): EdDSA signature via JWKS (kid),
 * alg allowlist, iss, aud, exp/nbf with 60 s leeway, iat skew ≤ 120 s,
 * TTL ≤ 15 min, task binding, claim shape, Ruling A scope-bound rules.
 */
export async function verifyScopeToken(token: string, opts: VerifyTokenOptions): Promise<ScopeTokenClaims> {
  if (!token) {
    throw new PepError("TOKEN_MISSING", "no Scope Token presented");
  }
  const nowSeconds = opts.nowSeconds ?? Math.floor(Date.now() / 1000);

  let payload: unknown;
  try {
    const result = await jwtVerify(token, opts.getKey, {
      algorithms: ["EdDSA"],
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE,
      clockTolerance: CLOCK_LEEWAY_SECONDS,
      ...(opts.nowSeconds !== undefined ? { currentDate: new Date(opts.nowSeconds * 1000) } : {}),
    });
    payload = result.payload;
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      throw new PepError("TOKEN_EXPIRED", "Scope Token expired", { jti: undefined });
    }
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      const claim = (err as { claim?: string }).claim;
      if (claim === "aud") throw new PepError("TOKEN_AUDIENCE_INVALID", "audience mismatch");
      if (claim === "iss") throw new PepError("TOKEN_ISSUER_INVALID", "issuer mismatch");
      if (claim === "nbf") throw new PepError("TOKEN_NOT_YET_VALID", "token not yet valid (nbf)");
      throw new PepError("TOKEN_MALFORMED", `claim validation failed: ${String(claim)}`);
    }
    if (err instanceof joseErrors.JWSSignatureVerificationFailed || err instanceof joseErrors.JOSEAlgNotAllowed) {
      throw new PepError("TOKEN_SIGNATURE_INVALID", "Scope Token signature verification failed");
    }
    if (err instanceof joseErrors.JWKSNoMatchingKey) {
      throw new PepError("JWKS_UNAVAILABLE", "no JWKS key matches the token kid");
    }
    throw new PepError("TOKEN_MALFORMED", `token verification failed: ${(err as Error).message}`);
  }

  const claims = parseScopeTokenClaims(payload, nowSeconds);

  if (opts.expectedTaskId !== undefined && claims.task_id !== opts.expectedTaskId) {
    // Doc 11 §3.2: a token minted for one task_id is useless for any other.
    throw new PepError("TOKEN_TASK_MISMATCH", "token is bound to a different task_id", {
      expected: opts.expectedTaskId,
    });
  }
  return claims;
}
