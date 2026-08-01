/**
 * The `scan.request` authorization gate (doc 07 §5.2 handling + §8 hard
 * requirements). Validation order (normative):
 *   0. browser-mode agents reject unconditionally (UNSUPPORTED_IN_MODE);
 *   1. gatekeeper Scope Token verified — signature against gatekeeper JWKS,
 *      expiry, task binding (§8.2; offline verification, fail-closed);
 *   2. scopeId ∈ the agent's enrolled scope allowlist (SCOPE_DENIED);
 *   3. per-scope rate cap (RATE_CAPPED) — default 600 items/min, compiled-in
 *      hard ceiling 5 000/min; the token's `rate_caps` claim wins when
 *      tighter (§8.3).
 *
 * Token verification itself is injected (the MVP-B adapter binds the
 * platform TS agent SDK's `verifyScopeToken` + `JwksCache` — Rulings B/C5:
 * this module never defines its own token format). The gate is pure logic
 * and fully testable offline.
 */

import type { ScopeTokenClaims } from "@aegisbastion/agent-sdk";
import type { ScanRejectReason, ScanRequestPayload } from "./messages.js";

export const DEFAULT_RATE_CAP_PER_MIN = 600;
/** Compiled-in blast-radius ceiling (doc 07 §8.3) — not configurable. */
export const HARD_CEILING_PER_MIN = 5000;

export type DeploymentMode = "node-batch" | "browser-extension" | "browser-embed";

export interface TokenVerifier {
  /** Throws on any verification failure (fail-closed). */
  (token: string, expectedTaskId?: string): Promise<ScopeTokenClaims>;
}

export interface ScanGateOptions {
  mode: DeploymentMode;
  /** Enrolled scope allowlist (tenant IDs, mailbox stores, buckets — §8.1). */
  scopeAllowlist: readonly string[];
  verifyToken: TokenVerifier;
  /** Per-scope default (600 items/min, §8.3). */
  defaultRateCapPerMin?: number;
  now?: () => number;
}

export type GateDecision =
  | { ok: true; claims: ScopeTokenClaims; effectiveRateCapPerMin: number }
  | { ok: false; reason: ScanRejectReason; detail: string };

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

export class ScanRequestGate {
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;

  constructor(private readonly opts: ScanGateOptions) {
    this.now = opts.now ?? (() => Date.now());
  }

  private effectiveCap(req: ScanRequestPayload, claims: ScopeTokenClaims): number {
    let cap = this.opts.defaultRateCapPerMin ?? DEFAULT_RATE_CAP_PER_MIN;
    if (req.rateCapPerMin !== undefined && req.rateCapPerMin > 0) {
      cap = Math.min(cap, req.rateCapPerMin);
    }
    // The Scope Token's rate_caps claim wins when tighter (§8.3).
    if (claims.rate_caps?.max_rps !== undefined && claims.rate_caps.max_rps >= 0) {
      cap = Math.min(cap, claims.rate_caps.max_rps * 60);
    }
    // Compiled-in ceiling bounds a compromised commander (§8.3).
    return Math.min(cap, HARD_CEILING_PER_MIN);
  }

  private consume(scopeId: string, items: number, capPerMin: number): boolean {
    const nowMs = this.now();
    let bucket = this.buckets.get(scopeId);
    if (!bucket) {
      bucket = { tokens: capPerMin, lastRefillMs: nowMs };
      this.buckets.set(scopeId, bucket);
    }
    const elapsedMin = (nowMs - bucket.lastRefillMs) / 60_000;
    if (elapsedMin > 0) {
      bucket.tokens = Math.min(capPerMin, bucket.tokens + elapsedMin * capPerMin);
      bucket.lastRefillMs = nowMs;
    }
    if (bucket.tokens < items) return false;
    bucket.tokens -= items;
    return true;
  }

  /** Evaluate one scan.request. Never throws — failures are rejections. */
  async evaluate(req: ScanRequestPayload): Promise<GateDecision> {
    // §5.2: browser-mode agents reject scan.request unconditionally.
    if (this.opts.mode !== "node-batch") {
      return { ok: false, reason: "UNSUPPORTED_IN_MODE", detail: "scan.request is node-batch only" };
    }

    // §8.2: no token → no batch scan (fail-closed; JWKS-unreachable ⇒ the
    // injected verifier throws ⇒ ROE_INVALID, doc 07 §9).
    if (typeof req.scopeToken !== "string" || req.scopeToken === "") {
      return { ok: false, reason: "ROE_INVALID", detail: "missing gatekeeper Scope Token" };
    }
    let claims: ScopeTokenClaims;
    try {
      claims = await this.opts.verifyToken(req.scopeToken, req.taskId);
    } catch (err) {
      return {
        ok: false,
        reason: "ROE_INVALID",
        detail: `Scope Token verification failed: ${(err as Error).message}`,
      };
    }

    // §8.1: enrolled scope allowlist.
    if (!this.opts.scopeAllowlist.includes(req.scopeId)) {
      return { ok: false, reason: "SCOPE_DENIED", detail: `scopeId "${req.scopeId}" not enrolled` };
    }

    // §8.3: per-scope rate cap.
    const cap = this.effectiveCap(req, claims);
    const items = Math.max(1, req.inputRefs.length);
    if (!this.consume(req.scopeId, items, cap)) {
      return { ok: false, reason: "RATE_CAPPED", detail: `scope "${req.scopeId}" exceeds ${cap} items/min` };
    }

    return { ok: true, claims, effectiveRateCapPerMin: cap };
  }
}
