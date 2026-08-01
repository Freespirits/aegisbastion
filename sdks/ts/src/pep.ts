/**
 * PEP guardrails — the merged platform agent SDK / gatekeeper pep-sdk
 * execution gate (PEP-2, Ruling B.2; doc 01 §9.1/§10.1 "Agent SDK" layer;
 * doc 11 §9 item 4).
 *
 * One `TaskAuthorization` per (task, token): verifies the Scope Token locally
 * (cached JWKS), fetches + verifies the hashed manifest from MinIO, and then
 * enforces — before EVERY network action — target membership (exact manifest,
 * or canonicalized scope evaluation with exclusions-first for scope-bound
 * watch tokens), the token's embedded rate caps, and the live revocation set.
 *
 * Everything fails closed: any mismatch throws PepError and the agent must
 * report REJECTED_UNAUTHORIZED / halt (doc 01 §9 item 4, §10.5).
 */

import { PepError } from "./errors.js";
import { JwksCache } from "./jwks.js";
import {
  fetchAndVerifyManifest,
  type ManifestFetcher,
  type VerifiedManifest,
} from "./manifest.js";
import { RateCapsEnforcer } from "./ratecap.js";
import { RevocationCache } from "./revocation.js";
import { evaluateTargetInScope, isTargetInManifest } from "./scope.js";
import {
  verifyScopeToken,
  type ScopeTokenClaims,
} from "./token.js";

export interface PepOptions {
  jwks: JwksCache;
  manifestFetcher: ManifestFetcher;
  revocations?: RevocationCache;
  /** Test hook: override "now" (Unix seconds) for token verification. */
  nowSeconds?: () => number;
}

export class Pep {
  private readonly manifestCache = new Map<string, Promise<VerifiedManifest>>();

  constructor(private readonly opts: PepOptions) {}

  /**
   * Verify a Scope Token and its manifest, returning the authorization
   * context used to gate every subsequent target touch. Throws (fail-closed)
   * on forged/expired/wrong-audience/wrong-task tokens, manifest hash
   * mismatches, and active revocations.
   */
  async authorizeTask(token: string, expectedTaskId: string): Promise<TaskAuthorization> {
    const claims = await verifyScopeToken(token, {
      getKey: this.opts.jwks.getKey,
      expectedTaskId,
      ...(this.opts.nowSeconds ? { nowSeconds: this.opts.nowSeconds() } : {}),
    });
    const manifest = await this.verifiedManifest(claims);
    this.opts.revocations?.assertNotRevoked(claims);
    return new TaskAuthorization(claims, manifest, this.opts.revocations ?? null);
  }

  private verifiedManifest(claims: ScopeTokenClaims): Promise<VerifiedManifest> {
    const key = claims.targets.manifest_sha256;
    let cached = this.manifestCache.get(key);
    if (!cached) {
      cached = fetchAndVerifyManifest(claims.targets, claims.scope_bound === true, this.opts.manifestFetcher).catch(
        (err: unknown) => {
          // Do not cache failures — a transient MinIO outage must not pin a
          // permanent denial for this manifest hash.
          this.manifestCache.delete(key);
          throw err;
        },
      );
      this.manifestCache.set(key, cached);
    }
    return cached;
  }
}

/**
 * The per-task guard. Modules call `checkTarget` before every network action
 * (doc 01 §5.5: "re-check every target string against the manifest before
 * each network action"; Ruling A.5 for scope-bound watch tokens).
 */
export class TaskAuthorization {
  readonly rateCaps: RateCapsEnforcer;

  constructor(
    readonly claims: ScopeTokenClaims,
    readonly manifest: VerifiedManifest,
    private readonly revocations: RevocationCache | null,
  ) {
    this.rateCaps = new RateCapsEnforcer(claims.rate_caps, { riskClass: claims.risk_class });
  }

  /** True when this is a Ruling A scope-bound watch authorization. */
  get scopeBound(): boolean {
    return this.claims.scope_bound === true;
  }

  /** Assert the task may exercise this capability at all. */
  assertCapability(capability: string): void {
    if (!this.claims.capabilities.includes(capability)) {
      throw new PepError("TARGET_NOT_IN_SCOPE", `capability not granted by token: ${capability}`, {
        capability,
      });
    }
    this.revocations?.assertNotRevoked(this.claims, undefined, capability);
  }

  /**
   * Gate one target touch. Throws PepError on:
   *  - active revocation (global / RoE / capability / target),
   *  - target ∉ exact manifest (exact form),
   *  - target ∉ canonical scope or ∈ exclusions (scope-bound form;
   *    exclusions ALWAYS win),
   *  - embedded rate cap exceeded.
   */
  checkTarget(rawTarget: string, capability?: string): void {
    if (capability !== undefined) this.assertCapability(capability);
    this.revocations?.assertNotRevoked(this.claims, rawTarget, capability);

    if (this.manifest.form === "exact") {
      if (!isTargetInManifest(rawTarget, this.manifest.targets)) {
        throw new PepError("TARGET_NOT_IN_MANIFEST", `target not in token manifest: ${rawTarget}`);
      }
    } else {
      const verdict = evaluateTargetInScope(rawTarget, this.manifest.manifest.scope);
      if (!verdict.allow) {
        throw new PepError(verdict.code, `target denied by scope (${verdict.code}): ${rawTarget}`, {
          matchedRule: verdict.matchedRule,
        });
      }
    }

    this.rateCaps.check();
  }
}
