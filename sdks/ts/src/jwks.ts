/**
 * JWKS cache for local Scope Token verification (doc 01 §10.2, doc 11 §3.2):
 * public keys come from gatekeeper's TokenService.GetJWKS (published at
 * /.well-known/gatekeeper-jwks.json, internal + mTLS) and are cached; rotation
 * via kid header with two active keys max. An unknown kid triggers ONE refresh
 * (key rotation), then fails closed.
 */

import { createLocalJWKSet, type JWTVerifyGetKey, type JSONWebKeySet } from "jose";
import type { JsonWebKey } from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";
import { PepError } from "./errors.js";

export interface JwksCacheOptions {
  /**
   * Fetches the current JWKS keys from gatekeeper (TokenService.GetJWKS).
   * Injected so the cache stays transport-agnostic (and testable).
   */
  fetchKeys: () => Promise<JsonWebKey[]>;
  /** Background refresh interval (default 5 min, matching PEP cache TTL norms). */
  refreshIntervalMs?: number;
}

export class JwksCache {
  private keys: JsonWebKey[] = [];
  private localSet: JWTVerifyGetKey | null = null;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private refreshing: Promise<void> | null = null;

  constructor(private readonly opts: JwksCacheOptions) {}

  /** Initial load. Throws JWKS_UNAVAILABLE when gatekeeper cannot be reached. */
  async start(): Promise<void> {
    await this.refresh();
    const interval = this.opts.refreshIntervalMs ?? 5 * 60 * 1000;
    this.refreshTimer = setInterval(() => {
      this.refresh().catch(() => {
        // Keep serving the last good key set (doc 11 §7: existing unexpired
        // tokens keep working when a gatekeeper dependency is down).
      });
    }, interval);
    this.refreshTimer.unref?.();
  }

  stop(): void {
    if (this.refreshTimer !== null) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  async refresh(): Promise<void> {
    this.refreshing ??= this.doRefresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async doRefresh(): Promise<void> {
    let keys: JsonWebKey[];
    try {
      keys = await this.opts.fetchKeys();
    } catch (err) {
      throw new PepError("JWKS_UNAVAILABLE", `failed to fetch JWKS: ${(err as Error).message}`);
    }
    const active = keys.filter((k) => k.kty === "OKP" && k.crv === "Ed25519" && k.kid !== "");
    if (active.length === 0) {
      throw new PepError("JWKS_UNAVAILABLE", "JWKS contains no active Ed25519 keys");
    }
    const jwks: JSONWebKeySet = {
      keys: active.map((k) => ({
        kty: k.kty,
        crv: k.crv,
        kid: k.kid,
        alg: k.alg || "EdDSA",
        use: k.use || "sig",
        x: k.x,
      })),
    };
    this.keys = active;
    this.localSet = createLocalJWKSet(jwks);
  }

  /** Currently cached key ids (diagnostics / audit). */
  cachedKids(): string[] {
    return this.keys.map((k) => k.kid);
  }

  /**
   * jose-compatible key resolver. On an unknown kid (key rotation in
   * progress), refreshes the JWKS once and retries; still no match → the
   * caller's jwtVerify fails closed with JWKS_UNAVAILABLE.
   */
  getKey: JWTVerifyGetKey = async (protectedHeader, token) => {
    if (this.localSet !== null) {
      try {
        return await this.localSet(protectedHeader, token);
      } catch {
        // Unknown kid or stale cache — one refresh, then retry once.
      }
    }
    await this.refresh();
    if (this.localSet === null) {
      throw new PepError("JWKS_UNAVAILABLE", "JWKS cache is empty");
    }
    return this.localSet(protectedHeader, token);
  };
}
