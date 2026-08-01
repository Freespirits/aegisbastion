/**
 * Authz-context enforcement (doc 05 §13.1 — NON-DEFERRABLE, ships in MVP).
 *
 * Any alert from ddos-engine / ai-redteam, and any `confirmed` vuln/exposure
 * alert, must carry a valid gatekeeper Scope Token. Herald verifies:
 *
 *   1. EdDSA signature against gatekeeper's JWKS (via the SDK JwksCache).
 *   2. occurred_at inside the token's validity window (nbf–exp, 60 s leeway,
 *      doc 11 §7) — NOT "token unexpired at ingest" (Ruling C5 amendment of
 *      §5.7: a token proves the activity was authorized WHEN IT RAN; bus
 *      streams retain 72 h, so alerts legitimately arrive after expiry).
 *      Implemented by evaluating the SDK verification at nowSeconds =
 *      occurred_at.
 *   3. jti == authorization_token_id (the event must point at THIS token).
 *   4. capabilities cover the source module's activity (prefix map aligned
 *      with gatekeeper's capreg, services/gatekeeper/internal/capreg).
 *   5. The alert's asset identifier falls inside the token's target
 *      manifest/scope (exact-enumerated manifests: canonical equality;
 *      scope-bound watch tokens: doc 01 §10.1 evaluation, exclusions win).
 *
 * Every failure quarantines the alert to alerts.dlq with an authz_reject
 * audit record — no token, no notification, no exceptions. When the JWKS
 * itself is unavailable the alert is HELD (not delivered, not rejected) and
 * quarantined only after 15 min with VERIFICATION_UNAVAILABLE (§12).
 */
import { evaluateTargetInScope, fetchAndVerifyManifest, isTargetInManifest, verifyScopeToken, } from "@aegisbastion/agent-sdk";
/** pep-sdk error codes (sdks/ts/src/errors.ts) treated as infrastructure, not rejection. */
const UNAVAILABLE_CODES = new Set(["JWKS_UNAVAILABLE", "MANIFEST_FETCH_FAILED"]);
export function isAuthzUnavailable(err) {
    const code = err?.code;
    return typeof code === "string" && UNAVAILABLE_CODES.has(code);
}
/** §5.2/§13.1: which alerts MUST carry a verifiable authorization context. */
export function requiresAuthorization(event) {
    if (event.source_module === "ddos-engine" || event.source_module === "ai-redteam")
        return true;
    return ((event.category === "vuln" || event.category === "exposure") && event.confidence === "confirmed");
}
/**
 * Module → capability namespaces (gatekeeper capreg alignment, Ruling B.3
 * row for doc 05: "capabilities covers the source module's activity").
 */
const MODULE_CAPABILITY_PREFIXES = {
    detect: ["detect.", "vuln.validate", "scan.active"],
    monitor: ["monitor."],
    discover: ["discover.", "recon."],
    "ddos-engine": ["stress."],
    "ai-redteam": ["ai_redteam.", "redteam."],
    "phish-catcher": ["intel.phishing_indicators", "phish."],
    commander: [], // commander orders are capability-agnostic (§4.2)
};
export function capabilitiesCoverModule(capabilities, module) {
    const prefixes = MODULE_CAPABILITY_PREFIXES[module];
    if (prefixes.length === 0)
        return true;
    return capabilities.some((cap) => prefixes.some((p) => cap === p || cap.startsWith(p)));
}
export class AuthzEnforcer {
    opts;
    cache;
    cacheTtl;
    constructor(opts) {
        this.opts = opts;
        this.cache = opts.manifestCache ?? new Map();
        this.cacheTtl = opts.manifestCacheTtlMs ?? 5 * 60 * 1000;
    }
    /** Warm the JWKS cache at boot; readiness depends on it. */
    async start() {
        await this.opts.jwksCache.start();
    }
    stop() {
        this.opts.jwksCache.stop();
    }
    /**
     * Verify one alert's authorization context. Never throws for rejection
     * cases; infrastructure failures come back as `unavailable` (caller holds
     * and retries per §12) except completely absent verification prerequisites.
     */
    async verify(event, compactToken, now) {
        if (!requiresAuthorization(event)) {
            return { outcome: "not-required" };
        }
        if (!event.authorization_token_id) {
            return {
                outcome: "rejected",
                code: "AUTHZ_TOKEN_ID_MISSING",
                reason: "alert requires an authorization context but carries no authorization_token_id",
            };
        }
        if (!compactToken) {
            return {
                outcome: "rejected",
                code: "AUTHZ_TOKEN_MISSING",
                reason: "alert requires an authorization context but no compact Scope Token was attached",
            };
        }
        const occurredAtSec = Math.floor(Date.parse(event.occurred_at) / 1000);
        if (!Number.isFinite(occurredAtSec)) {
            return { outcome: "rejected", code: "AUTHZ_OCCURRED_AT_INVALID", reason: "unparseable occurred_at" };
        }
        // JWKS-outage detection: the SDK remaps non-jose errors to TOKEN_MALFORMED
        // inside verifyScopeToken, so a failing getKey (gatekeeper down, §12) must
        // be captured HERE to preserve the unavailable/hold semantics.
        let jwksError;
        const guardedGetKey = async (header, token) => {
            try {
                return await this.opts.jwksCache.getKey(header, token);
            }
            catch (err) {
                jwksError = err;
                throw err;
            }
        };
        let claims;
        try {
            // §5.7 (as amended by Ruling C5): the token must have been valid AT
            // occurred_at — evaluate SDK verification with now = occurred_at.
            claims = await verifyScopeToken(compactToken, {
                getKey: guardedGetKey,
                nowSeconds: occurredAtSec,
            });
        }
        catch (err) {
            const code = err.code ?? "TOKEN_INVALID";
            // The SDK maps BOTH "gatekeeper JWKS unreachable" and "fresh JWKS has
            // no key for this kid" to JWKS_UNAVAILABLE (sdks/ts token.ts). Only
            // the no-matching-kid case reaches here with that code: a failed
            // refresh throws out of getKey first (captured above as jwksError and
            // remapped by the SDK to TOKEN_MALFORMED). A successfully refreshed
            // JWKS without the kid means a forged/unknown signing key — a §13.1
            // rejection, NOT the §12 hold-and-quarantine path.
            if (code === "JWKS_UNAVAILABLE" && !isAuthzUnavailable(jwksError)) {
                return {
                    outcome: "rejected",
                    code: "AUTHZ_UNKNOWN_SIGNING_KEY",
                    reason: `no gatekeeper signing key matches the token kid: ${err.message}`,
                };
            }
            if (isAuthzUnavailable(err) || isAuthzUnavailable(jwksError)) {
                return { outcome: "unavailable", reason: `verification unavailable: ${err.message}` };
            }
            return {
                outcome: "rejected",
                code: `AUTHZ_${code}`,
                reason: err.message,
            };
        }
        if (claims.jti !== event.authorization_token_id) {
            return {
                outcome: "rejected",
                code: "AUTHZ_JTI_MISMATCH",
                reason: "token jti does not match the alert's authorization_token_id",
            };
        }
        if (!capabilitiesCoverModule(claims.capabilities, event.source_module)) {
            return {
                outcome: "rejected",
                code: "AUTHZ_CAPABILITY_MISMATCH",
                reason: `token capabilities [${claims.capabilities.join(", ")}] do not cover ${event.source_module} activity`,
            };
        }
        // Target/scope containment of the alerted asset (§13.1 item 4).
        try {
            const manifest = await this.verifiedManifest(claims);
            const identifier = event.asset.identifier;
            const inside = manifest.form === "exact"
                ? isTargetInManifest(identifier, manifest.targets)
                : evaluateTargetInScope(identifier, manifest.manifest.scope).allow;
            if (!inside) {
                return {
                    outcome: "rejected",
                    code: "AUTHZ_TARGET_OUT_OF_SCOPE",
                    reason: `asset identifier ${identifier} is outside the token's target manifest/scope`,
                };
            }
        }
        catch (err) {
            if (isAuthzUnavailable(err)) {
                return { outcome: "unavailable", reason: `manifest verification unavailable: ${err.message}` };
            }
            const code = err.code ?? "MANIFEST_INVALID";
            return { outcome: "rejected", code: `AUTHZ_${code}`, reason: err.message };
        }
        // Belt-and-braces: occurred_at must ALSO not be implausibly stale (beyond
        // the token window the SDK already enforced; nothing further here).
        void now;
        return { outcome: "verified", claims };
    }
    async verifiedManifest(claims) {
        const key = claims.targets.manifest_sha256;
        const hit = this.cache.get(key);
        const nowMs = Date.now();
        if (hit && nowMs - hit.at < this.cacheTtl)
            return hit.manifest;
        const manifest = await fetchAndVerifyManifest(claims.targets, claims.scope_bound === true, this.opts.manifestFetcher);
        this.cache.set(key, { at: nowMs, manifest });
        return manifest;
    }
}
