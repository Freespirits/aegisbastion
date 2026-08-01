/**
 * Authz-context enforcement (doc 05 §13.1 — NON-DEFERRABLE). Fail-closed
 * matrix: forged signature, token window not covering occurred_at, jti
 * mismatch, capability mismatch, out-of-scope asset, missing token — every
 * one rejected. Plus the Ruling C5 semantics: a token proves the activity was
 * authorized WHEN IT RAN, so a token expired at ingest time still verifies
 * when occurred_at fell inside its validity window.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { JwksCache } from "@aegisbastion/agent-sdk";
import { AuthzEnforcer, capabilitiesCoverModule, requiresAuthorization } from "../src/authz/enforce.js";
import { exactManifestFetcher, makeKeys, mintToken, offensiveEvent, sampleEvent } from "./helpers.js";

const keys = makeKeys("gk-key-1");
const otherKeys = makeKeys("gk-key-1"); // same kid, different material → forgery

const manifest = exactManifestFetcher(["api.example.com"]);

async function makeEnforcer(): Promise<AuthzEnforcer> {
  const jwksCache = new JwksCache({ fetchKeys: async () => [keys.publicJwk] });
  await jwksCache.start();
  const enforcer = new AuthzEnforcer({ jwksCache, manifestFetcher: manifest.fetcher });
  return enforcer;
}

let enforcer: AuthzEnforcer;
beforeAll(async () => {
  enforcer = await makeEnforcer();
});

describe("requiresAuthorization (§5.2/§13.1)", () => {
  it("ddos-engine / ai-redteam always require a context", () => {
    expect(requiresAuthorization(sampleEvent({ source_module: "ddos-engine" }))).toBe(true);
    expect(requiresAuthorization(sampleEvent({ source_module: "ai-redteam" }))).toBe(true);
  });
  it("confirmed vuln/exposure requires a context", () => {
    expect(requiresAuthorization(sampleEvent({ category: "vuln", confidence: "confirmed" }))).toBe(true);
    expect(requiresAuthorization(sampleEvent({ category: "exposure", confidence: "confirmed" }))).toBe(true);
  });
  it("passive monitor alerts do not", () => {
    expect(requiresAuthorization(sampleEvent())).toBe(false);
  });
});

describe("capabilitiesCoverModule", () => {
  it("prefix match", () => {
    expect(capabilitiesCoverModule(["detect.nuclei"], "detect")).toBe(true);
    expect(capabilitiesCoverModule(["stress.http_flood"], "ddos-engine")).toBe(true);
    expect(capabilitiesCoverModule(["discover.passive"], "detect")).toBe(false);
    expect(capabilitiesCoverModule([], "commander")).toBe(true);
  });
});

describe("AuthzEnforcer.verify — fail-closed matrix", () => {
  const occurredAt = new Date().toISOString();

  it("not-required alerts skip verification entirely", async () => {
    const verdict = await enforcer.verify(sampleEvent(), undefined, new Date());
    expect(verdict.outcome).toBe("not-required");
  });

  it("missing authorization_token_id → rejected", async () => {
    const event = offensiveEvent({ authorization_token_id: undefined, occurred_at: occurredAt });
    const verdict = await enforcer.verify(event, undefined, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_TOKEN_ID_MISSING" });
  });

  it("missing compact token → rejected", async () => {
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), undefined, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_TOKEN_MISSING" });
  });

  it("forged signature (same kid, wrong key) → rejected TOKEN_SIGNATURE_INVALID", async () => {
    const forged = await mintToken(otherKeys, { manifestSha256: manifest.sha256 });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), forged, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_TOKEN_SIGNATURE_INVALID" });
  });

  it("unknown kid (fresh JWKS has no such key) → rejected AUTHZ_UNKNOWN_SIGNING_KEY, not held", async () => {
    const foreignKeys = makeKeys("gk-rotated-away");
    const forged = await mintToken(foreignKeys, { manifestSha256: manifest.sha256 });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), forged, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_UNKNOWN_SIGNING_KEY" });
  });

  it("token validity window not covering occurred_at → rejected TOKEN_EXPIRED", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await mintToken(keys, {
      iat: nowSec - 3600,
      exp: nowSec - 2700, // expired 45 min ago — window does not cover occurred_at=now
      manifestSha256: manifest.sha256,
    });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), token, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_TOKEN_EXPIRED" });
  });

  it("jti mismatch between event and token → rejected", async () => {
    const token = await mintToken(keys, { jti: "tok_other", manifestSha256: manifest.sha256 });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), token, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_JTI_MISMATCH" });
  });

  it("capability mismatch → rejected", async () => {
    const token = await mintToken(keys, { capabilities: ["discover.passive"], manifestSha256: manifest.sha256 });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), token, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_CAPABILITY_MISMATCH" });
  });

  it("asset outside the target manifest → rejected", async () => {
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const event = offensiveEvent({ occurred_at: occurredAt, asset: { asset_id: "a9", kind: "subdomain", identifier: "evil.example.com" } });
    const verdict = await enforcer.verify(event, token, new Date());
    expect(verdict).toMatchObject({ outcome: "rejected", code: "AUTHZ_TARGET_OUT_OF_SCOPE" });
  });

  it("valid token + in-scope asset → verified", async () => {
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredAt }), token, new Date());
    expect(verdict.outcome).toBe("verified");
    if (verdict.outcome === "verified") expect(verdict.claims.jti).toBe("tok_test01");
  });

  it("Ruling C5: token expired at INGEST time still verifies when occurred_at was inside the window", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const iat = nowSec - 1800;
    const token = await mintToken(keys, {
      capabilities: ["detect.nuclei"],
      iat,
      exp: iat + 900, // expired 15 min ago
      manifestSha256: manifest.sha256,
    });
    // The alert is about activity that ran while the token was valid.
    const occurredInsideWindow = new Date((iat + 600) * 1000).toISOString();
    const verdict = await enforcer.verify(offensiveEvent({ occurred_at: occurredInsideWindow }), token, new Date());
    expect(verdict.outcome).toBe("verified");
  });

  it("JWKS outage → unavailable (hold, not rejection)", async () => {
    const deadCache = new JwksCache({
      fetchKeys: async () => {
        throw new Error("connection refused");
      },
    });
    // No start(): cache empty → getKey refreshes → JWKS_UNAVAILABLE.
    const down = new AuthzEnforcer({ jwksCache: deadCache, manifestFetcher: manifest.fetcher });
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const verdict = await down.verify(offensiveEvent({ occurred_at: occurredAt }), token, new Date());
    expect(verdict.outcome).toBe("unavailable");
  });
});
