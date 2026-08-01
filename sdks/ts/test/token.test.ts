/**
 * Scope Token verification guarantee matrix (doc 01 §5.5, doc 11 §3.2/§7;
 * Ruling C5; Phase-0 exit gate: "forged token → SDK refuses target contact").
 */

import { describe, expect, it } from "vitest";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { create } from "@bufbuild/protobuf";
import { JsonWebKeySchema } from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";
import { JwksCache } from "../src/jwks.js";
import { PepError } from "../src/errors.js";
import { verifyScopeToken, MAX_TOKEN_TTL_SECONDS } from "../src/token.js";
import { makeKey, signToken, NOW, type TestKey } from "./helpers.js";

async function makeJwks(key: TestKey): Promise<JwksCache> {
  const cache = new JwksCache({ fetchKeys: async () => [key.publicJwk] });
  await cache.start();
  return cache;
}

describe("verifyScopeToken", () => {
  it("accepts a valid token and returns its claims", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { capabilities: ["detect.scan.web"], risk_class: "R2" });
    const claims = await verifyScopeToken(token, {
      getKey: jwks.getKey,
      expectedTaskId: "tsk_01J92H",
      nowSeconds: NOW,
    });
    expect(claims.jti).toBe("tok_01J9ZM8W3F");
    expect(claims.task_id).toBe("tsk_01J92H");
    expect(claims.risk_class).toBe("R2");
    expect(claims.targets.manifest_sha256).toBe("a".repeat(64));
    jwks.stop();
  });

  it("rejects a forged token (signed by a non-gatekeeper key)", async () => {
    const gatekeeperKey = await makeKey("gk-a");
    const attackerKey = await makeKey("gk-a"); // same kid, different key
    const jwks = await makeJwks(gatekeeperKey);
    const forged = await signToken(attackerKey);
    await expect(
      verifyScopeToken(forged, { getKey: jwks.getKey, nowSeconds: NOW }),
    ).rejects.toMatchObject({ code: "TOKEN_SIGNATURE_INVALID" } satisfies Partial<PepError>);
    jwks.stop();
  });

  it("rejects an expired token", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { iat: NOW - 2000, nbf: NOW - 2000, exp: NOW - 1200 });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_EXPIRED",
    });
    jwks.stop();
  });

  it("rejects a wrong-audience token", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { aud: "aegisbastion.commanders" });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_AUDIENCE_INVALID",
    });
    jwks.stop();
  });

  it("rejects a wrong-issuer token", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { iss: "attacker.platform" });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_ISSUER_INVALID",
    });
    jwks.stop();
  });

  it("rejects a TTL over 15 minutes (Ruling C5)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { iat: NOW, nbf: NOW, exp: NOW + MAX_TOKEN_TTL_SECONDS + 1 });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_TTL_EXCEEDED",
    });
    jwks.stop();
  });

  it("rejects iat more than 120s in the future (skew/tamper, doc 11 §7)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { iat: NOW + 600, nbf: NOW - 10, exp: NOW + 900 });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_NOT_YET_VALID",
    });
    jwks.stop();
  });

  it("rejects nbf beyond the 60s leeway", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { iat: NOW, nbf: NOW + 300, exp: NOW + 900 });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_NOT_YET_VALID",
    });
    jwks.stop();
  });

  it("rejects a token bound to a different task_id (single-purpose)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { task_id: "tsk_OTHER" });
    await expect(
      verifyScopeToken(token, { getKey: jwks.getKey, expectedTaskId: "tsk_01J92H", nowSeconds: NOW }),
    ).rejects.toMatchObject({ code: "TOKEN_TASK_MISMATCH" });
    jwks.stop();
  });

  it("rejects a non-EdDSA algorithm", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const { privateKey } = await generateKeyPair("ES256");
    const token = await new SignJWT({ iss: "gatekeeper.platform", aud: "aegisbastion.modules" })
      .setProtectedHeader({ alg: "ES256", kid: key.kid })
      .sign(privateKey);
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_SIGNATURE_INVALID",
    });
    jwks.stop();
  });

  it("rejects a missing token", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    await expect(verifyScopeToken("", { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_MISSING",
    });
    jwks.stop();
  });

  it("rejects malformed claims (bad manifest hash form)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, {
      targets: { hash_alg: "sha256", manifest_uri: "blob://b/k", manifest_sha256: "ZZZ" },
    });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_MALFORMED",
    });
    jwks.stop();
  });

  it("rejects R0 / unknown risk classes — tokens exist only for R1–R3", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { risk_class: "R0" });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_RISK_CLASS_INVALID",
    });
    jwks.stop();
  });

  it("rejects scope_bound on an R2 token (Ruling A narrow applicability)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, {
      scope_bound: true,
      risk_class: "R2",
      capabilities: ["monitor.watch"],
    });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_SCOPE_BOUND_MISUSE",
    });
    jwks.stop();
  });

  it("rejects scope_bound for a non-watch capability", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, {
      scope_bound: true,
      risk_class: "R1",
      capabilities: ["detect.scan.web"],
    });
    await expect(verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "TOKEN_SCOPE_BOUND_MISUSE",
    });
    jwks.stop();
  });

  it("accepts a well-formed scope_bound watch token (R1 monitor.watch)", async () => {
    const key = await makeKey("gk-a");
    const jwks = await makeJwks(key);
    const token = await signToken(key, { scope_bound: true, risk_class: "R1" });
    const claims = await verifyScopeToken(token, { getKey: jwks.getKey, nowSeconds: NOW });
    expect(claims.scope_bound).toBe(true);
    jwks.stop();
  });
});

describe("JwksCache", () => {
  it("fails closed when the JWKS has no Ed25519 keys", async () => {
    const { publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = await exportJWK(publicKey);
    const cache = new JwksCache({
      fetchKeys: async () => [
        create(JsonWebKeySchema, {
          kty: jwk.kty ?? "EC",
          crv: "P-256",
          kid: "es-1",
          alg: "ES256",
          use: "sig",
          x: jwk.x ?? "",
        }),
      ],
    });
    await expect(cache.start()).rejects.toMatchObject({ code: "JWKS_UNAVAILABLE" });
  });

  it("refreshes once on unknown kid (key rotation) then verifies", async () => {
    const oldKey = await makeKey("gk-old");
    const newKey = await makeKey("gk-new");
    let fetches = 0;
    const cache = new JwksCache({
      fetchKeys: async () => {
        fetches += 1;
        return fetches === 1 ? [oldKey.publicJwk] : [oldKey.publicJwk, newKey.publicJwk];
      },
    });
    await cache.start();
    const token = await signToken(newKey);
    const claims = await verifyScopeToken(token, { getKey: cache.getKey, nowSeconds: NOW });
    expect(claims.jti).toBe("tok_01J9ZM8W3F");
    expect(fetches).toBeGreaterThanOrEqual(2);
    cache.stop();
  });

  it("fails closed when the kid never appears in the JWKS", async () => {
    const gatekeeperKey = await makeKey("gk-a");
    const strangerKey = await makeKey("gk-stranger");
    const cache = new JwksCache({ fetchKeys: async () => [gatekeeperKey.publicJwk] });
    await cache.start();
    const token = await signToken(strangerKey);
    await expect(verifyScopeToken(token, { getKey: cache.getKey, nowSeconds: NOW })).rejects.toMatchObject({
      code: "JWKS_UNAVAILABLE",
    });
    cache.stop();
  });
});
