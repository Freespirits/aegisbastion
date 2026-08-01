/**
 * End-to-end PEP guardrail matrix (PEP-2, Ruling B.2): token → manifest →
 * per-target checks, scope-bound evaluation, rate caps, revocation — all
 * fail-closed.
 */

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { Pep } from "../src/pep.js";
import { JwksCache } from "../src/jwks.js";
import { RevocationCache } from "../src/revocation.js";
import type { ManifestFetcher } from "../src/manifest.js";
import { makeKey, signToken, NOW, type TestKey } from "./helpers.js";
import { RevocationScope } from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";
import { create } from "@bufbuild/protobuf";
import { RevocationSchema } from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";

const EXACT_TARGETS = ["https://api.acme.com/graphql", "203.0.113.10"];
const exactBytes = JSON.stringify(EXACT_TARGETS);

const scopeDoc = JSON.stringify({
  roe_id: "roe_01J8ZM",
  roe_version: 3,
  scope: {
    domains: ["*.acme.com", "acme.com"],
    cidrs: ["203.0.113.0/24"],
    explicit_excludes: ["legacy.acme.com", "203.0.113.50"],
  },
});

function refFor(bytes: string, uri = "blob://token-manifests/tok/targets.json") {
  return {
    hash_alg: "sha256",
    manifest_uri: uri,
    manifest_sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

const fetcherFor = (bytes: string): ManifestFetcher => ({
  fetch: async () => new TextEncoder().encode(bytes),
});

async function makePep(
  key: TestKey,
  bytes: string,
  revocations = new RevocationCache(),
): Promise<Pep> {
  const jwks = new JwksCache({ fetchKeys: async () => [key.publicJwk] });
  await jwks.start();
  return new Pep({ jwks, manifestFetcher: fetcherFor(bytes), revocations, nowSeconds: () => NOW });
}

describe("Pep — exact-enumerated manifest", () => {
  it("authorizes manifest members and denies non-members", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, exactBytes);
    const token = await signToken(key, {
      risk_class: "R2",
      capabilities: ["detect.scan.web"],
      targets: { ...refFor(exactBytes), count: 2 },
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    expect(() => auth.checkTarget("https://api.acme.com/graphql", "detect.scan.web")).not.toThrow();
    expect(() => auth.checkTarget("https://api.acme.com/admin", "detect.scan.web")).toThrowError(
      expect.objectContaining({ code: "TARGET_NOT_IN_MANIFEST" }),
    );
    expect(() => auth.checkTarget("198.51.100.7", "detect.scan.web")).toThrowError(
      expect.objectContaining({ code: "TARGET_NOT_IN_MANIFEST" }),
    );
  });

  it("denies a capability the token does not grant", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, exactBytes);
    const token = await signToken(key, {
      risk_class: "R2",
      capabilities: ["detect.scan.web"],
      targets: refFor(exactBytes),
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    expect(() => auth.checkTarget("203.0.113.10", "stress.http_flood")).toThrowError(
      expect.objectContaining({ code: "TARGET_NOT_IN_SCOPE" }),
    );
  });

  it("refuses the whole task when the manifest hash is wrong", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, exactBytes);
    const token = await signToken(key, {
      targets: { ...refFor(exactBytes), manifest_sha256: "f".repeat(64) },
    });
    await expect(pep.authorizeTask(token, "tsk_01J92H")).rejects.toMatchObject({
      code: "MANIFEST_HASH_MISMATCH",
    });
  });
});

describe("Pep — scope-bound watch tokens (Ruling A)", () => {
  const scopeUri = "blob://token-manifests/tok/scope.json";

  it("allows in-scope probes and denies out-of-scope ones", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, scopeDoc);
    const token = await signToken(key, {
      scope_bound: true,
      risk_class: "R1",
      capabilities: ["monitor.watch"],
      targets: refFor(scopeDoc, scopeUri),
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    expect(auth.scopeBound).toBe(true);
    expect(() => auth.checkTarget("api.acme.com", "monitor.watch")).not.toThrow();
    expect(() => auth.checkTarget("203.0.113.9", "monitor.watch")).not.toThrow();
    expect(() => auth.checkTarget("evil.example.com", "monitor.watch")).toThrowError(
      expect.objectContaining({ code: "TARGET_NOT_IN_SCOPE" }),
    );
  });

  it("exclusions ALWAYS win, per-probe", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, scopeDoc);
    const token = await signToken(key, {
      scope_bound: true,
      targets: refFor(scopeDoc, scopeUri),
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    expect(() => auth.checkTarget("legacy.acme.com", "monitor.watch")).toThrowError(
      expect.objectContaining({ code: "TARGET_EXCLUDED" }),
    );
    expect(() => auth.checkTarget("203.0.113.50", "monitor.watch")).toThrowError(
      expect.objectContaining({ code: "TARGET_EXCLUDED" }),
    );
  });

  it("enforces embedded rate caps during checks", async () => {
    const key = await makeKey("gk-a");
    const pep = await makePep(key, scopeDoc);
    const token = await signToken(key, {
      scope_bound: true,
      targets: refFor(scopeDoc, scopeUri),
      rate_caps: { max_rps: 1 },
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    auth.checkTarget("a.acme.com", "monitor.watch");
    expect(() => auth.checkTarget("b.acme.com", "monitor.watch")).toThrowError(
      expect.objectContaining({ code: "RATE_LIMITED" }),
    );
  });
});

describe("Pep — revocation interplay (fail-closed)", () => {
  it("denies at authorizeTask time when the RoE is already revoked", async () => {
    const key = await makeKey("gk-a");
    const revocations = new RevocationCache();
    revocations.apply(
      create(RevocationSchema, {
        revocationId: "rev_1",
        scope: RevocationScope.ROE,
        key: "roe_01J8ZM",
      }),
    );
    const pep = await makePep(key, exactBytes, revocations);
    const token = await signToken(key, { targets: refFor(exactBytes), capabilities: ["detect.scan.web"], risk_class: "R2" });
    await expect(pep.authorizeTask(token, "tsk_01J92H")).rejects.toMatchObject({ code: "REVOKED" });
  });

  it("denies a per-target check after a mid-run revocation", async () => {
    const key = await makeKey("gk-a");
    const revocations = new RevocationCache();
    const pep = await makePep(key, exactBytes, revocations);
    const token = await signToken(key, {
      risk_class: "R2",
      capabilities: ["detect.scan.web"],
      targets: refFor(exactBytes),
    });
    const auth = await pep.authorizeTask(token, "tsk_01J92H");
    expect(() => auth.checkTarget("203.0.113.10", "detect.scan.web")).not.toThrow();
    revocations.apply(
      create(RevocationSchema, {
        revocationId: "rev_2",
        scope: RevocationScope.GLOBAL,
        key: "",
      }),
    );
    expect(() => auth.checkTarget("203.0.113.10", "detect.scan.web")).toThrowError(
      expect.objectContaining({ code: "REVOKED" }),
    );
  });
});
