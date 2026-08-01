/**
 * Manifest fetch + verify matrix (doc 01 §5.5, Ruling A.3): hash check before
 * parse, exact vs scope-bound forms, fail-closed on every mismatch.
 */

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  fetchAndVerifyManifest,
  parseManifestUri,
  type ManifestFetcher,
} from "../src/manifest.js";
import type { TargetManifestRef } from "../src/token.js";

function refFor(bytes: string, overrides: Partial<TargetManifestRef> = {}): TargetManifestRef {
  return {
    hash_alg: "sha256",
    manifest_uri: "blob://token-manifests/tok_x/targets.json",
    manifest_sha256: createHash("sha256").update(bytes).digest("hex"),
    ...overrides,
  };
}

const fetcherWith = (bytes: string): ManifestFetcher => ({
  fetch: async () => new TextEncoder().encode(bytes),
});

const scopeDoc = JSON.stringify({
  roe_id: "roe_01J8ZM",
  roe_version: 3,
  resolved_at: "2026-07-30T00:00:00Z",
  scope: {
    domains: ["*.acme.com", "acme.com"],
    cidrs: ["203.0.113.0/24"],
    explicit_excludes: ["legacy.acme.com"],
  },
});

describe("parseManifestUri", () => {
  it("parses blob:// URIs", () => {
    expect(parseManifestUri("blob://token-manifests/tok_1/scope.json")).toEqual({
      bucket: "token-manifests",
      key: "tok_1/scope.json",
    });
  });
  it("rejects non-blob URIs (fail-closed)", () => {
    expect(() => parseManifestUri("https://evil.com/x.json")).toThrow();
    expect(() => parseManifestUri("blob://bucket-only")).toThrow();
  });
});

describe("fetchAndVerifyManifest — exact form", () => {
  it("fetches, verifies the hash, and parses the target list", async () => {
    const bytes = JSON.stringify(["https://api.acme.com", "203.0.113.10"]);
    const m = await fetchAndVerifyManifest(refFor(bytes), false, fetcherWith(bytes));
    expect(m.form).toBe("exact");
    if (m.form === "exact") expect(m.targets).toHaveLength(2);
  });

  it("rejects a hash mismatch BEFORE parsing (tampered manifest)", async () => {
    const bytes = JSON.stringify(["https://attacker.example.com"]);
    await expect(
      fetchAndVerifyManifest(
        refFor(bytes, { manifest_sha256: "0".repeat(64) }),
        false,
        fetcherWith(bytes),
      ),
    ).rejects.toMatchObject({ code: "MANIFEST_HASH_MISMATCH" });
  });

  it("rejects invalid JSON and non-string-array documents", async () => {
    const bad1 = "{not json";
    await expect(fetchAndVerifyManifest(refFor(bad1), false, fetcherWith(bad1))).rejects.toMatchObject(
      { code: "MANIFEST_MALFORMED" },
    );
    const bad2 = JSON.stringify({ nope: true });
    await expect(fetchAndVerifyManifest(refFor(bad2), false, fetcherWith(bad2))).rejects.toMatchObject(
      { code: "MANIFEST_MALFORMED" },
    );
  });

  it("enforces the claimed target count when present", async () => {
    const bytes = JSON.stringify(["a.acme.com"]);
    await expect(
      fetchAndVerifyManifest(refFor(bytes, { count: 5 }), false, fetcherWith(bytes)),
    ).rejects.toMatchObject({ code: "MANIFEST_MALFORMED" });
  });

  it("propagates fetch failures as MANIFEST_FETCH_FAILED (fail-closed)", async () => {
    const down: ManifestFetcher = {
      fetch: async () => {
        throw new Error("connection refused");
      },
    };
    await expect(
      fetchAndVerifyManifest(refFor("[]"), false, down),
    ).rejects.toMatchObject({ code: "MANIFEST_FETCH_FAILED" });
  });
});

describe("fetchAndVerifyManifest — scope-bound form (Ruling A)", () => {
  it("parses the canonical scope document; hash IS the audit value", async () => {
    const m = await fetchAndVerifyManifest(refFor(scopeDoc), true, fetcherWith(scopeDoc));
    expect(m.form).toBe("scope");
    if (m.form === "scope") {
      expect(m.manifest.roe_id).toBe("roe_01J8ZM");
      expect(m.manifest.scope.domains).toContain("*.acme.com");
      expect(m.manifest.scope.explicit_excludes).toContain("legacy.acme.com");
      expect(m.sha256).toBe(createHash("sha256").update(scopeDoc).digest("hex"));
    }
  });

  it("rejects scope documents missing required fields", async () => {
    const missingScope = JSON.stringify({ roe_id: "roe_1", roe_version: 1 });
    await expect(
      fetchAndVerifyManifest(refFor(missingScope), true, fetcherWith(missingScope)),
    ).rejects.toMatchObject({ code: "MANIFEST_MALFORMED" });
    const badRoe = JSON.stringify({
      roe_id: "not-an-roe",
      roe_version: 1,
      scope: { domains: [], cidrs: [], explicit_excludes: [] },
    });
    await expect(
      fetchAndVerifyManifest(refFor(badRoe), true, fetcherWith(badRoe)),
    ).rejects.toMatchObject({ code: "MANIFEST_MALFORMED" });
  });

  it("rejects unknown hash algorithms", async () => {
    await expect(
      fetchAndVerifyManifest(refFor(scopeDoc, { hash_alg: "md5" as never }), true, fetcherWith(scopeDoc)),
    ).rejects.toMatchObject({ code: "MANIFEST_MALFORMED" });
  });
});
