/**
 * phish-intel (doc 07 §4.4/§8.6/§9): SHA-256 vectors, Bloom + exact-hash
 * confirmation, JCS, Ed25519 sign/verify, bundle & policy verification
 * (accept/reject/rollback/stale/rotation), IntelStore last-good semantics.
 */

import { describe, expect, it } from "vitest";
import { utf8ToBytes, bytesToUtf8, base64ToBytes, bytesToBase64 } from "../src/intel/base64.js";
import { sha256, sha256Hex } from "../src/intel/sha256.js";
import { jcs } from "../src/intel/jcs.js";
import {
  generateEd25519Keypair,
  importPinnedPublicKey,
  importPrivateKeyPkcs8,
  signBytes,
  verifyBytes,
} from "../src/intel/ed25519.js";
import { BloomFilter, ExactHashTable, blocklistEntry } from "../src/intel/bloom.js";
import {
  bundleIsStale,
  compareBundleVersions,
  validateIntelBundle,
  type IntelBundle,
} from "../src/intel/bundle.js";
import { verifyIntelBundle, verifyPolicyConfig } from "../src/intel/verify.js";
import { IntelStore } from "../src/intel/store.js";
import { normalizeUrlForHash } from "../src/url/parse.js";
import {
  buildSignedBundle,
  makeKeypair,
  policyBody,
  signDocument,
} from "./helpers.js";

describe("sha256 (pure TS, sync for reputation checks)", () => {
  it("matches FIPS 180-4 vectors", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("cross-checks against WebCrypto", async () => {
    const data = utf8ToBytes("aegisbastion phish-catcher");
    const web = new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
    expect(Buffer.from(sha256(data)).equals(Buffer.from(web))).toBe(true);
  });
});

describe("base64 helpers", () => {
  it("round-trips", () => {
    const bytes = utf8ToBytes("hello aegisbastion ✓");
    expect(bytesToUtf8(base64ToBytes(bytesToBase64(bytes)))).toBe("hello aegisbastion ✓");
  });
});

describe("jcs (RFC 8785, doc 01 §10.2)", () => {
  it("canonicalizes key order and whitespace", () => {
    expect(jcs({ b: 1, a: { d: [1, 2], c: "x" } })).toBe('{"a":{"c":"x","d":[1,2]},"b":1}');
  });
});

describe("ed25519 (WebCrypto)", () => {
  it("signs and verifies; wrong key fails", async () => {
    const keys = await generateEd25519Keypair();
    const other = await generateEd25519Keypair();
    const priv = await importPrivateKeyPkcs8(keys.privateKeyPkcs8);
    const pub = await importPinnedPublicKey(keys.publicKey);
    const wrongPub = await importPinnedPublicKey(other.publicKey);
    const payload = utf8ToBytes(jcs({ hello: "world" }));
    const sig = await signBytes(priv, payload);
    expect(await verifyBytes(pub, sig, payload)).toBe(true);
    expect(await verifyBytes(wrongPub, sig, payload)).toBe(false);
    expect(await verifyBytes(pub, sig, utf8ToBytes(jcs({ hello: "tampered" })))).toBe(false);
  });
});

describe("bloom + exact-hash confirmation (§3.2)", () => {
  it("finds every inserted item and confirms via the exact table", () => {
    const entries = ["d:evil.tk", "u:http://evil.tk/x", "s:scam@evil.tk"];
    const bloom = BloomFilter.create(entries.length, 0.001);
    for (const e of entries) bloom.add(e);
    const exact = ExactHashTable.fromHexList(entries.map((e) => sha256Hex(e)));
    for (const e of entries) {
      expect(bloom.has(e)).toBe(true);
      expect(exact.hasDigest(sha256(utf8ToBytes(e)))).toBe(true);
    }
  });

  it("removes false positives: bloom positive without exact confirm → not blocklisted", () => {
    const bloom = BloomFilter.create(4, 0.2); // tiny, deliberately fp-prone
    bloom.add("d:evil.tk");
    const emptyExact = ExactHashTable.fromHexList([]);
    // Any bloom hit that is NOT in the exact table must not confirm.
    const victims = Array.from({ length: 500 }, (_, i) => `d:legit-${i}.com`);
    const bloomHits = victims.filter((v) => bloom.has(v));
    for (const v of bloomHits) {
      expect(emptyExact.hasDigest(sha256(utf8ToBytes(v)))).toBe(false);
    }
    // And the confirmed path requires BOTH (mirrors IntelStore.confirmed).
    const confirmed = (e: string) => bloom.has(e) && emptyExact.hasDigest(sha256(utf8ToBytes(e)));
    expect(victims.some(confirmed)).toBe(false);
  });

  it("round-trips the wire format", () => {
    const bloom = BloomFilter.create(10);
    bloom.add("d:evil.tk");
    const parsed = BloomFilter.fromBase64(bloom.toBase64());
    expect(parsed.has("d:evil.tk")).toBe(true);
    expect(parsed.has("d:other.com")).toBe(false);
    expect(() => BloomFilter.fromBase64(bytesToBase64(utf8ToBytes("garbage")))).toThrow();
  });
});

describe("bundle version + staleness", () => {
  it("compares monotonic versions", () => {
    expect(compareBundleVersions("2026.07.30-2", "2026.07.30-1")).toBe(1);
    expect(compareBundleVersions("2026.07.30-1", "2026.07.30-2")).toBe(-1);
    expect(compareBundleVersions("2026.07.30-1", "2026.07.30-1")).toBe(0);
    expect(compareBundleVersions("2026.08.01-1", "2026.07.30-9")).toBe(1);
  });

  it("marks bundles stale past 14 days or expiresAt (§9)", () => {
    const now = new Date("2026-07-30T00:00:00Z");
    expect(bundleIsStale({ issuedAt: "2026-07-29T00:00:00Z", expiresAt: "2026-08-30T00:00:00Z" }, now)).toBe(false);
    expect(bundleIsStale({ issuedAt: "2026-07-15T00:00:00Z", expiresAt: "2026-08-30T00:00:00Z" }, now)).toBe(true);
    expect(bundleIsStale({ issuedAt: "2026-07-29T00:00:00Z", expiresAt: "2026-07-29T12:00:00Z" }, now)).toBe(true);
  });
});

describe("bundle signature verification (§4.4)", () => {
  it("accepts a properly signed bundle and answers blocklist lookups", async () => {
    const keys = await makeKeypair();
    const bundle = await buildSignedBundle(keys, {
      domains: ["evil.tk"],
      urls: [normalizeUrlForHash("http://evil.tk/steal")],
      senders: ["scam@evil.tk"],
    });
    const res = await verifyIntelBundle(bundle, { pinnedKeys: [keys.publicKey] });
    expect(res.ok).toBe(true);
    expect(res.stale).toBe(false);

    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    expect((await store.applyBundle(bundle)).applied).toBe(true);
    expect(store.isDomainBlocklisted("evil.tk")).toBe(true);
    expect(store.isUrlBlocklisted("http://evil.tk/steal")).toBe(true);
    expect(store.isSenderBlocklisted("scam@evil.tk")).toBe(true);
    expect(store.isDomainBlocklisted("example.com")).toBe(false);
    expect(store.degraded()).toBe(false);
  });

  it("rejects a tampered bundle (SIGNATURE_INVALID) and keeps last good", async () => {
    const keys = await makeKeypair();
    const good = await buildSignedBundle(keys, { domains: ["evil.tk"] });
    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    await store.applyBundle(good);

    const tampered = { ...(await buildSignedBundle(keys, { version: "2026.07.30-2" })), brandDomains: ["trojan.example"] } as unknown as IntelBundle;
    const res = await store.applyBundle(tampered);
    expect(res.applied).toBe(false);
    expect(res.reason).toBe("SIGNATURE_INVALID");
    expect(res.integrityFailure).toBe(true);
    expect(store.bundleVersion()).toBe("2026.07.30-1"); // last good retained (§9)
    expect(store.isDomainBlocklisted("evil.tk")).toBe(true);
  });

  it("rejects signatures from untrusted keys", async () => {
    const keys = await makeKeypair();
    const attacker = await makeKeypair();
    const bundle = await buildSignedBundle(attacker, {});
    const res = await verifyIntelBundle(bundle, { pinnedKeys: [keys.publicKey] });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("SIGNATURE_INVALID");
    const noPins = await verifyIntelBundle(bundle, { pinnedKeys: [] });
    expect(noPins.reason).toBe("UNTRUSTED_KEY");
  });

  it("rejects rollbacks (monotonic version pinning)", async () => {
    const keys = await makeKeypair();
    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    await store.applyBundle(await buildSignedBundle(keys, { version: "2026.07.30-2" }));
    const older = await buildSignedBundle(keys, { version: "2026.07.30-1" });
    const res = await store.applyBundle(older);
    expect(res.applied).toBe(false);
    expect(res.reason).toBe("ROLLBACK");
    expect(res.integrityFailure).toBe(true);
    const same = await buildSignedBundle(keys, { version: "2026.07.30-2" });
    expect((await store.applyBundle(same)).reason).toBe("ROLLBACK");
  });

  it("rejects schema-invalid bundles fail-closed", () => {
    const errors = validateIntelBundle({ schemaVersion: 2, bundleVersion: "x" });
    expect(errors.length).toBeGreaterThan(0);
  });

  it("accepts stale-but-valid bundles as degraded (§9)", async () => {
    const keys = await makeKeypair();
    const bundle = await buildSignedBundle(keys, {
      issuedAt: new Date(Date.now() - 20 * 24 * 3600_000).toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 3600_000).toISOString(),
    });
    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    const res = await store.applyBundle(bundle);
    expect(res.applied).toBe(true);
    expect(res.stale).toBe(true);
    expect(store.degraded()).toBe(true);
  });

  it("adopts a dual-signed rotation key and rejects a bogus one (§8.6)", async () => {
    const keys = await makeKeypair();
    const next = await makeKeypair();
    const priv = await importPrivateKeyPkcs8(keys.privateKeyPkcs8);
    const rotationSignature = await signBytes(priv, utf8ToBytes(jcs({ publicKey: next.publicKey })));

    const withRotation = await buildSignedBundle(keys, {
      nextKey: { publicKey: next.publicKey, signature: rotationSignature },
    });
    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    const res = await store.applyBundle(withRotation);
    expect(res.applied).toBe(true);
    expect(res.rotationAdopted).toBe(next.publicKey);
    expect(store.pinnedKeys()).toContain(next.publicKey);

    // A bundle signed by the ROTATED key now verifies (version bump).
    const followup = await buildSignedBundle(next, { version: "2026.07.31-1" });
    expect((await store.applyBundle(followup)).applied).toBe(true);

    // Bogus rotation (nextKey not signed by the bundle's key) is rejected —
    // the bundle signature itself is valid, so the failure is the rotation.
    const bogus = await buildSignedBundle(keys, {
      version: "2026.08.01-1",
      nextKey: { publicKey: next.publicKey, signature: rotationSignature.slice(0, -4) + "AAAA" },
    });
    const bogusRes = await store.applyBundle(bogus);
    expect(bogusRes.applied).toBe(false);
    expect(bogusRes.reason).toBe("ROTATION_SIGNATURE_INVALID");
  });
});

describe("policy verification (§4.3/§5.2)", () => {
  it("accepts a signed fresh policy", async () => {
    const keys = await makeKeypair();
    const policy = await signDocument(keys, policyBody());
    const res = await verifyPolicyConfig(policy, { pinnedKeys: [keys.publicKey] });
    expect(res.ok).toBe(true);
  });

  it("rejects unsigned / expired / rolled-back policies", async () => {
    const keys = await makeKeypair();
    const unsigned = await verifyPolicyConfig(policyBody(), { pinnedKeys: [keys.publicKey] });
    expect(unsigned.reason).toBe("SIGNATURE_MISSING");

    const expired = await signDocument(keys, policyBody({ expiresAt: new Date(Date.now() - 1000).toISOString() }));
    expect((await verifyPolicyConfig(expired, { pinnedKeys: [keys.publicKey] })).reason).toBe("POLICY_EXPIRED");

    const store = new IntelStore({ pinnedKeys: [keys.publicKey] });
    await store.applyPolicy(await signDocument(keys, policyBody({ policyVersion: 7 })));
    const rollback = await signDocument(keys, policyBody({ policyVersion: 6 }));
    expect((await store.applyPolicy(rollback)).reason).toBe("ROLLBACK");
    expect(store.policy().policyVersion).toBe(7); // last good retained
  });

  it("falls back to compiled-in defaults when the policy expires (§9)", async () => {
    const keys = await makeKeypair();
    let now = new Date("2026-07-01T00:00:00Z");
    const store = new IntelStore({ pinnedKeys: [keys.publicKey], now: () => now });
    await store.applyPolicy(await signDocument(keys, policyBody({
      policyVersion: 3,
      expiresAt: "2026-07-10T00:00:00Z",
      thresholds: { malicious: 90, suspicious: 50 },
    })));
    expect(store.policy().thresholds.malicious).toBe(90);
    now = new Date("2026-08-01T00:00:00Z"); // past expiry
    expect(store.policy().thresholds.malicious).toBe(70); // compiled-in safe defaults
  });
});
