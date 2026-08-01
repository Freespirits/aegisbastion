/**
 * JCS (RFC 8785) canonicalization + audit-chain helpers (doc 01 §10.2/§5.9).
 */

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { auditChainHash, jcs, scopeHashCheckpoint, sha256JcsHex } from "../src/jcs.js";

describe("jcs (RFC 8785)", () => {
  it("sorts object keys recursively", () => {
    expect(jcs({ b: 1, a: [{ d: null, c: true }, 2] })).toBe('{"a":[{"c":true,"d":null},2],"b":1}');
  });

  it("serializes numbers per the ES2022 number-to-string rules", () => {
    expect(jcs({ n: [333333333.33333329, 1e30, 4.5, 2e-3] })).toBe(
      '{"n":[333333333.3333333,1e+30,4.5,0.002]}',
    );
  });

  it("escapes strings minimally and keeps unicode literal", () => {
    expect(jcs({ s: '€A"B\\C' })).toBe('{"s":"€A\\"B\\\\C"}');
  });

  it("is deterministic across key insertion orders", () => {
    const a = jcs({ x: 1, y: { p: 2, q: 3 } });
    const b = jcs({ y: { q: 3, p: 2 }, x: 1 });
    expect(a).toBe(b);
  });
});

describe("scopeHashCheckpoint (Ruling A.3/A.4)", () => {
  it("formats the scope:sha256:<hash> audit value", () => {
    expect(scopeHashCheckpoint("AB" + "0".repeat(62))).toBe(`scope:sha256:ab${"0".repeat(62)}`);
  });
});

describe("auditChainHash (doc 01 §5.9)", () => {
  it("computes sha256:hex(prev_hash || JCS(event))", () => {
    const event = { event_id: "aud_1", seq: 1, type: "TARGET_TOUCHED" };
    const expected =
      "sha256:" + createHash("sha256").update("sha256:prev123" + jcs(event)).digest("hex");
    expect(auditChainHash(event, "sha256:prev123")).toBe(expected);
  });

  it("genesis events use an empty prev_hash", () => {
    const event = { event_id: "aud_0" };
    const expected = "sha256:" + createHash("sha256").update(jcs(event)).digest("hex");
    expect(auditChainHash(event, "")).toBe(expected);
  });

  it("sha256JcsHex matches the manifest-hash discipline", () => {
    const doc = { roe_id: "roe_1", scope: { domains: ["acme.com"], cidrs: [], explicit_excludes: [] } };
    expect(sha256JcsHex(doc)).toBe(createHash("sha256").update(jcs(doc)).digest("hex"));
  });
});
