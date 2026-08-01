/**
 * Revocation cache + control.kill decoding (doc 11 §7, Ruling C11):
 * scoped revocations, temporary-expiry lift, idempotency, and the fail-safe
 * global kill on unparseable broadcasts.
 */

import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  RevocationEventSchema,
  RevocationSchema,
  RevocationScope,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";
import { decodeControlKill, RevocationCache } from "../src/revocation.js";
import { newEnvelope, encodeEnvelope } from "../src/envelope.js";
import type { ScopeTokenClaims } from "../src/token.js";

const claims = (over: Partial<ScopeTokenClaims> = {}): ScopeTokenClaims => ({
  iss: "gatekeeper.platform",
  aud: "aegisbastion.modules",
  jti: "tok_1",
  sub: "agent_1",
  task_id: "tsk_1",
  roe_id: "roe_1",
  roe_version: 1,
  risk_class: "R1",
  capabilities: ["monitor.watch"],
  targets: { hash_alg: "sha256", manifest_uri: "blob://b/k", manifest_sha256: "a".repeat(64) },
  iat: 0,
  exp: 0,
  ...over,
});

const revocation = (
  scope: RevocationScope,
  key: string,
  over: Record<string, unknown> = {},
) =>
  create(RevocationSchema, {
    revocationId: `rev_${scope}_${key}_${Math.random().toString(36).slice(2)}`,
    scope,
    key,
    issuedBy: "op_jane",
    reason: "test",
    ...over,
  });

describe("RevocationCache", () => {
  it("GLOBAL revocation halts everything", () => {
    const c = new RevocationCache();
    c.apply(revocation(RevocationScope.GLOBAL, ""));
    expect(c.check(claims())).toMatchObject({ kind: "global" });
    expect(() => c.assertNotRevoked(claims())).toThrowError(
      expect.objectContaining({ code: "REVOKED" }),
    );
  });

  it("ROE revocation halts only tasks under that RoE", () => {
    const c = new RevocationCache();
    c.apply(revocation(RevocationScope.ROE, "roe_1"));
    expect(c.check(claims({ roe_id: "roe_1" }))).toMatchObject({ kind: "roe", roeId: "roe_1" });
    expect(c.check(claims({ roe_id: "roe_2" }))).toBeNull();
  });

  it("TARGET revocation matches canonicalized targets", () => {
    const c = new RevocationCache();
    c.apply(revocation(RevocationScope.TARGET, "HTTPS://API.Acme.COM:443/graphql"));
    expect(c.check(claims(), "https://api.acme.com/graphql")).toMatchObject({ kind: "target" });
    expect(c.check(claims(), "https://api.acme.com/other")).toBeNull();
  });

  it("CAPABILITY revocation matches token capabilities and explicit checks", () => {
    const c = new RevocationCache();
    c.apply(revocation(RevocationScope.CAPABILITY, "monitor.watch"));
    expect(c.check(claims())).toMatchObject({ kind: "capability" });
    expect(c.check(claims({ capabilities: ["monitor.rescan"] }))).toBeNull();
  });

  it("temporary revocations lift after expires_at", () => {
    let now = 1_000_000;
    const c = new RevocationCache(() => now);
    c.apply(
      revocation(RevocationScope.ROE, "roe_1", {
        expiresAt: timestampFromDate(new Date(now + 5_000)),
      }),
    );
    expect(c.check(claims())).not.toBeNull();
    now += 6_000;
    expect(c.check(claims())).toBeNull();
  });

  it("is idempotent on revocation_id", () => {
    const c = new RevocationCache();
    const rev = revocation(RevocationScope.ROE, "roe_1");
    c.apply(rev);
    c.apply(rev);
    expect(c.size).toBe(1);
  });

  it("an UNSPECIFIED scope fails safe toward a global halt", () => {
    const c = new RevocationCache();
    c.apply(revocation(RevocationScope.UNSPECIFIED, ""));
    expect(c.check(claims())).toMatchObject({ kind: "global" });
  });
});

describe("decodeControlKill", () => {
  it("decodes an Envelope-wrapped RevocationEvent", () => {
    const event = create(RevocationEventSchema, {
      revocation: revocation(RevocationScope.GLOBAL, ""),
      ts: timestampFromDate(new Date()),
    });
    const bytes = encodeEnvelope(newEnvelope(RevocationEventSchema, event));
    const decoded = decodeControlKill(bytes);
    expect("global" in decoded).toBe(false);
  });

  it("treats unparseable payloads as a GLOBAL kill (fail-safe)", () => {
    expect(decodeControlKill(new TextEncoder().encode("garbage"))).toEqual({ global: true });
    expect(decodeControlKill(new Uint8Array(0))).toEqual({ global: true });
  });
});
