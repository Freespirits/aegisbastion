// @vitest-environment node
// (jose's key handling is realm-sensitive; the session crypto is server-side
// Node code, so this suite runs outside jsdom)
process.env.SESSION_SECRET = "test-session-secret-at-least-32-bytes!!";
process.env.DEV_AUTH_ENABLED = "true";

import { describe, expect, it } from "vitest";
import { __resetEnvForTests } from "@/env";
import { hasStepUp, sealSession, unsealSession, type Session } from "@/lib/session";

const sample: Session = {
  sub: "op_jane@example.com",
  name: "Jane",
  orgId: "org_acme",
  roles: ["operator"],
  dev: true,
  iat: Math.floor(Date.now() / 1000),
};

describe("session seal/unseal", () => {
  it("round-trips a session", async () => {
    __resetEnvForTests();
    const token = await sealSession(sample);
    const back = await unsealSession(token);
    expect(back).not.toBeNull();
    expect(back?.sub).toBe(sample.sub);
    expect(back?.orgId).toBe("org_acme");
    expect(back?.roles).toEqual(["operator"]);
    expect(back?.dev).toBe(true);
  });

  it("rejects a tampered token", async () => {
    const token = await sealSession(sample);
    const tampered = token.slice(0, -4) + "AAAA";
    expect(await unsealSession(tampered)).toBeNull();
  });

  it("rejects a token sealed with a different secret", async () => {
    const token = await sealSession(sample);
    process.env.SESSION_SECRET = "a-different-secret-also-32-bytes!!!";
    __resetEnvForTests();
    expect(await unsealSession(token)).toBeNull();
    process.env.SESSION_SECRET = "test-session-secret-at-least-32-bytes!!";
    __resetEnvForTests();
  });
});

describe("hasStepUp (doc 10 §7.2: ≤5 min window)", () => {
  it("is false without a step-up assertion", () => {
    expect(hasStepUp(sample)).toBe(false);
    expect(hasStepUp(null)).toBe(false);
  });

  it("is true inside the window and false after expiry", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(hasStepUp({ ...sample, stepUpUntil: now + 300 }, now)).toBe(true);
    expect(hasStepUp({ ...sample, stepUpUntil: now - 1 }, now)).toBe(false);
  });
});
