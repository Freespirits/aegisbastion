import { describe, expect, it } from "vitest";
import { capabilitiesOf, hasCapability } from "@/lib/roles";

describe("role → affordance mapping (doc 10 §7.2 over doc 11 §3.5 roles)", () => {
  it("every authenticated principal can read", () => {
    expect(hasCapability([], "read")).toBe(true);
    expect(hasCapability(["module-svc"], "read")).toBe(true);
  });

  it("operator gets triage, launch and mission control — not RoE approve", () => {
    const caps = capabilitiesOf(["operator"]);
    expect(caps.has("findings.triage")).toBe(true);
    expect(caps.has("tasks.launch")).toBe(true);
    expect(caps.has("missions.control")).toBe(true);
    expect(caps.has("roe.author")).toBe(false);
    expect(caps.has("roe.approve")).toBe(false);
    expect(caps.has("audit.view")).toBe(false);
  });

  it("roe-author can author but not approve (segregation of duties)", () => {
    const caps = capabilitiesOf(["roe-author"]);
    expect(caps.has("roe.author")).toBe(true);
    expect(caps.has("roe.approve")).toBe(false);
  });

  it("offensive-approver can approve but not author", () => {
    const caps = capabilitiesOf(["offensive-approver"]);
    expect(caps.has("roe.approve")).toBe(true);
    expect(caps.has("roe.author")).toBe(false);
    expect(caps.has("tasks.launch")).toBe(false);
  });

  it("auditor reads audit trails only", () => {
    const caps = capabilitiesOf(["auditor"]);
    expect(caps.has("audit.view")).toBe(true);
    expect(caps.has("findings.triage")).toBe(false);
    expect(caps.has("missions.control")).toBe(false);
  });

  it("platform-admin is the union", () => {
    const caps = capabilitiesOf(["platform-admin"]);
    for (const c of [
      "findings.triage",
      "tasks.launch",
      "missions.control",
      "roe.author",
      "roe.approve",
      "audit.view",
      "alert-rules.manage",
    ] as const) {
      expect(caps.has(c)).toBe(true);
    }
  });

  it("unknown roles degrade to read-only (fail-closed)", () => {
    const caps = capabilitiesOf(["not-a-role"]);
    expect([...caps]).toEqual(["read"]);
  });
});
