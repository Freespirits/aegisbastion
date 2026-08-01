/**
 * Escalation (doc 05 §9): step timing math, mid-chain ack stops the chain,
 * repeats capped by max_repeats, exhausted chains fire the fail-safe hook.
 */

import { describe, expect, it } from "vitest";
import { initialEscalationState, nextEscalationState, runDueEscalations, type EscalationDriver } from "../src/escalate.js";
import { MemoryStore } from "../src/db/memory.js";
import type { EscalationPolicy, EscalationStep, Incident } from "../src/types.js";

const policy: EscalationPolicy = {
  policyId: "esc_12",
  orgId: "org_acme",
  steps: [
    { step: 0, wait_seconds: 0, targets: [{ channel: "slack", destination: "#sec-critical" }] },
    { step: 1, wait_seconds: 60, targets: [{ channel: "slack", destination: "#sec-oncall", mention: "@oncall" }] },
    { step: 2, wait_seconds: 120, targets: [{ channel: "teams", destination: "SecOps" }] },
  ],
  repeatLastStepEverySeconds: 300,
  maxRepeats: 2,
  stopOn: ["ack", "resolved"],
};

function incident(escalation: Incident["escalation"], state: Incident["state"] = "open"): Incident {
  return {
    incidentId: "inc_esc",
    orgId: "org_acme",
    state,
    title: "t",
    severity: "critical",
    category: "vuln",
    sourceModule: "detect",
    asset: { asset_id: "a1", kind: "ip", identifier: "1.2.3.4" },
    labels: {},
    correlationKey: "k",
    alertCount: 1,
    requiresAck: true,
    firstSeenAt: new Date("2026-07-30T00:00:00Z"),
    lastSeenAt: new Date("2026-07-30T00:00:00Z"),
    escalation,
    escalationExhausted: false,
  };
}

class SpyDriver implements EscalationDriver {
  steps: EscalationStep[] = [];
  exhausted: Incident[] = [];
  async fireStep(_incident: Incident, step: EscalationStep): Promise<void> {
    this.steps.push(step);
  }
  async fireExhausted(incident: Incident): Promise<void> {
    this.exhausted.push(incident);
  }
}

const T0 = new Date("2026-07-30T00:00:00Z");
const at = (ms: number) => new Date(T0.getTime() + ms);

describe("nextEscalationState timing", () => {
  it("step waits are cumulative from attachment", () => {
    const esc = initialEscalationState(policy, T0);
    expect(esc.next_fire_at).toBe(at(60_000).toISOString());
    const inc = incident(esc);
    expect(nextEscalationState(inc, policy, at(59_000)).action).toBe("none");
    const fire1 = nextEscalationState(inc, policy, at(61_000));
    expect(fire1.action).toBe("step");
    if (fire1.action === "step") expect(fire1.step.step).toBe(1);
  });

  it("chain end → repeat last step up to max_repeats, then exhausted", () => {
    const esc = { ...initialEscalationState(policy, T0), current_step: 2, last_fired_at: T0.toISOString() };
    const inc = incident(esc);
    const repeat = nextEscalationState(inc, policy, at(301_000));
    expect(repeat.action).toBe("step");
    const capped = nextEscalationState(incident({ ...esc, repeat_count: 2 }), policy, at(600_000));
    expect(capped.action).toBe("exhausted");
  });
});

describe("runDueEscalations (§9 scan)", () => {
  it("fires due steps and schedules the next one", async () => {
    const store = new MemoryStore();
    const inc = incident(initialEscalationState(policy, T0));
    await store.insertIncident(inc);
    await store.putEscalationPolicy(policy);
    const driver = new SpyDriver();

    expect(await runDueEscalations(store, driver, at(59_000))).toBe(0);
    expect(await runDueEscalations(store, driver, at(61_000))).toBe(1);
    expect(driver.steps.map((s) => s.step)).toEqual([1]);
    const updated = await store.getIncident(inc.incidentId);
    expect(updated?.state).toBe("escalated");
    expect(updated?.escalation.next_fire_at).toBe(at(120_000).toISOString());
  });

  it("an ack stops the chain (stop_on)", async () => {
    const store = new MemoryStore();
    const inc = incident(initialEscalationState(policy, T0));
    await store.insertIncident(inc);
    await store.putEscalationPolicy(policy);
    const driver = new SpyDriver();

    await store.ackIncident(inc.incidentId, "user_dana", "on it", "nonce-1", at(30_000));
    expect(await runDueEscalations(store, driver, at(61_000))).toBe(0);
    expect(driver.steps).toHaveLength(0);
  });

  it("nonce reuse is rejected (§12 callback replay)", async () => {
    const store = new MemoryStore();
    const inc = incident({});
    await store.insertIncident(inc);
    expect(await store.ackIncident(inc.incidentId, "a", "", "n1", at(1))).toBe("acked");
    expect(await store.ackIncident(inc.incidentId, "b", "", "n1", at(2))).toBe("nonce_used");
    expect(await store.ackIncident(inc.incidentId, "b", "", "n2", at(3))).toBe("already");
  });

  it("exhausted chains fire the fail-safe hook once", async () => {
    const store = new MemoryStore();
    const inc = incident({
      policy_id: "esc_12",
      current_step: 2,
      attached_at: T0.toISOString(),
      last_fired_at: T0.toISOString(),
      next_fire_at: at(300_000).toISOString(),
      repeat_count: 2, // repeats spent
    });
    await store.insertIncident(inc);
    await store.putEscalationPolicy(policy);
    const driver = new SpyDriver();
    expect(await runDueEscalations(store, driver, at(301_000))).toBe(1);
    expect(driver.exhausted).toHaveLength(1);
    const updated = await store.getIncident(inc.incidentId);
    expect(updated?.escalationExhausted).toBe(true);
  });
});
