/**
 * Routing matrix (doc 05 §8/§5.4): ordered matchers, first-match-per-channel-
 * type wins, matcher coverage (severity_gte / categories / asset criticality /
 * source_modules / labels_any), org-level egress policy (§13.2 — fail-closed,
 * NOT a gatekeeper token claim), bootstrap policies, ack-window suppression.
 */

import { describe, expect, it } from "vitest";
import {
  applyEgressPolicy,
  bootstrapPolicies,
  egressAllows,
  policyMatches,
  routeIncident,
  urgencyForSeverity,
} from "../src/routing.js";
import type { EgressEntry, Incident, RoutingPolicy } from "../src/types.js";

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    incidentId: "inc_1",
    orgId: "org_acme",
    state: "open",
    title: "t",
    severity: "high",
    category: "vuln",
    sourceModule: "detect",
    asset: { asset_id: "a1", kind: "subdomain", identifier: "api.example.com", criticality: "high" },
    labels: { playbook: "internet-facing-rce" },
    correlationKey: "k",
    alertCount: 1,
    requiresAck: false,
    firstSeenAt: new Date("2026-07-30T00:00:00Z"),
    lastSeenAt: new Date("2026-07-30T00:00:00Z"),
    escalation: {},
    escalationExhausted: false,
    ...overrides,
  };
}

function policy(overrides: Partial<RoutingPolicy>): RoutingPolicy {
  return {
    policyId: "rp_x",
    orgId: "org_acme",
    priority: 100,
    enabled: true,
    match: {},
    targets: [],
    createdBy: "test",
    createdAt: new Date("2026-07-01T00:00:00Z"),
    ...overrides,
  };
}

describe("policyMatches", () => {
  it("severity_gte", () => {
    expect(policyMatches(policy({ match: { severity_gte: "high" } }), incident())).toBe(true);
    expect(policyMatches(policy({ match: { severity_gte: "critical" } }), incident())).toBe(false);
    expect(policyMatches(policy({ match: { severity_gte: "medium" } }), incident())).toBe(true);
  });
  it("categories", () => {
    expect(policyMatches(policy({ match: { categories: ["vuln", "exposure"] } }), incident())).toBe(true);
    expect(policyMatches(policy({ match: { categories: ["phishing"] } }), incident())).toBe(false);
  });
  it("asset_criticality_gte", () => {
    expect(policyMatches(policy({ match: { asset_criticality_gte: "medium" } }), incident())).toBe(true);
    expect(policyMatches(policy({ match: { asset_criticality_gte: "critical" } }), incident())).toBe(false);
    expect(policyMatches(policy({ match: { asset_criticality_gte: "low" } }), incident({ asset: { asset_id: "a", kind: "ip", identifier: "i" } }))).toBe(false);
  });
  it("source_modules", () => {
    expect(policyMatches(policy({ match: { source_modules: ["detect", "monitor"] } }), incident())).toBe(true);
    expect(policyMatches(policy({ match: { source_modules: ["monitor"] } }), incident())).toBe(false);
  });
  it("labels_any", () => {
    expect(policyMatches(policy({ match: { labels_any: { playbook: "internet-facing-rce" } } }), incident())).toBe(true);
    expect(policyMatches(policy({ match: { labels_any: { playbook: "other", team: "sec" } } }), incident())).toBe(false);
    expect(policyMatches(policy({ match: { labels_any: { playbook: "other", team: "sec", x: "y" }, severity_gte: "low" } }), incident())).toBe(false);
  });
  it("suppress_if_acknowledged_within stands a policy down after a quick ack", () => {
    const p = policy({ suppressIfAcknowledgedWithin: 3600 });
    const acked = incident({ ack: { by: "u", at: "2026-07-30T00:30:00Z", note: "" } });
    expect(policyMatches(p, acked, new Date("2026-07-30T00:45:00Z"))).toBe(false);
    expect(policyMatches(p, acked, new Date("2026-07-30T02:00:00Z"))).toBe(true);
  });
});

describe("routeIncident — first match per channel type (§8)", () => {
  it("a catch-all SIEM policy and a specific Slack policy coexist (§8: ascending priority)", () => {
    const specific = policy({
      policyId: "rp_slack",
      priority: 10,
      match: { severity_gte: "high" },
      targets: [{ channel: "slack", destination: "#sec-critical" }],
    });
    const catchAll = policy({
      policyId: "rp_siem",
      priority: 900,
      match: {},
      targets: [
        { channel: "webhook", destination: "https://siem.example/ingest" },
        { channel: "slack", destination: "#everything" },
      ],
    });
    // Engine sorts by priority — input order must not matter.
    const sorted = routeIncident([catchAll, specific], incident());
    expect(sorted.matchedPolicyIds).toEqual(["rp_slack", "rp_siem"]);
    // Slack comes from the specific policy; the catch-all contributes only webhook.
    expect(sorted.targets).toEqual([
      { channel: "slack", destination: "#sec-critical" },
      { channel: "webhook", destination: "https://siem.example/ingest" },
    ]);
  });

  it("lower-priority policy cannot add a second target for a satisfied channel", () => {
    const p1 = policy({ policyId: "rp_1", priority: 1, targets: [{ channel: "slack", destination: "#a" }] });
    const p2 = policy({ policyId: "rp_2", priority: 2, targets: [{ channel: "slack", destination: "#b" }, { channel: "teams", destination: "T" }] });
    const decision = routeIncident([p1, p2], incident());
    expect(decision.targets).toEqual([
      { channel: "slack", destination: "#a" },
      { channel: "teams", destination: "T" },
    ]);
  });

  it("carries the first matching policy's escalation_policy_id", () => {
    const p1 = policy({ policyId: "rp_1", priority: 1, escalationPolicyId: "esc_12", targets: [{ channel: "slack", destination: "#a" }] });
    const p2 = policy({ policyId: "rp_2", priority: 2, escalationPolicyId: "esc_99", targets: [{ channel: "teams", destination: "T" }] });
    expect(routeIncident([p1, p2], incident()).escalationPolicyId).toBe("esc_12");
  });
});

describe("org egress policy (§13.2, Ruling B — herald-owned, NOT a token claim)", () => {
  const entries: EgressEntry[] = [
    { channel: "slack", pattern: "#sec-critical" },
    { channel: "webhook", pattern: "siem.example" },
  ];

  it("is fail-closed when no org policy exists", () => {
    expect(egressAllows(null, { channel: "slack", destination: "#sec-critical" })).toBe(false);
    const decision = applyEgressPolicy(
      { targets: [{ channel: "slack", destination: "#sec-critical" }], matchedPolicyIds: ["rp"], droppedByEgress: [] },
      null,
    );
    expect(decision.targets).toEqual([]);
    expect(decision.droppedByEgress).toHaveLength(1); // audit flag
  });

  it("matches exact destinations and URL hosts", () => {
    expect(egressAllows(entries, { channel: "slack", destination: "#sec-critical" })).toBe(true);
    expect(egressAllows(entries, { channel: "slack", destination: "#random" })).toBe(false);
    expect(egressAllows(entries, { channel: "webhook", destination: "https://siem.example/ingest" })).toBe(true);
    expect(egressAllows(entries, { channel: "webhook", destination: "https://evil.example/x" })).toBe(false);
    expect(egressAllows(entries, { channel: "teams", destination: "#sec-critical" })).toBe(false); // channel must match
  });

  it("wildcard pattern allows the channel", () => {
    expect(egressAllows([{ channel: "webhook", pattern: "*" }], { channel: "webhook", destination: "https://anything.example" })).toBe(true);
  });
});

describe("bootstrap policies (§8)", () => {
  it("creates the three default policies", () => {
    const policies = bootstrapPolicies("org_acme", { orgSiemWebhook: "https://siem.example/x", slackSecAlerts: "https://hooks.slack.example/T/B/X" }, "esc_bootstrap_default");
    expect(policies.map((p) => p.policyId)).toEqual(["rp_bootstrap_siem", "rp_bootstrap_slack_high", "rp_bootstrap_slack_critical"]);
    const critical = routeIncident(policies, incident({ severity: "critical" }));
    expect(critical.escalationPolicyId).toBe("esc_bootstrap_default");
    expect(critical.targets.map((t) => t.channel)).toContain("webhook");
  });

  it("urgency mapping", () => {
    expect(urgencyForSeverity("critical")).toBe("critical");
    expect(urgencyForSeverity("high")).toBe("high");
    expect(urgencyForSeverity("medium")).toBe("normal");
    expect(urgencyForSeverity("low")).toBe("low");
    expect(urgencyForSeverity("info")).toBe("low");
  });
});
