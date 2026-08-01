/**
 * Routing engine (doc 05 §8 + §5.4). Policies evaluate in ascending
 * `priority` (ties → creation order); FIRST MATCH PER CHANNEL TYPE wins, so a
 * catch-all SIEM policy and a specific Slack policy coexist. Every decision
 * records matched_policy_ids (§8) for the audit record.
 *
 * Effective severity comes from enrichment (§8); escalation bumps urgency one
 * notch (§9). Destinations are validated against the org-level egress policy
 * (§13.2 — herald-owned, deliberately NOT a gatekeeper token claim, Ruling B):
 * out-of-policy targets are dropped and audit-flagged here AND re-checked at
 * send time.
 */

import { severityRank, type Channel, type ChannelTarget, type EgressEntry, type Incident, type RoutingPolicy, type Severity, type DeliveryUrgency } from "./types.js";

export function policyMatches(policy: RoutingPolicy, incident: Incident, now: Date = new Date()): boolean {
  const m = policy.match;
  // §5.4: a policy may stand down when the incident was acked quickly.
  if (
    policy.suppressIfAcknowledgedWithin !== undefined &&
    incident.ack &&
    now.getTime() - Date.parse(incident.ack.at) < policy.suppressIfAcknowledgedWithin * 1000
  ) {
    return false;
  }
  if (m.severity_gte && severityRank(incident.severity) < severityRank(m.severity_gte)) return false;
  if (m.categories && m.categories.length > 0 && !m.categories.includes(incident.category)) return false;
  if (m.asset_criticality_gte) {
    const crit = incident.asset.criticality;
    if (!crit || severityRank(criticalityToSeverity(crit)) < severityRank(criticalityToSeverity(m.asset_criticality_gte))) {
      return false;
    }
  }
  if (m.source_modules && m.source_modules.length > 0 && !m.source_modules.includes(incident.sourceModule)) {
    return false;
  }
  if (m.labels_any) {
    const labels = incident.labels ?? {};
    const anyHit = Object.entries(m.labels_any).some(([k, v]) => labels[k] === v);
    if (!anyHit) return false;
  }
  return true;
}

function criticalityToSeverity(c: "critical" | "high" | "medium" | "low"): Severity {
  // Reuse the shared 5-rank scale for the gte comparison (criticality ranks
  // align 1:1 with severity ranks for comparison purposes).
  switch (c) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
  }
}

export function urgencyForSeverity(severity: Severity): DeliveryUrgency {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "normal";
    default:
      return "low";
  }
}

/** Escalation bumps urgency one notch (§9). */
export function bumpUrgency(u: DeliveryUrgency): DeliveryUrgency {
  switch (u) {
    case "low":
      return "normal";
    case "normal":
      return "high";
    default:
      return "critical";
  }
}

export interface RouteDecision {
  targets: ChannelTarget[];
  matchedPolicyIds: string[];
  escalationPolicyId?: string;
  /** Targets dropped by the org egress policy (§13.2), for the audit flag. */
  droppedByEgress: ChannelTarget[];
}

/**
 * Evaluate the policy set against an incident. First match per channel type:
 * once a channel has been satisfied by a higher-priority policy, lower
 * policies cannot add more targets for that channel.
 */
export function routeIncident(policies: RoutingPolicy[], incident: Incident, now: Date = new Date()): RouteDecision {
  const satisfiedChannels = new Set<Channel>();
  const targets: ChannelTarget[] = [];
  const matchedPolicyIds: string[] = [];
  let escalationPolicyId: string | undefined;

  // §8: evaluate in ascending priority (ties → creation order); the engine
  // does not rely on the store's ordering.
  const ordered = [...policies].sort(
    (a, b) => a.priority - b.priority || a.createdAt.getTime() - b.createdAt.getTime(),
  );
  for (const policy of ordered) {
    if (!policyMatches(policy, incident, now)) continue;
    const contributes = policy.targets.filter((t) => !satisfiedChannels.has(t.channel));
    if (contributes.length === 0) continue;
    matchedPolicyIds.push(policy.policyId);
    escalationPolicyId ??= policy.escalationPolicyId;
    for (const t of contributes) {
      targets.push(t);
      satisfiedChannels.add(t.channel);
    }
  }
  const decision: RouteDecision = { targets, matchedPolicyIds, droppedByEgress: [] };
  if (escalationPolicyId !== undefined) decision.escalationPolicyId = escalationPolicyId;
  return decision;
}

// ---------------------------------------------------------------------------
// Org-level egress policy (§13.2)
// ---------------------------------------------------------------------------

function destinationHost(destination: string): string | null {
  if (!destination.includes("://")) return null;
  try {
    return new URL(destination).host;
  } catch {
    return null;
  }
}

/** Does the org egress policy explicitly allow this target? */
export function egressAllows(entries: EgressEntry[] | null, target: ChannelTarget): boolean {
  if (!entries) return false; // no org egress policy → nothing is approved (fail-closed, §13.2)
  return entries.some((e) => {
    if (e.channel !== target.channel) return false;
    if (e.pattern === "*" || e.pattern === target.destination) return true;
    const host = destinationHost(target.destination);
    if (host && (e.pattern === host || e.pattern === host.split(":")[0])) return true;
    // "#channel" destinations match exact pattern entries only (checked above).
    return false;
  });
}

export function egressEntryFor(entries: EgressEntry[] | null, target: ChannelTarget): EgressEntry | null {
  if (!entries) return null;
  for (const e of entries) {
    if (e.channel !== target.channel) continue;
    if (e.pattern === "*" || e.pattern === target.destination) return e;
    const host = destinationHost(target.destination);
    if (host && (e.pattern === host || e.pattern === host.split(":")[0])) return e;
  }
  return null;
}

/** Split a route decision into allowed + dropped targets under the org egress policy. */
export function applyEgressPolicy(decision: RouteDecision, entries: EgressEntry[] | null): RouteDecision {
  const allowed: ChannelTarget[] = [];
  const dropped: ChannelTarget[] = [];
  for (const t of decision.targets) {
    (egressAllows(entries, t) ? allowed : dropped).push(t);
  }
  const out: RouteDecision = { ...decision, targets: allowed, droppedByEgress: dropped };
  return out;
}

// ---------------------------------------------------------------------------
// Default org bootstrap policies (§8)
// ---------------------------------------------------------------------------

export interface BootstrapChannels {
  /** Org fail-safe SIEM webhook (§8/§9) — destination URL. */
  orgSiemWebhook?: string;
  /** Slack destination for #sec-alerts (URL or logical channel name). */
  slackSecAlerts?: string;
}

/**
 * The three bootstrap policies created at org onboarding (§8): ≥medium → org
 * SIEM webhook; ≥high → Slack #sec-alerts; critical → Slack + ack-required +
 * default escalation. Built in-memory by the pipeline when an org has no
 * policies; persisting them is the onboarding job's business, not the hot
 * path's.
 */
export function bootstrapPolicies(
  orgId: string,
  channels: BootstrapChannels,
  defaultEscalationPolicyId?: string,
  now: Date = new Date(),
): RoutingPolicy[] {
  const policies: RoutingPolicy[] = [];
  if (channels.orgSiemWebhook) {
    policies.push({
      policyId: "rp_bootstrap_siem",
      orgId,
      priority: 900,
      enabled: true,
      match: { severity_gte: "medium" },
      targets: [{ channel: "webhook", destination: channels.orgSiemWebhook, template: "raw_json" }],
      createdBy: "herald-bootstrap",
      createdAt: now,
    });
  }
  if (channels.slackSecAlerts) {
    policies.push({
      policyId: "rp_bootstrap_slack_high",
      orgId,
      priority: 500,
      enabled: true,
      match: { severity_gte: "high" },
      targets: [{ channel: "slack", destination: channels.slackSecAlerts, template: "incident_card" }],
      createdBy: "herald-bootstrap",
      createdAt: now,
    });
    policies.push({
      policyId: "rp_bootstrap_slack_critical",
      orgId,
      priority: 100,
      enabled: true,
      match: { severity_gte: "critical" },
      targets: [{ channel: "slack", destination: channels.slackSecAlerts, template: "incident_card" }],
      ...(defaultEscalationPolicyId ? { escalationPolicyId: defaultEscalationPolicyId } : {}),
      createdBy: "herald-bootstrap",
      createdAt: now,
    });
  }
  return policies;
}

/** Default escalation policy for criticals (§8 bootstrap). */
export function defaultEscalationPolicy(orgId: string, slackDestination?: string) {
  return {
    policyId: "esc_bootstrap_default",
    orgId,
    steps: [
      {
        step: 0,
        wait_seconds: 0,
        targets: slackDestination
          ? [{ channel: "slack" as const, destination: slackDestination, template: "incident_card" }]
          : [],
      },
      {
        step: 1,
        wait_seconds: 900,
        targets: slackDestination
          ? [{ channel: "slack" as const, destination: slackDestination, template: "incident_card", mention: "@oncall" }]
          : [],
      },
    ],
    repeatLastStepEverySeconds: 3600,
    maxRepeats: 4,
    stopOn: ["ack", "resolved"],
  };
}
