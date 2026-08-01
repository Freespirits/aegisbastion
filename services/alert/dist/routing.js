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
import { severityRank } from "./types.js";
export function policyMatches(policy, incident, now = new Date()) {
    const m = policy.match;
    // §5.4: a policy may stand down when the incident was acked quickly.
    if (policy.suppressIfAcknowledgedWithin !== undefined &&
        incident.ack &&
        now.getTime() - Date.parse(incident.ack.at) < policy.suppressIfAcknowledgedWithin * 1000) {
        return false;
    }
    if (m.severity_gte && severityRank(incident.severity) < severityRank(m.severity_gte))
        return false;
    if (m.categories && m.categories.length > 0 && !m.categories.includes(incident.category))
        return false;
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
        if (!anyHit)
            return false;
    }
    return true;
}
function criticalityToSeverity(c) {
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
export function urgencyForSeverity(severity) {
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
export function bumpUrgency(u) {
    switch (u) {
        case "low":
            return "normal";
        case "normal":
            return "high";
        default:
            return "critical";
    }
}
/**
 * Evaluate the policy set against an incident. First match per channel type:
 * once a channel has been satisfied by a higher-priority policy, lower
 * policies cannot add more targets for that channel.
 */
export function routeIncident(policies, incident, now = new Date()) {
    const satisfiedChannels = new Set();
    const targets = [];
    const matchedPolicyIds = [];
    let escalationPolicyId;
    // §8: evaluate in ascending priority (ties → creation order); the engine
    // does not rely on the store's ordering.
    const ordered = [...policies].sort((a, b) => a.priority - b.priority || a.createdAt.getTime() - b.createdAt.getTime());
    for (const policy of ordered) {
        if (!policyMatches(policy, incident, now))
            continue;
        const contributes = policy.targets.filter((t) => !satisfiedChannels.has(t.channel));
        if (contributes.length === 0)
            continue;
        matchedPolicyIds.push(policy.policyId);
        escalationPolicyId ??= policy.escalationPolicyId;
        for (const t of contributes) {
            targets.push(t);
            satisfiedChannels.add(t.channel);
        }
    }
    const decision = { targets, matchedPolicyIds, droppedByEgress: [] };
    if (escalationPolicyId !== undefined)
        decision.escalationPolicyId = escalationPolicyId;
    return decision;
}
// ---------------------------------------------------------------------------
// Org-level egress policy (§13.2)
// ---------------------------------------------------------------------------
function destinationHost(destination) {
    if (!destination.includes("://"))
        return null;
    try {
        return new URL(destination).host;
    }
    catch {
        return null;
    }
}
/** Does the org egress policy explicitly allow this target? */
export function egressAllows(entries, target) {
    if (!entries)
        return false; // no org egress policy → nothing is approved (fail-closed, §13.2)
    return entries.some((e) => {
        if (e.channel !== target.channel)
            return false;
        if (e.pattern === "*" || e.pattern === target.destination)
            return true;
        const host = destinationHost(target.destination);
        if (host && (e.pattern === host || e.pattern === host.split(":")[0]))
            return true;
        // "#channel" destinations match exact pattern entries only (checked above).
        return false;
    });
}
export function egressEntryFor(entries, target) {
    if (!entries)
        return null;
    for (const e of entries) {
        if (e.channel !== target.channel)
            continue;
        if (e.pattern === "*" || e.pattern === target.destination)
            return e;
        const host = destinationHost(target.destination);
        if (host && (e.pattern === host || e.pattern === host.split(":")[0]))
            return e;
    }
    return null;
}
/** Split a route decision into allowed + dropped targets under the org egress policy. */
export function applyEgressPolicy(decision, entries) {
    const allowed = [];
    const dropped = [];
    for (const t of decision.targets) {
        (egressAllows(entries, t) ? allowed : dropped).push(t);
    }
    const out = { ...decision, targets: allowed, droppedByEgress: dropped };
    return out;
}
/**
 * The three bootstrap policies created at org onboarding (§8): ≥medium → org
 * SIEM webhook; ≥high → Slack #sec-alerts; critical → Slack + ack-required +
 * default escalation. Built in-memory by the pipeline when an org has no
 * policies; persisting them is the onboarding job's business, not the hot
 * path's.
 */
export function bootstrapPolicies(orgId, channels, defaultEscalationPolicyId, now = new Date()) {
    const policies = [];
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
export function defaultEscalationPolicy(orgId, slackDestination) {
    return {
        policyId: "esc_bootstrap_default",
        orgId,
        steps: [
            {
                step: 0,
                wait_seconds: 0,
                targets: slackDestination
                    ? [{ channel: "slack", destination: slackDestination, template: "incident_card" }]
                    : [],
            },
            {
                step: 1,
                wait_seconds: 900,
                targets: slackDestination
                    ? [{ channel: "slack", destination: slackDestination, template: "incident_card", mention: "@oncall" }]
                    : [],
            },
        ],
        repeatLastStepEverySeconds: 3600,
        maxRepeats: 4,
        stopOn: ["ack", "resolved"],
    };
}
