/**
 * Pipeline orchestrator (doc 05 §3.2): ingest → authz-context enforcement →
 * enrich → dedup → correlate → route, plus held-authz retry/quarantine (§12),
 * commander NotifyOrders (§4.2), acks (§9), and dry-run route testing (§4.1).
 *
 * Dispatch is decoupled: routing writes Delivery rows (the recorded outbox,
 * §5.6) and the dispatcher (dispatch/dispatcher.ts) works them. Every
 * transition is audit-logged locally (append-only, §5.8) and published to
 * alerts.lifecycle (§4.3); authz rejections also quarantine to alerts.dlq
 * (§13.1 — no token, no notification, no exceptions).
 */

import { sha256JcsHex, ulid } from "@aegisbastion/agent-sdk";
import type { HeraldConfig } from "./config.js";
import type { AssetCache } from "./enrich.js";
import { enrichEvent } from "./enrich.js";
import type { AuthzEnforcer } from "./authz/enforce.js";
import { dedupCheck, fingerprintFor } from "./dedup.js";
import { correlate } from "./correlate.js";
import {
  applyEgressPolicy,
  bootstrapPolicies,
  defaultEscalationPolicy,
  routeIncident,
  urgencyForSeverity,
  type BootstrapChannels,
} from "./routing.js";
import { initialEscalationState, type EscalationDriver } from "./escalate.js";
import { newDeliveryId } from "./ids.js";
import type { Metrics } from "./metrics.js";
import type { Store, StoredAlert } from "./store.js";
import type {
  AlertEvent,
  AuditRecord,
  ChannelTarget,
  Delivery,
  EgressEntry,
  EscalationPolicy,
  Incident,
  IngressContext,
  RoutingPolicy,
  Severity,
} from "./types.js";
import { severityRank } from "./types.js";

/** Bus/lifecycle/audit side-effects — no-ops when the bus is disabled (tests). */
export interface PipelineSinks {
  /** alerts.lifecycle — one CloudEvents JSON message per transition (§4.3). */
  publishLifecycle(transition: string, subject: string, data: Record<string, unknown>): Promise<void>;
  /** alerts.dlq — authz quarantines + dead-lettered deliveries (§12/§13.1). */
  publishDlq(reason: string, data: Record<string, unknown>): Promise<void>;
  /** Best-effort forward of a local audit record to gatekeeper's audit of record (§5.8). */
  forwardAudit(record: AuditRecord, auditId: string): Promise<void>;
}

export const noopSinks: PipelineSinks = {
  async publishLifecycle() {},
  async publishDlq() {},
  async forwardAudit() {},
};

export interface PipelineOptions {
  store: Store;
  enforcer: AuthzEnforcer;
  assetCache: AssetCache;
  sinks: PipelineSinks;
  metrics: Metrics;
  /** Bootstrap routing channels (§8) when an org has no policies. */
  bootstrapChannels: BootstrapChannels;
  /** Org egress policy seed (§13.2) for orgs without a DB policy. */
  egressSeed?: Record<string, EgressEntry[]>;
  maxDeliveryAttempts: number;
  /** §12: held-alert re-verification cadence + quarantine deadline. */
  authzRetryMs: number;
  authzHoldQuarantineMs: number;
  actor?: string;
}

export type IngestResult =
  | { status: "processed"; incidentId: string; deliveries: number }
  | { status: "duplicate" }
  | { status: "suppressed"; reason: "dedup" | "severity_floor" }
  | { status: "renotified"; incidentId: string; deliveries: number }
  | { status: "held" }
  | { status: "rejected"; code: string; reason: string };

const OCCURRED_AT_TOLERANCE_MS = 24 * 3600 * 1000; // §5.2: ±24 h of ingest
export const MAX_ALERT_PAYLOAD_BYTES = 64 * 1024; // §5.2: payload max 64 KiB

export class Pipeline implements EscalationDriver {
  private readonly actor: string;

  constructor(private readonly opts: PipelineOptions) {
    this.actor = opts.actor ?? "herald";
  }

  // -------------------------------------------------------------------------
  // Audit helper (§5.8): local append-only spool + best-effort forward.
  // -------------------------------------------------------------------------
  private async audit(
    action: AuditRecord["action"],
    orgId: string,
    entityIds: Record<string, string>,
    decisionDetail: Record<string, unknown>,
    actor: { kind: "service" | "commander" | "user"; id: string } = { kind: "service", id: this.actor },
  ): Promise<void> {
    const record: AuditRecord = {
      orgId,
      actor,
      action,
      entityIds,
      decisionDetail,
      requestHash: sha256JcsHex({ action, entityIds, decisionDetail }),
    };
    try {
      const auditId = await this.opts.store.appendAudit(record);
      await this.opts.sinks.forwardAudit(record, auditId).catch(() => {
        /* spool retains it (forwarded_at NULL) for later reconciliation */
      });
    } catch (err) {
      // Audit must never silently break the pipeline, but it is loud (§13.8).
      console.error(`herald: audit append failed for ${action}: ${(err as Error).message}`);
    }
  }

  // -------------------------------------------------------------------------
  // C1/C2: ingest one schema-valid AlertEvent.
  // -------------------------------------------------------------------------
  async ingest(event: AlertEvent, ctx: IngressContext): Promise<IngestResult> {
    const now = ctx.receivedAt;
    const occurredAt = Date.parse(event.occurred_at);
    if (!Number.isFinite(occurredAt) || Math.abs(now.getTime() - occurredAt) > OCCURRED_AT_TOLERANCE_MS) {
      await this.audit("ingest_reject", event.org_id, { event_id: event.event_id }, {
        reason: "occurred_at outside ±24 h of ingest",
        occurred_at: event.occurred_at,
      });
      return { status: "rejected", code: "OCCURRED_AT_OUT_OF_RANGE", reason: "occurred_at outside ±24 h of ingest" };
    }
    this.opts.metrics.ingest(event.source_module);

    // C2 enrich (fail-soft) → effective severity (§8 floor rule).
    const { event: enriched, effectiveSeverity, enriched: wasEnriched } = await enrichEvent(event, this.opts.assetCache);

    // §13.1 authz-context enforcement (NON-DEFERRABLE).
    const verdict = await this.opts.enforcer.verify(enriched, ctx.authorizationToken, now);
    if (verdict.outcome === "rejected") {
      await this.insertAlertRow(enriched, ctx, effectiveSeverity, "suppressed", "rejected");
      this.opts.metrics.authzReject(verdict.code);
      await this.audit("authz_reject", event.org_id, { event_id: event.event_id }, {
        code: verdict.code,
        reason: verdict.reason,
        authorization_token_id: event.authorization_token_id ?? null,
      });
      await this.opts.sinks.publishDlq("authz_reject", {
        event_id: event.event_id,
        org_id: event.org_id,
        code: verdict.code,
        detail: verdict.reason,
        event: enriched,
      });
      return { status: "rejected", code: verdict.code, reason: verdict.reason };
    }
    if (verdict.outcome === "unavailable") {
      // §12 JWKS outage: HOLD in the raw store (not delivered, not rejected);
      // retried by runDueAuthzRetries and quarantined after 15 min.
      const inserted = await this.insertAlertRow(enriched, ctx, effectiveSeverity, "open", "held", {
        held_token: ctx.authorizationToken ?? null,
        reason: verdict.reason,
      });
      if (!inserted) return { status: "duplicate" };
      await this.opts.store.setAlertAuthz(event.event_id, "held", undefined, new Date(now.getTime() + this.opts.authzRetryMs));
      await this.audit("authz_hold", event.org_id, { event_id: event.event_id }, { reason: verdict.reason });
      return { status: "held" };
    }

    const authzStatus = verdict.outcome === "verified" ? "verified" : "none";
    const claims =
      verdict.outcome === "verified"
        ? ({ jti: verdict.claims.jti, task_id: verdict.claims.task_id, roe_id: verdict.claims.roe_id, risk_class: verdict.claims.risk_class, capabilities: verdict.claims.capabilities } as Record<string, unknown>)
        : undefined;
    const inserted = await this.insertAlertRow(enriched, ctx, effectiveSeverity, "open", authzStatus, claims);
    if (!inserted) return { status: "duplicate" }; // §3.2 step 2: duplicates on event_id dropped at ingest
    await this.audit("ingest", event.org_id, { event_id: event.event_id }, {
      source_module: event.source_module,
      severity: event.severity,
      effective_severity: effectiveSeverity,
      enriched: wasEnriched,
      authz: authzStatus,
      ...(ctx.envelopeSource ? { envelope_source: ctx.envelopeSource } : {}),
    });
    return this.processStored(enriched, effectiveSeverity, now);
  }

  /** Insert the alert row; false when the event_id was already ingested. */
  private async insertAlertRow(
    event: AlertEvent,
    ctx: IngressContext,
    effectiveSeverity: Severity,
    state: StoredAlert["state"],
    authzStatus: StoredAlert["authzStatus"],
    authzClaims?: Record<string, unknown>,
  ): Promise<boolean> {
    const row: StoredAlert = {
      eventId: event.event_id,
      orgId: event.org_id,
      state,
      effectiveSeverity,
      dedupVerdict: "new",
      dedupDegraded: false,
      authzStatus,
      event,
      receivedAt: ctx.receivedAt,
      ...(authzClaims !== undefined ? { authzClaims } : {}),
    };
    return (await this.opts.store.insertAlertIfNew(row)) === "inserted";
  }

  /** Stages C3–C5 for an accepted alert row (also the resume path for held alerts). */
  private async processStored(event: AlertEvent, effectiveSeverity: Severity, now: Date): Promise<IngestResult> {
    const store = this.opts.store;

    // C3 dedup (§7.1) — fail-open inside dedupCheck.
    const dedup = await dedupCheck(store, event, now);
    await store.setAlertDedup(event.event_id, dedup.verdict, dedup.degraded);
    this.opts.metrics.dedupVerdict(dedup.verdict);
    if (dedup.verdict === "duplicate") {
      await store.setAlertState(event.event_id, "suppressed");
      // §7.1: suppressions audited (the fingerprint tracks occurrence count).
      await this.audit("dedup_suppress", event.org_id, { event_id: event.event_id }, {
        fingerprint: fingerprintFor(event),
        first_alert_id: dedup.firstAlertId,
        occurrence_count: dedup.count,
      });
      await this.opts.sinks.publishLifecycle("deduped", `alert/${event.event_id}`, {
        event_id: event.event_id,
        org_id: event.org_id,
        occurrence_count: dedup.count,
      });
      return { status: "suppressed", reason: "dedup" };
    }

    // C4 correlate (§7.2 deterministic key #1).
    const { incident, created } = await correlate(store, event, effectiveSeverity, now);
    if (created) {
      await this.audit("correlate", event.org_id, { event_id: event.event_id, incident_id: incident.incidentId }, {
        correlation_key: incident.correlationKey,
        created: true,
      });
      await this.opts.sinks.publishLifecycle("correlated", `incident/${incident.incidentId}`, {
        incident_id: incident.incidentId,
        org_id: incident.orgId,
        correlation_key: incident.correlationKey,
        created: true,
      });
    }

    // C5 route (§8) — renotify routes a "still firing" notice instead (§3.2.4).
    const deliveries = await this.routeAndQueue(incident, event, now, dedup.verdict === "renotify");
    return dedup.verdict === "renotify"
      ? { status: "renotified", incidentId: incident.incidentId, deliveries }
      : { status: "processed", incidentId: incident.incidentId, deliveries };
  }

  // -------------------------------------------------------------------------
  // §12: held-authz retry loop (JWKS-outage hold → verify → pipeline | quarantine).
  // -------------------------------------------------------------------------
  async runDueAuthzRetries(now: Date): Promise<number> {
    const due = await this.opts.store.dueAuthzRetries(now);
    let processed = 0;
    for (const row of due) {
      const heldToken = (row.authzClaims as { held_token?: string } | undefined)?.held_token;
      const verdict = await this.opts.enforcer.verify(row.event, heldToken ?? undefined, now);
      if (verdict.outcome === "unavailable") {
        const heldSince = row.receivedAt.getTime();
        if (now.getTime() - heldSince >= this.opts.authzHoldQuarantineMs) {
          await this.quarantine(row, "AUTHZ_VERIFICATION_UNAVAILABLE", "verification unavailable past the 15-minute hold window (§12)");
        } else {
          await this.opts.store.setAlertAuthz(row.eventId, "held", undefined, new Date(now.getTime() + this.opts.authzRetryMs));
        }
        continue;
      }
      if (verdict.outcome === "rejected") {
        await this.quarantine(row, verdict.code, verdict.reason);
        continue;
      }
      // Verified (or no longer required): clear the held token and resume C3–C5.
      const claims =
        verdict.outcome === "verified"
          ? ({ jti: verdict.claims.jti, task_id: verdict.claims.task_id, roe_id: verdict.claims.roe_id, risk_class: verdict.claims.risk_class, capabilities: verdict.claims.capabilities } as Record<string, unknown>)
          : { held_token: null };
      await this.opts.store.setAlertAuthz(row.eventId, verdict.outcome === "verified" ? "verified" : "none", claims, null);
      await this.processStored(row.event, row.effectiveSeverity, now);
      processed++;
    }
    return processed;
  }

  private async quarantine(row: StoredAlert, code: string, reason: string): Promise<void> {
    await this.opts.store.setAlertAuthz(row.eventId, "rejected", { code, held_token: null }, null);
    await this.opts.store.setAlertState(row.eventId, "suppressed");
    this.opts.metrics.authzReject(code);
    await this.audit("authz_reject", row.orgId, { event_id: row.eventId }, { code, reason });
    await this.opts.sinks.publishDlq("authz_reject", {
      event_id: row.eventId,
      org_id: row.orgId,
      code,
      detail: reason,
      event: row.event,
    });
  }

  // -------------------------------------------------------------------------
  // C5: routing → DeliveryTask rows (recorded outbox, §5.6).
  // -------------------------------------------------------------------------
  private async routeAndQueue(incident: Incident, event: AlertEvent, now: Date, stillFiring: boolean): Promise<number> {
    const store = this.opts.store;
    const policies = await this.policiesFor(incident.orgId);
    let decision = routeIncident(policies, incident, now);
    const egress = await this.egressFor(incident.orgId);
    decision = applyEgressPolicy(decision, egress);
    this.opts.metrics.routeDecision(decision.matchedPolicyIds);

    const targets = decision.targets.map((t) => (stillFiring ? { ...t, template: "still_firing" } : t));
    const count = await this.createDeliveries(incident, targets, {
      triggeringEventId: event.event_id,
      urgency: urgencyForSeverity(incident.severity),
    });

    // Escalation attachment (§9): ack-required incidents get the matched
    // policy's escalation chain (bootstrap default for criticals, §8).
    if (incident.requiresAck && !incident.escalation.policy_id) {
      const policyId = decision.escalationPolicyId;
      const policy = policyId ? await this.escalationPolicyFor(incident.orgId, policyId) : null;
      if (policy) {
        await store.setIncidentEscalation(incident.incidentId, initialEscalationState(policy, now));
      }
    }

    await this.audit("route", incident.orgId, { incident_id: incident.incidentId, event_id: event.event_id }, {
      matched_policy_ids: decision.matchedPolicyIds,
      targets: decision.targets.map((t) => `${t.channel}:${t.destination}`),
      dropped_by_egress: decision.droppedByEgress.map((t) => `${t.channel}:${t.destination}`), // §13.2 audit flag
      still_firing: stillFiring,
      deliveries: count,
    });
    await this.opts.sinks.publishLifecycle("routed", `incident/${incident.incidentId}`, {
      incident_id: incident.incidentId,
      org_id: incident.orgId,
      matched_policy_ids: decision.matchedPolicyIds,
      deliveries: count,
    });
    return count;
  }

  /** Delivery creation shared by routing and the escalation driver. */
  async createDeliveries(
    incident: Incident,
    targets: ChannelTarget[],
    opts: {
      triggeringEventId: string;
      urgency: Delivery["urgency"];
      escalationStep?: number;
      templateOverride?: string;
    },
  ): Promise<number> {
    let created = 0;
    for (const target of targets) {
      const delivery: Delivery = {
        deliveryId: newDeliveryId(),
        orgId: incident.orgId,
        incidentId: incident.incidentId,
        alertIds: await this.opts.store.incidentAlerts(incident.incidentId),
        channel: target.channel,
        destination: target.destination,
        template: opts.templateOverride ?? target.template ?? "incident_card",
        urgency: opts.urgency,
        status: "pending",
        attemptCount: 0,
        maxAttempts: this.opts.maxDeliveryAttempts,
        idempotencyKey: `rte_${opts.triggeringEventId}_${target.channel}_${sha256JcsHex(target.destination).slice(0, 16)}_${opts.escalationStep ?? 0}`,
        ...(opts.escalationStep !== undefined ? { escalationStep: opts.escalationStep } : {}),
        nextAttemptAt: new Date(),
      };
      await this.opts.store.insertDelivery(delivery, null);
      created++;
    }
    return created;
  }

  // --- EscalationDriver (C7, §9) ---------------------------------------------
  async fireStep(incident: Incident, step: { step: number; wait_seconds: number; targets: ChannelTarget[] }, _policy: EscalationPolicy): Promise<void> {
    const egress = await this.egressFor(incident.orgId);
    const allowed = applyEgressPolicy({ targets: step.targets, matchedPolicyIds: [], droppedByEgress: [] }, egress);
    const urgency = urgencyForSeverity(incident.severity) === "critical" ? "critical" : "high"; // §9: bumped one notch
    await this.createDeliveries(incident, allowed.targets, {
      triggeringEventId: `${incident.incidentId}_esc${step.step}_${Date.now()}`,
      urgency,
      escalationStep: step.step,
      templateOverride: "escalation",
    });
    this.opts.metrics.escalationFire(step.step);
    await this.audit("escalate", incident.orgId, { incident_id: incident.incidentId }, {
      step: step.step,
      targets: allowed.targets.map((t) => `${t.channel}:${t.destination}`),
    });
    await this.opts.sinks.publishLifecycle("escalated", `incident/${incident.incidentId}`, {
      incident_id: incident.incidentId,
      org_id: incident.orgId,
      step: step.step,
    });
  }

  async fireExhausted(incident: Incident): Promise<void> {
    // §9: exhausted chains emit a final operational/critical alert to the org
    // fail-safe channel — ALWAYS the org SIEM webhook.
    const failSafe = this.opts.bootstrapChannels.orgSiemWebhook;
    if (failSafe) {
      await this.createDeliveries(incident, [{ channel: "webhook", destination: failSafe, template: "escalation" }], {
        triggeringEventId: `${incident.incidentId}_exhausted_${Date.now()}`,
        urgency: "critical",
      });
    }
    await this.audit("escalate", incident.orgId, { incident_id: incident.incidentId }, {
      exhausted: true,
      fail_safe_delivered: Boolean(failSafe),
    });
    await this.opts.sinks.publishLifecycle("escalated", `incident/${incident.incidentId}`, {
      incident_id: incident.incidentId,
      org_id: incident.orgId,
      exhausted: true,
    });
  }

  // -------------------------------------------------------------------------
  // Acks (§9): API / channel callback / commander. Nonce single-use enforced
  // by the store; the chain stops via stop_on (dueEscalations filters state).
  // -------------------------------------------------------------------------
  async ack(input: { incidentId: string; by: string; note: string; nonce: string }): Promise<"acked" | "already" | "notfound" | "nonce_used"> {
    const now = new Date();
    const result = await this.opts.store.ackIncident(input.incidentId, input.by, input.note, input.nonce, now);
    if (result === "acked") {
      await this.audit("ack", "", { incident_id: input.incidentId }, { by: input.by, note: input.note }, { kind: "user", id: input.by });
      await this.opts.sinks.publishLifecycle("acked", `incident/${input.incidentId}`, {
        incident_id: input.incidentId,
        by: input.by,
      });
    }
    return result;
  }

  async resolve(incidentId: string, actor: string): Promise<void> {
    await this.opts.store.resolveIncident(incidentId, new Date());
    await this.audit("resolve", "", { incident_id: incidentId }, {}, { kind: "commander", id: actor });
    await this.opts.sinks.publishLifecycle("resolved", `incident/${incidentId}`, { incident_id: incidentId, by: actor });
  }

  // -------------------------------------------------------------------------
  // Commander NotifyOrder (§4.2): explicit one-shot notification. Runs the
  // same pipeline; channel_override short-circuits routing but NEVER the
  // egress policy (§13.2) or authz-context rules (§13.1).
  // -------------------------------------------------------------------------
  async notify(order: {
    org_id: string;
    order_id?: string;
    issued_by: string;
    authorization_token_id?: string;
    authorization_token?: string;
    channel_override?: string[];
    severity_floor?: Severity;
    severity?: Severity;
    category?: AlertEvent["category"];
    payload: { title: string; body?: string; context_url?: string };
    requires_ack?: boolean;
    asset?: AlertEvent["asset"];
  }): Promise<IngestResult> {
    const now = new Date();
    const severity = order.severity ?? "info";
    if (order.severity_floor && severityRank(severity) < severityRank(order.severity_floor)) {
      await this.audit("notify", order.org_id, {}, {
        suppressed: "severity_floor",
        severity,
        floor: order.severity_floor,
        issued_by: order.issued_by,
      });
      return { status: "suppressed", reason: "severity_floor" };
    }
    const eventId = `evt_${ulid()}`;
    const event: AlertEvent = {
      schema_version: "1.0",
      event_id: eventId,
      org_id: order.org_id,
      source_module: "commander",
      source_event_id: order.order_id ?? eventId,
      // Each notify is a distinct fingerprint — one-shot orders must never
      // dedup against each other (fingerprint_hint defaults to the order id).
      fingerprint_hint: order.order_id ?? eventId,
      ...(order.authorization_token_id !== undefined ? { authorization_token_id: order.authorization_token_id } : {}),
      title: order.payload.title,
      ...(order.payload.body !== undefined
        ? { description: order.payload.body + (order.payload.context_url ? `\n${order.payload.context_url}` : "") }
        : {}),
      severity,
      confidence: "confirmed",
      category: order.category ?? "operational",
      asset: order.asset ?? { asset_id: "cmd_oneshot", kind: "cloud-resource", identifier: "commander.notify" },
      occurred_at: now.toISOString(),
      dedup_window_seconds: 0,
      requires_ack: order.requires_ack ?? false,
    };
    await this.audit("notify", order.org_id, { event_id: eventId }, {
      issued_by: order.issued_by,
      channel_override: order.channel_override ?? null,
      severity,
    });

    if (!order.channel_override || order.channel_override.length === 0) {
      return this.ingest(event, { receivedAt: now, authorizationToken: order.authorization_token });
    }

    // channel_override: authz + enrich + persist still run; routing is replaced
    // by the override targets, filtered through the org egress policy (§13.2).
    const { event: enriched, effectiveSeverity } = await enrichEvent(event, this.opts.assetCache);
    const verdict = await this.opts.enforcer.verify(enriched, order.authorization_token, now);
    if (verdict.outcome === "rejected") {
      this.opts.metrics.authzReject(verdict.code);
      await this.audit("authz_reject", order.org_id, { event_id: eventId }, { code: verdict.code, reason: verdict.reason });
      return { status: "rejected", code: verdict.code, reason: verdict.reason };
    }
    if (verdict.outcome === "unavailable") {
      await this.audit("authz_hold", order.org_id, { event_id: eventId }, { reason: verdict.reason });
      return { status: "held" };
    }
    const inserted = await this.insertAlertRow(
      enriched,
      { receivedAt: now },
      effectiveSeverity,
      "open",
      verdict.outcome === "verified" ? "verified" : "none",
    );
    if (!inserted) return { status: "duplicate" };

    const { incident } = await correlate(this.opts.store, enriched, effectiveSeverity, now);
    const overrides: ChannelTarget[] = [];
    for (const raw of order.channel_override) {
      const idx = raw.indexOf(":");
      if (idx <= 0) continue;
      overrides.push({ channel: raw.slice(0, idx) as ChannelTarget["channel"], destination: raw.slice(idx + 1) });
    }
    const egress = await this.egressFor(order.org_id);
    const allowed = applyEgressPolicy({ targets: overrides, matchedPolicyIds: ["channel_override"], droppedByEgress: [] }, egress);
    const count = await this.createDeliveries(incident, allowed.targets, {
      triggeringEventId: eventId,
      urgency: urgencyForSeverity(effectiveSeverity),
      templateOverride: "notify",
    });
    await this.audit("route", order.org_id, { incident_id: incident.incidentId, event_id: eventId }, {
      matched_policy_ids: ["channel_override"],
      targets: allowed.targets.map((t) => `${t.channel}:${t.destination}`),
      dropped_by_egress: allowed.droppedByEgress.map((t) => `${t.channel}:${t.destination}`),
    });
    return { status: "processed", incidentId: incident.incidentId, deliveries: count };
  }

  // -------------------------------------------------------------------------
  // herald_test_route (§4.1): dry-run a sample event through enrichment +
  // routing WITHOUT persisting or delivering anything.
  // -------------------------------------------------------------------------
  async testRoute(sample: AlertEvent): Promise<{
    effective_severity: Severity;
    matched_policy_ids: string[];
    targets: ChannelTarget[];
    dropped_by_egress: ChannelTarget[];
  }> {
    const { event: enriched, effectiveSeverity } = await enrichEvent(sample, this.opts.assetCache);
    const hypothetical: Incident = {
      incidentId: "inc_dryrun",
      orgId: enriched.org_id,
      state: "open",
      title: enriched.title,
      severity: effectiveSeverity,
      category: enriched.category,
      sourceModule: enriched.source_module,
      asset: enriched.asset,
      labels: enriched.labels ?? {},
      correlationKey: "dryrun",
      alertCount: 1,
      requiresAck: enriched.requires_ack ?? false,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      escalation: {},
      escalationExhausted: false,
    };
    const policies = await this.policiesFor(enriched.org_id);
    const decision = applyEgressPolicy(routeIncident(policies, hypothetical), await this.egressFor(enriched.org_id));
    return {
      effective_severity: effectiveSeverity,
      matched_policy_ids: decision.matchedPolicyIds,
      targets: decision.targets,
      dropped_by_egress: decision.droppedByEgress,
    };
  }

  // -------------------------------------------------------------------------
  // Policy/egress resolution with bootstrap fallback (§8/§13.2).
  // -------------------------------------------------------------------------
  async policiesFor(orgId: string): Promise<RoutingPolicy[]> {
    const policies = await this.opts.store.routingPolicies(orgId);
    if (policies.length > 0) return policies;
    return bootstrapPolicies(orgId, this.opts.bootstrapChannels, "esc_bootstrap_default");
  }

  async escalationPolicyFor(orgId: string, policyId: string): Promise<EscalationPolicy | null> {
    if (policyId === "esc_bootstrap_default") {
      return defaultEscalationPolicy(orgId, this.opts.bootstrapChannels.slackSecAlerts);
    }
    return this.opts.store.escalationPolicy(orgId, policyId);
  }

  async egressFor(orgId: string): Promise<EgressEntry[] | null> {
    const stored = await this.opts.store.egressPolicy(orgId);
    if (stored) return stored;
    return this.opts.egressSeed?.[orgId] ?? null;
  }
}

/** Config → PipelineOptions convenience (main.ts). */
export function pipelineOptionsFromConfig(
  cfg: HeraldConfig,
  base: Omit<PipelineOptions, "bootstrapChannels" | "egressSeed" | "maxDeliveryAttempts" | "authzRetryMs" | "authzHoldQuarantineMs">,
): PipelineOptions {
  let egressSeed: Record<string, EgressEntry[]> | undefined;
  if (cfg.egressSeedJson) {
    egressSeed = JSON.parse(cfg.egressSeedJson) as Record<string, EgressEntry[]>;
  }
  return {
    ...base,
    bootstrapChannels: {
      ...(cfg.orgSiemWebhookUrl ? { orgSiemWebhook: cfg.orgSiemWebhookUrl } : {}),
      ...(cfg.slackWebhookUrl ? { slackSecAlerts: cfg.slackWebhookUrl } : {}),
    },
    ...(egressSeed !== undefined ? { egressSeed } : {}),
    maxDeliveryAttempts: cfg.maxDeliveryAttempts,
    authzRetryMs: cfg.authzRetryMs,
    authzHoldQuarantineMs: cfg.authzHoldQuarantineMs,
  };
}
