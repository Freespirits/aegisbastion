/**
 * Dispatcher workers (doc 05 C6, §3.2 step 7, §12). Pulls due Delivery rows
 * from the recorded outbox, enforces per-channel/per-destination token buckets
 * (§11 — the bottleneck BY DESIGN), renders templates (Handlebars, sandboxed),
 * applies §13.3 redaction per target evidence grade, sends via the injected
 * DeliverySink (RecordedSink in tests / record mode, LiveSink in production),
 * and writes DeliveryRecords. Failures back off (1,2,4,8,16 min + jitter,
 * max_attempts=6) then DLQ; provider 429s pause only that destination's
 * bucket (Retry-After).
 *
 * Splunk HEC deliveries for the same destination are batched up to 100
 * events per POST (§6).
 */

import { sha256JcsHex } from "@aegisbastion/agent-sdk";
import type { PipelineSinks } from "../pipeline.js";
import type { Metrics } from "../metrics.js";
import type { Store } from "../store.js";
import type { AuditRecord, Channel, Delivery, EgressEntry, Incident } from "../types.js";
import { egressEntryFor } from "../routing.js";
import { redactEventForTarget } from "./redact.js";
import { renderText } from "./templates.js";
import { BucketRegistry, bucketKey } from "./ratelimit.js";
import type { DeliverySink, SendRequest, SendResult } from "./sink.js";
import { sendSplunkBatch, type AdapterContext } from "./adapters.js";
import { mintAckToken, ackCallbackUrl } from "../acktoken.js";

export interface DispatcherOptions {
  store: Store;
  sink: DeliverySink;
  buckets: BucketRegistry;
  metrics: Metrics;
  sinks: PipelineSinks;
  /** Org egress entries resolver (§13.2 re-check at send time). */
  egressFor: (orgId: string) => Promise<EgressEntry[] | null>;
  retryBackoffMinutes: number[];
  maxAttempts: number;
  /** Ack link building for interactive channels (§9). Empty secret = no links. */
  publicBaseUrl: string;
  ackSigningSecret: string;
  /** Splunk batching needs the live adapter path; null in record mode. */
  splunkContext?: AdapterContext | null;
  actor?: string;
}

const SPLUNK_BATCH_MAX = 100; // §6

export class Dispatcher {
  private readonly actor: string;

  constructor(private readonly opts: DispatcherOptions) {
    this.actor = opts.actor ?? "herald";
  }

  private async audit(action: AuditRecord["action"], orgId: string, entityIds: Record<string, string>, detail: Record<string, unknown>): Promise<void> {
    const record: AuditRecord = {
      orgId,
      actor: { kind: "service", id: this.actor },
      action,
      entityIds,
      decisionDetail: detail,
      requestHash: sha256JcsHex({ action, entityIds, detail }),
    };
    try {
      const auditId = await this.opts.store.appendAudit(record);
      await this.opts.sinks.forwardAudit(record, auditId).catch(() => {});
    } catch (err) {
      console.error(`herald: audit append failed for ${action}: ${(err as Error).message}`);
    }
  }

  /** Work all due deliveries once. Returns the number of deliveries attempted. */
  async runDue(now: Date, limit = 100): Promise<number> {
    const due = await this.opts.store.dueDeliveries(now, limit);
    if (due.length === 0) return 0;

    // Splunk HEC: batch per destination (§6, ≤100 events/POST).
    const splunkByDestination = new Map<string, Delivery[]>();
    const singles: Delivery[] = [];
    for (const d of due) {
      if (d.channel === "splunk-hec") {
        const group = splunkByDestination.get(d.destination) ?? [];
        group.push(d);
        splunkByDestination.set(d.destination, group);
      } else {
        singles.push(d);
      }
    }

    let attempted = 0;
    for (const delivery of singles) {
      const bucket = this.opts.buckets.forKey(bucketKey(delivery.channel, delivery.destination));
      if (!bucket.tryTake()) continue; // §11: caps are the bottleneck by design
      await this.attempt(delivery, now, async (req) => this.opts.sink.send(req));
      attempted++;
    }
    for (const group of splunkByDestination.values()) {
      for (let i = 0; i < group.length; i += SPLUNK_BATCH_MAX) {
        const chunk = group.slice(i, i + SPLUNK_BATCH_MAX);
        const first = chunk[0]!;
        const bucket = this.opts.buckets.forKey(bucketKey("splunk-hec", first.destination));
        if (!bucket.tryTake()) continue;
        await this.attemptBatch(chunk, now);
        attempted += chunk.length;
      }
    }
    return attempted;
  }

  private async buildRequest(delivery: Delivery): Promise<SendRequest | null> {
    const incident = await this.opts.store.getIncident(delivery.incidentId);
    if (!incident) return null;
    const alertIds = delivery.alertIds.length > 0 ? delivery.alertIds : await this.opts.store.incidentAlerts(delivery.incidentId);
    const events = [];
    for (const id of alertIds) {
      const row = await this.opts.store.getAlert(id);
      if (row) events.push(row.event);
    }
    const egress = await this.opts.egressFor(delivery.orgId);
    const entry = egressEntryFor(egress, { channel: delivery.channel, destination: delivery.destination });
    const grade = entry?.evidence_grade;
    const alerts = events.map((e) => redactEventForTarget(e, grade));
    const { text, renderError } = renderText(delivery.template, { incident, alerts });
    if (renderError) {
      // §12: render error → plain-text fallback already rendered; flag it.
      await this.audit("deliver_failed", delivery.orgId, { delivery_id: delivery.deliveryId }, {
        render_error: renderError,
        fallback: "plain",
      });
    }
    const req: SendRequest = { delivery, incident, alerts, text, egressEntry: entry };
    if (incident.requiresAck && this.opts.ackSigningSecret && (delivery.channel === "slack" || delivery.channel === "teams")) {
      req.ackUrl = ackCallbackUrl(this.opts.publicBaseUrl, mintAckToken(this.opts.ackSigningSecret, incident.incidentId));
    }
    return req;
  }

  private async attempt(delivery: Delivery, now: Date, send: (req: SendRequest) => Promise<SendResult>): Promise<void> {
    const req = await this.buildRequest(delivery);
    if (!req) {
      await this.opts.store.recordDeliveryAttempt(delivery.deliveryId, {
        ok: false,
        status: "dlq",
        error: "incident missing — cannot render delivery",
      });
      return;
    }
    const result = await send(req);
    await this.recordResult(delivery, result, now);
  }

  private async attemptBatch(chunk: Delivery[], now: Date): Promise<void> {
    const reqs: SendRequest[] = [];
    for (const d of chunk) {
      const req = await this.buildRequest(d);
      if (req) reqs.push(req);
    }
    if (reqs.length === 0) return;
    let result: SendResult;
    if (this.opts.splunkContext) {
      result = await sendSplunkBatch(reqs, this.opts.splunkContext);
    } else {
      // Record mode: the sink captures one representative request per delivery.
      for (const req of reqs) await this.opts.sink.send(req);
      result = { ok: true, providerResponseCode: 200, payloadSnapshot: { events: reqs.length } };
    }
    for (const d of chunk) await this.recordResult(d, result, now);
  }

  private async recordResult(delivery: Delivery, result: SendResult, now: Date): Promise<void> {
    const attemptNumber = delivery.attemptCount + 1;
    if (result.ok) {
      await this.opts.store.recordDeliveryAttempt(delivery.deliveryId, {
        ok: true,
        status: "sent",
        ...(result.providerResponseCode !== undefined ? { providerResponseCode: result.providerResponseCode } : {}),
        ...(result.latencyMs !== undefined ? { latencyMs: result.latencyMs } : {}),
        ...(result.payloadSnapshot !== undefined ? { payloadSnapshot: result.payloadSnapshot } : {}),
      });
      this.opts.metrics.delivery(delivery.channel, "sent", result.latencyMs);
      await this.audit("deliver", delivery.orgId, { delivery_id: delivery.deliveryId, incident_id: delivery.incidentId }, {
        channel: delivery.channel,
        destination: redactDestination(delivery.destination),
        provider_response_code: result.providerResponseCode ?? null,
        latency_ms: result.latencyMs ?? null,
      });
      await this.opts.sinks.publishLifecycle("delivered", `incident/${delivery.incidentId}`, {
        incident_id: delivery.incidentId,
        delivery_id: delivery.deliveryId,
        channel: delivery.channel,
      });
      return;
    }

    // 429 Retry-After (§12): pause only this destination's bucket.
    if (result.retryAfterMs !== undefined) {
      this.opts.buckets.forKey(bucketKey(delivery.channel, delivery.destination)).pauseFor(result.retryAfterMs);
    }
    const exhausted = attemptNumber >= delivery.maxAttempts && result.retryAfterMs === undefined;
    const backoffMs = result.retryAfterMs ?? backoffFor(this.opts.retryBackoffMinutes, attemptNumber);
    const status = exhausted ? "dlq" : "failed";
    await this.opts.store.recordDeliveryAttempt(delivery.deliveryId, {
      ok: false,
      status,
      ...(result.providerResponseCode !== undefined ? { providerResponseCode: result.providerResponseCode } : {}),
      ...(result.latencyMs !== undefined ? { latencyMs: result.latencyMs } : {}),
      error: result.error ?? "unknown delivery failure",
      nextAttemptAt: new Date(now.getTime() + backoffMs),
    });
    this.opts.metrics.delivery(delivery.channel, status);
    await this.audit(exhausted ? "dlq" : "deliver_failed", delivery.orgId, { delivery_id: delivery.deliveryId, incident_id: delivery.incidentId }, {
      channel: delivery.channel,
      destination: redactDestination(delivery.destination),
      attempt: attemptNumber,
      error: (result.error ?? "unknown").slice(0, 500),
      next_attempt_in_ms: exhausted ? null : backoffMs,
    });
    if (exhausted) {
      await this.opts.sinks.publishDlq("delivery_exhausted", {
        delivery_id: delivery.deliveryId,
        incident_id: delivery.incidentId,
        org_id: delivery.orgId,
        channel: delivery.channel,
        destination: delivery.destination,
        attempts: attemptNumber,
        last_error: result.error ?? null,
      });
      await this.opts.sinks.publishLifecycle("failed", `incident/${delivery.incidentId}`, {
        incident_id: delivery.incidentId,
        delivery_id: delivery.deliveryId,
        channel: delivery.channel,
        exhausted: true,
      });
    }
  }
}

/** §12 backoff: 1,2,4,8,16 min with ±10% jitter, clamped at the last rung. */
export function backoffFor(scheduleMinutes: number[], attemptNumber: number, random: () => number = Math.random): number {
  const idx = Math.min(Math.max(attemptNumber - 1, 0), scheduleMinutes.length - 1);
  const base = (scheduleMinutes[idx] ?? 16) * 60_000;
  const jitter = base * 0.1 * (random() * 2 - 1);
  return Math.round(base + jitter);
}

/** Destinations may carry secrets in query strings — audit a redacted form. */
function redactDestination(destination: string): string {
  if (!destination.includes("://")) return destination;
  try {
    const u = new URL(destination);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return "<unparseable>";
  }
}

/** Interval loop wrapper (dispatch scan cadence, config.dispatchScanMs). */
export class DispatchLoop {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly dispatcher: Dispatcher,
    private readonly intervalMs: number,
    private readonly onError: (err: unknown) => void = () => {},
  ) {}

  start(): void {
    this.timer = setInterval(() => {
      this.dispatcher.runDue(new Date()).catch(this.onError);
    }, this.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

/** Channel filter helper for tests. */
export function deliveriesFor(deliveries: Delivery[], channel: Channel): Delivery[] {
  return deliveries.filter((d) => d.channel === channel);
}

/** Incident helper re-exported for the REST surface. */
export type { Incident };
