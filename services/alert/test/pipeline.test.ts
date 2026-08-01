/**
 * Pipeline integration (in-memory store + recorded outbox): the full
 * ingest → authz → enrich → dedup → correlate → route → dispatch flow,
 * plus the §12 JWKS-outage hold → verify/quarantine path and the recorded
 * (mockable) delivery outbox with backoff + DLQ.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { JwksCache } from "@aegisbastion/agent-sdk";
import { Pipeline, type PipelineSinks } from "../src/pipeline.js";
import { AuthzEnforcer } from "../src/authz/enforce.js";
import { AssetCache } from "../src/enrich.js";
import { MemoryStore } from "../src/db/memory.js";
import { Metrics } from "../src/metrics.js";
import { Dispatcher } from "../src/dispatch/dispatcher.js";
import { RecordedSink } from "../src/dispatch/sink.js";
import { BucketRegistry } from "../src/dispatch/ratelimit.js";
import { exactManifestFetcher, makeKeys, mintToken, offensiveEvent, sampleEvent } from "./helpers.js";
import type { AuditRecord, EgressEntry } from "../src/types.js";

const keys = makeKeys("gk-pipeline");
const manifest = exactManifestFetcher(["api.example.com"]);

const EGRESS: EgressEntry[] = [
  { channel: "webhook", pattern: "siem.example" },
  { channel: "slack", pattern: "hooks.slack.example" },
];

function makeSinks(): PipelineSinks & { lifecycle: string[]; dlq: Record<string, unknown>[]; forwarded: AuditRecord[] } {
  const lifecycle: string[] = [];
  const dlq: Record<string, unknown>[] = [];
  const forwarded: AuditRecord[] = [];
  return {
    lifecycle,
    dlq,
    forwarded,
    async publishLifecycle(transition) {
      lifecycle.push(transition);
    },
    async publishDlq(reason, data) {
      dlq.push({ reason, ...data });
    },
    async forwardAudit(record) {
      forwarded.push(record);
    },
  };
}

function makePipeline(opts: { jwksDown?: boolean; egressSeed?: Record<string, EgressEntry[]>; maxAttempts?: number } = {}) {
  const store = new MemoryStore();
  const jwksCache = new JwksCache({
    fetchKeys: async () => {
      if (opts.jwksDown) throw new Error("connection refused");
      return [keys.publicJwk];
    },
  });
  const enforcer = new AuthzEnforcer({ jwksCache, manifestFetcher: manifest.fetcher });
  const sinks = makeSinks();
  const pipeline = new Pipeline({
    store,
    enforcer,
    assetCache: new AssetCache(null, 60_000),
    sinks,
    metrics: new Metrics(),
    bootstrapChannels: { orgSiemWebhook: "https://siem.example/hook", slackSecAlerts: "https://hooks.slack.example/T/B/X" },
    ...(opts.egressSeed !== undefined ? { egressSeed: opts.egressSeed } : { egressSeed: { org_acme: EGRESS } }),
    maxDeliveryAttempts: opts.maxAttempts ?? 3,
    authzRetryMs: 1_000,
    authzHoldQuarantineMs: 15 * 60 * 1000,
  });
  return { store, pipeline, sinks, jwksCache };
}

function audits(store: MemoryStore): string[] {
  return store.audit.map((a) => a.action);
}

describe("pipeline: passive alert end-to-end", () => {
  let ctx: ReturnType<typeof makePipeline>;
  beforeEach(() => {
    ctx = makePipeline();
  });

  it("ingest → correlate → route → recorded deliveries (bootstrap policies)", async () => {
    const result = await ctx.pipeline.ingest(sampleEvent({ severity: "high" }), { receivedAt: new Date() });
    expect(result.status).toBe("processed");
    if (result.status !== "processed") return;

    const incident = await ctx.store.getIncident(result.incidentId);
    expect(incident).toMatchObject({ orgId: "org_acme", severity: "high", state: "open" });
    expect(result.deliveries).toBe(2); // bootstrap: slack ≥high + SIEM webhook ≥medium
    const deliveries = await ctx.store.listDeliveries({ incidentId: result.incidentId });
    expect(deliveries.map((d) => d.channel).sort()).toEqual(["slack", "webhook"]);
    expect(deliveries.every((d) => d.status === "pending")).toBe(true);

    expect(audits(ctx.store)).toEqual(expect.arrayContaining(["ingest", "correlate", "route"]));
    expect(ctx.sinks.lifecycle).toEqual(expect.arrayContaining(["correlated", "routed"]));
  });

  it("idempotent on event_id (bus at-least-once)", async () => {
    const event = sampleEvent();
    const first = await ctx.pipeline.ingest(event, { receivedAt: new Date() });
    const second = await ctx.pipeline.ingest(event, { receivedAt: new Date() });
    expect(first.status).toBe("processed");
    expect(second.status).toBe("duplicate");
  });

  it("dedup suppresses repeat fingerprints and audits the suppression", async () => {
    const hint = { fingerprint_hint: "cve-2024-3094|443/tcp" };
    const first = await ctx.pipeline.ingest(sampleEvent(hint), { receivedAt: new Date() });
    const second = await ctx.pipeline.ingest(sampleEvent({ ...hint, event_id: "evt_dup" }), { receivedAt: new Date() });
    expect(first.status).toBe("processed");
    expect(second).toEqual({ status: "suppressed", reason: "dedup" });
    const dupAlert = await ctx.store.getAlert("evt_dup");
    expect(dupAlert?.state).toBe("suppressed");
    expect(audits(ctx.store)).toContain("dedup_suppress");
  });

  it("renotify_every routes a still-firing notice on the same incident", async () => {
    const hint = { fingerprint_hint: "fp-1", renotify_every: 2 };
    await ctx.pipeline.ingest(sampleEvent(hint), { receivedAt: new Date() });
    const renotify = await ctx.pipeline.ingest(sampleEvent({ ...hint, event_id: "evt_re" }), { receivedAt: new Date() });
    expect(renotify.status).toBe("renotified");
    if (renotify.status === "renotified") {
      const deliveries = await ctx.store.listDeliveries({ incidentId: renotify.incidentId });
      expect(deliveries.some((d) => d.template === "still_firing")).toBe(true);
    }
  });

  it("egress policy fail-closed: no org policy → targets dropped + audit-flagged", async () => {
    const noSeed = makePipeline({ egressSeed: {} });
    const result = await noSeed.pipeline.ingest(sampleEvent({ severity: "critical" }), { receivedAt: new Date() });
    expect(result.status).toBe("processed");
    if (result.status === "processed") expect(result.deliveries).toBe(0);
    const routeAudit = noSeed.store.audit.find((a) => a.action === "route");
    expect(routeAudit?.decisionDetail.dropped_by_egress).not.toEqual([]);
  });
});

describe("pipeline: authz-context enforcement (§13.1)", () => {
  it("forged token → alert refused, suppressed, audited, quarantined to DLQ", async () => {
    const forged = makeKeys("gk-pipeline"); // same kid, wrong key
    const ctx = makePipeline();
    const token = await mintToken(forged, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const result = await ctx.pipeline.ingest(offensiveEvent(), { receivedAt: new Date(), authorizationToken: token });
    expect(result.status).toBe("rejected");
    if (result.status !== "rejected") return;
    expect(result.code).toBe("AUTHZ_TOKEN_SIGNATURE_INVALID");

    const alert = await ctx.store.getAlert("evt_" + ""); // unknown — fetch by event
    void alert;
    const stored = [...ctx.store.alerts.values()][0];
    expect(stored?.state).toBe("suppressed");
    expect(stored?.authzStatus).toBe("rejected");
    expect(audits(ctx.store)).toContain("authz_reject");
    expect(ctx.sinks.dlq).toHaveLength(1);
    expect(ctx.sinks.dlq[0]).toMatchObject({ reason: "authz_reject", code: "AUTHZ_TOKEN_SIGNATURE_INVALID" });
    expect(await ctx.store.listDeliveries({})).toHaveLength(0); // no token, no notification
  });

  it("valid token → verified claims stored, alert delivered", async () => {
    const ctx = makePipeline();
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const result = await ctx.pipeline.ingest(offensiveEvent({ severity: "critical" }), {
      receivedAt: new Date(),
      authorizationToken: token,
    });
    expect(result.status).toBe("processed");
    const stored = [...ctx.store.alerts.values()][0];
    expect(stored?.authzStatus).toBe("verified");
    expect(stored?.authzClaims).toMatchObject({ jti: "tok_test01", task_id: "task_test01" });
  });

  it("JWKS outage → held, then verified when JWKS recovers (§12)", async () => {
    let down = true;
    const store = new MemoryStore();
    const jwksCache = new JwksCache({
      fetchKeys: async () => {
        if (down) throw new Error("connection refused");
        return [keys.publicJwk];
      },
    });
    const enforcer = new AuthzEnforcer({ jwksCache, manifestFetcher: manifest.fetcher });
    const sinks = makeSinks();
    const pipeline = new Pipeline({
      store,
      enforcer,
      assetCache: new AssetCache(null, 60_000),
      sinks,
      metrics: new Metrics(),
      bootstrapChannels: { orgSiemWebhook: "https://siem.example/hook" },
      egressSeed: { org_acme: EGRESS },
      maxDeliveryAttempts: 3,
      authzRetryMs: 1_000,
      authzHoldQuarantineMs: 15 * 60 * 1000,
    });
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const t0 = new Date();
    const held = await pipeline.ingest(offensiveEvent(), { receivedAt: t0, authorizationToken: token });
    expect(held.status).toBe("held");
    expect(audits(store)).toContain("authz_hold");
    expect(await store.listDeliveries({})).toHaveLength(0); // held ≠ delivered

    // JWKS recovers; the retry loop verifies and resumes the pipeline.
    down = false;
    const resumed = await pipeline.runDueAuthzRetries(new Date(t0.getTime() + 2_000));
    expect(resumed).toBe(1);
    const stored = [...store.alerts.values()][0];
    expect(stored?.authzStatus).toBe("verified");
    expect(stored?.authzClaims?.held_token).toBeUndefined();
    expect(await store.listDeliveries({})).not.toHaveLength(0);
  });

  it("JWKS outage past 15 min → quarantined with VERIFICATION_UNAVAILABLE (fail closed)", async () => {
    const ctx = makePipeline({ jwksDown: true });
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const t0 = new Date();
    expect((await ctx.pipeline.ingest(offensiveEvent(), { receivedAt: t0, authorizationToken: token })).status).toBe("held");

    // Still held (rescheduled) inside the window…
    await ctx.pipeline.runDueAuthzRetries(new Date(t0.getTime() + 2_000));
    expect([...ctx.store.alerts.values()][0]?.authzStatus).toBe("held");

    // …quarantined after it.
    await ctx.pipeline.runDueAuthzRetries(new Date(t0.getTime() + 16 * 60_000));
    const stored = [...ctx.store.alerts.values()][0];
    expect(stored?.authzStatus).toBe("rejected");
    expect(stored?.state).toBe("suppressed");
    expect(ctx.sinks.dlq[0]).toMatchObject({ reason: "authz_reject", code: "AUTHZ_VERIFICATION_UNAVAILABLE" });
  });
});

describe("dispatcher: recorded outbox, rate caps, backoff, DLQ", () => {
  function makeDispatcher(ctx: ReturnType<typeof makePipeline>, sink: RecordedSink, perSecond = 100, burst = 100) {
    return new Dispatcher({
      store: ctx.store,
      sink,
      buckets: new BucketRegistry(perSecond, burst),
      metrics: new Metrics(),
      sinks: ctx.sinks,
      egressFor: (orgId) => ctx.pipeline.egressFor(orgId),
      retryBackoffMinutes: [1, 2, 4, 8, 16],
      maxAttempts: 3,
      publicBaseUrl: "http://herald.test",
      ackSigningSecret: "ack-secret",
    });
  }

  it("sends pending deliveries via the sink and records receipts", async () => {
    const ctx = makePipeline();
    const sink = new RecordedSink();
    const dispatcher = makeDispatcher(ctx, sink);
    await ctx.pipeline.ingest(sampleEvent({ severity: "high" }), { receivedAt: new Date() });
    expect(await dispatcher.runDue(new Date())).toBe(2);
    expect(sink.sent.map((s) => s.delivery.channel).sort()).toEqual(["slack", "webhook"]);
    const deliveries = await ctx.store.listDeliveries({});
    expect(deliveries.every((d) => d.status === "sent" && d.attemptCount === 1)).toBe(true);
    expect(audits(ctx.store)).toContain("deliver");
  });

  it("per-destination token buckets are the bottleneck (§11)", async () => {
    const ctx = makePipeline();
    const sink = new RecordedSink();
    const dispatcher = makeDispatcher(ctx, sink, 1, 1); // 1 msg/s, burst 1
    await ctx.pipeline.ingest(sampleEvent({ severity: "high", fingerprint_hint: "a" }), { receivedAt: new Date() });
    await ctx.pipeline.ingest(sampleEvent({ severity: "high", fingerprint_hint: "b", event_id: "evt_b" }), { receivedAt: new Date() });
    // Two slack deliveries share the default webhook destination.
    const first = await dispatcher.runDue(new Date());
    expect(first).toBeLessThan(4); // capped
    const pending = await ctx.store.listDeliveries({ status: "pending" });
    expect(pending.length).toBeGreaterThan(0);
  });

  it("failures back off and dead-letter after max_attempts (§12)", async () => {
    const ctx = makePipeline({ maxAttempts: 3 });
    const sink = new RecordedSink();
    sink.failChannels.add("webhook");
    const dispatcher = makeDispatcher(ctx, sink);
    await ctx.pipeline.ingest(sampleEvent({ severity: "high" }), { receivedAt: new Date() });

    const t0 = new Date();
    await dispatcher.runDue(t0); // attempt 1 → failed, +1 min (±10% jitter)
    let webhook = (await ctx.store.listDeliveries({ channel: "webhook" }))[0]!;
    expect(webhook.status).toBe("failed");
    expect(webhook.nextAttemptAt.getTime()).toBeGreaterThan(t0.getTime());

    await dispatcher.runDue(new Date(t0.getTime() + 70_000)); // attempt 2 → failed, +2 min
    await dispatcher.runDue(new Date(t0.getTime() + 70_000 + 140_000)); // attempt 3 → DLQ
    webhook = (await ctx.store.listDeliveries({ channel: "webhook" }))[0]!;
    expect(webhook.status).toBe("dlq");
    expect(webhook.attemptCount).toBe(3);
    expect(ctx.sinks.dlq.some((d) => d.reason === "delivery_exhausted")).toBe(true);
    expect(audits(ctx.store)).toContain("dlq");
  });

  it("requires_ack incidents get ack links on interactive channels", async () => {
    const ctx = makePipeline();
    const sink = new RecordedSink();
    const dispatcher = makeDispatcher(ctx, sink);
    await ctx.pipeline.ingest(sampleEvent({ severity: "critical", requires_ack: true }), { receivedAt: new Date() });
    await dispatcher.runDue(new Date());
    const slackSend = sink.sent.find((s) => s.delivery.channel === "slack");
    expect(slackSend?.ackUrl).toMatch(/^http:\/\/herald\.test\/v1\/acks\?token=/);
  });
});

describe("pipeline: acks and escalation attachment", () => {
  it("critical ack-required incidents attach the bootstrap escalation policy; ack stops it", async () => {
    const ctx = makePipeline();
    const result = await ctx.pipeline.ingest(sampleEvent({ severity: "critical", requires_ack: true }), { receivedAt: new Date() });
    expect(result.status).toBe("processed");
    if (result.status !== "processed") return;
    const incident = await ctx.store.getIncident(result.incidentId);
    expect(incident?.escalation.policy_id).toBe("esc_bootstrap_default");
    expect(incident?.escalation.next_fire_at).toBeTruthy();

    expect(await ctx.pipeline.ack({ incidentId: result.incidentId, by: "user_dana", note: "patching", nonce: "n1" })).toBe("acked");
    expect((await ctx.store.getIncident(result.incidentId))?.state).toBe("acknowledged");
    expect(audits(ctx.store)).toContain("ack");
    expect(ctx.sinks.lifecycle).toContain("acked");
  });
});
