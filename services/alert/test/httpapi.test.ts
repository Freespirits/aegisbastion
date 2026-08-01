/**
 * REST surface tests: ingest (bare + envelope), schema rejection (400),
 * authz rejection (403), notify + admin scoping (§13.7), ack flow incl.
 * signed callback tokens (§12), policy/egress CRUD, routes/test, health.
 */

import { describe, expect, it, beforeAll, afterAll } from "vitest";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { JwksCache } from "@aegisbastion/agent-sdk";
import { createHttpServer } from "../src/httpapi.js";
import { loadConfig } from "../src/config.js";
import { loadValidators } from "../src/schemas.js";
import { Pipeline } from "../src/pipeline.js";
import { AuthzEnforcer } from "../src/authz/enforce.js";
import { AssetCache } from "../src/enrich.js";
import { MemoryStore } from "../src/db/memory.js";
import { Metrics } from "../src/metrics.js";
import { mintAckToken } from "../src/acktoken.js";
import { exactManifestFetcher, makeKeys, mintToken, offensiveEvent, sampleEvent } from "./helpers.js";
import type { EgressEntry } from "../src/types.js";

const keys = makeKeys("gk-http");
const forged = makeKeys("gk-http");
const manifest = exactManifestFetcher(["api.example.com"]);

const EGRESS: EgressEntry[] = [
  { channel: "webhook", pattern: "siem.example" },
  { channel: "slack", pattern: "hooks.slack.example" },
];

let server: Server;
let base: string;
let store: MemoryStore;

beforeAll(async () => {
  store = new MemoryStore();
  const jwksCache = new JwksCache({ fetchKeys: async () => [keys.publicJwk] });
  const config = loadConfig({
    databaseUrl: "postgres://unused-in-http-test",
    busEnabled: false,
    adminActors: new Set(["cai", "hexstrike-ai"]),
    webhookSigningSecret: "webhook-secret",
    ackSigningSecret: "ack-secret",
  });
  const pipeline = new Pipeline({
    store,
    enforcer: new AuthzEnforcer({ jwksCache, manifestFetcher: manifest.fetcher }),
    assetCache: new AssetCache(null, 60_000),
    sinks: {
      async publishLifecycle() {},
      async publishDlq() {},
      async forwardAudit() {},
    },
    metrics: new Metrics(),
    bootstrapChannels: { orgSiemWebhook: "https://siem.example/hook", slackSecAlerts: "https://hooks.slack.example/T/B/X" },
    egressSeed: { org_acme: EGRESS },
    maxDeliveryAttempts: 3,
    authzRetryMs: 1_000,
    authzHoldQuarantineMs: 900_000,
  });
  server = createHttpServer({
    config,
    pipeline,
    store,
    validators: loadValidators(),
    metrics: new Metrics(),
    readiness: async () => ({ ready: true, checks: { db: true, jwks: true, bus: true } }),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

describe("health + readiness", () => {
  it("GET /healthz and /readyz", async () => {
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
    const readyz = await fetch(`${base}/readyz`);
    expect(readyz.status).toBe(200);
    expect(await readyz.json()).toMatchObject({ ready: true });
  });
});

describe("POST /v1/alerts", () => {
  it("accepts a bare valid AlertEvent (202)", async () => {
    const res = await post("/v1/alerts", sampleEvent({ event_id: "evt_http_1", severity: "high" }));
    expect(res.status).toBe(202);
    expect(await res.json()).toMatchObject({ status: "processed" });
  });

  it("accepts a CloudEvents envelope", async () => {
    const event = sampleEvent({ event_id: "evt_http_2" });
    const res = await post("/v1/alerts", {
      specversion: "1.0",
      id: event.event_id,
      source: "//aegisbastion/monitor",
      type: "com.aegisbastion.alert.v1",
      time: new Date().toISOString(),
      datacontenttype: "application/json",
      data: event,
    });
    expect(res.status).toBe(202);
  });

  it("rejects schema-invalid payloads with 400 + details", async () => {
    const res = await post("/v1/alerts", { schema_version: "1.0", event_id: "evt_bad" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, any>;
    expect(body.error).toContain("invalid AlertEvent");
    expect(body.details.length).toBeGreaterThan(0);
  });

  it("rejects occurred_at outside ±24 h with 400", async () => {
    const res = await post("/v1/alerts", sampleEvent({ event_id: "evt_old", occurred_at: "2020-01-01T00:00:00Z" }));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ code: "OCCURRED_AT_OUT_OF_RANGE" });
  });

  it("forged authorization token → 403 + authz_reject audit", async () => {
    const token = await mintToken(forged, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const res = await post("/v1/alerts", offensiveEvent({ event_id: "evt_forged" }), { "authorization-token": token });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ status: "rejected", code: "AUTHZ_TOKEN_SIGNATURE_INVALID" });
    expect(store.audit.some((a) => a.action === "authz_reject")).toBe(true);
  });

  it("confirmed vuln without a token → 403 (schema requires token id; enforcer rejects missing compact token)", async () => {
    const res = await post("/v1/alerts", offensiveEvent({ event_id: "evt_notoken" }));
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ status: "rejected", code: "AUTHZ_TOKEN_MISSING" });
  });

  it("valid token → 202 processed", async () => {
    const token = await mintToken(keys, { capabilities: ["detect.nuclei"], manifestSha256: manifest.sha256 });
    const res = await post("/v1/alerts", offensiveEvent({ event_id: "evt_valid", severity: "critical" }), {
      "authorization-token": token,
    });
    expect(res.status).toBe(202);
  });

  it("duplicate event_id is idempotent (200)", async () => {
    const event = sampleEvent({ event_id: "evt_idem" });
    expect((await post("/v1/alerts", event)).status).toBe(202);
    const res = await post("/v1/alerts", event);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "duplicate" });
  });
});

describe("queries", () => {
  it("GET /v1/alerts with filters", async () => {
    const res = await fetch(`${base}/v1/alerts?org_id=org_acme&state=open`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.alerts.length).toBeGreaterThan(0);
  });

  it("GET /v1/alerts/{id} and /v1/incidents", async () => {
    const one = await fetch(`${base}/v1/alerts/evt_http_1`);
    expect(one.status).toBe(200);
    const incidents = await fetch(`${base}/v1/incidents?org_id=org_acme`);
    expect(incidents.status).toBe(200);
    expect(((await incidents.json()) as { incidents: unknown[] }).incidents.length).toBeGreaterThan(0);
    expect((await fetch(`${base}/v1/alerts/evt_nope`)).status).toBe(404);
  });
});

describe("POST /v1/notify (§4.2/§13.7)", () => {
  const order = { org_id: "org_acme", payload: { title: "Authorized stress test starting" } };

  it("plain notify works for any actor", async () => {
    const res = await post("/v1/notify", order, { "x-aegisbastion-actor": "op_jane" });
    expect(res.status).toBe(202);
  });

  it("channel_override requires herald:admin", async () => {
    const denied = await post("/v1/notify", { ...order, channel_override: ["slack:#war-room"] }, { "x-aegisbastion-actor": "op_jane" });
    expect(denied.status).toBe(403);
    const allowed = await post("/v1/notify", { ...order, channel_override: ["webhook:https://siem.example/war"] }, { "x-aegisbastion-actor": "cai" });
    expect(allowed.status).toBe(202);
  });

  it("severity_floor suppresses low-severity notifies", async () => {
    const res = await post("/v1/notify", { ...order, severity: "low", severity_floor: "high" });
    expect(res.status).toBe(202);
    expect(await res.json()).toMatchObject({ status: "suppressed", reason: "severity_floor" });
  });
});

describe("acks (§9/§12)", () => {
  it("API ack → acked → already; signed callback token ack; forgery rejected", async () => {
    const res = await post("/v1/alerts", sampleEvent({ event_id: "evt_ackme", fingerprint_hint: "ack-flow-1", severity: "critical", requires_ack: true }));
    const { incidentId } = (await res.json()) as { incidentId: string };

    const ack1 = await post("/v1/acks", { incident_id: incidentId, actor: "user_dana", note: "on it" });
    expect(ack1.status).toBe(200);
    expect(await ack1.json()).toMatchObject({ status: "acked" });

    const ack2 = await post("/v1/acks", { incident_id: incidentId, actor: "user_dana" });
    expect(await ack2.json()).toMatchObject({ status: "already" });

    // Signed channel-callback token (single-use nonce).
    const res2 = await post("/v1/alerts", sampleEvent({ event_id: "evt_ackcb", fingerprint_hint: "ack-flow-2", severity: "critical", requires_ack: true }));
    const { incidentId: inc2 } = (await res2.json()) as { incidentId: string };
    const token = mintAckToken("ack-secret", inc2);
    const cb = await fetch(`${base}/v1/acks?token=${encodeURIComponent(token)}`);
    expect(cb.status).toBe(200);
    expect(await cb.json()).toMatchObject({ status: "acked" });
    const replay = await fetch(`${base}/v1/acks?token=${encodeURIComponent(token)}`);
    expect(replay.status).toBe(409); // nonce replay

    const forgedCb = await fetch(`${base}/v1/acks?token=${encodeURIComponent(mintAckToken("wrong-secret", inc2))}`);
    expect(forgedCb.status).toBe(403);
  });
});

describe("policies + egress (§13.2/§13.7)", () => {
  it("routing policy CRUD requires admin", async () => {
    const policy = { org_id: "org_acme", priority: 50, match: { severity_gte: "high" }, targets: [{ channel: "webhook", destination: "https://siem.example/x" }] };
    expect((await post("/v1/policies/routing", policy)).status).toBe(403);
    const created = await post("/v1/policies/routing", policy, { "x-aegisbastion-actor": "cai" });
    expect(created.status).toBe(201);
    const body = (await created.json()) as Record<string, any>;
    expect(body.policyId).toMatch(/^rp_/);
  });

  it("escalation policy create + fetch", async () => {
    const policy = {
      org_id: "org_acme",
      steps: [{ step: 0, wait_seconds: 0, targets: [{ channel: "slack", destination: "#x" }] }],
      repeat_last_step_every_seconds: 3600,
      max_repeats: 4,
      stop_on: ["ack", "resolved"],
    };
    const created = await post("/v1/policies/escalation", policy, { "x-aegisbastion-actor": "cai" });
    expect(created.status).toBe(201);
  });

  it("egress policy PUT + GET (admin)", async () => {
    const put = await fetch(`${base}/v1/egress/org_acme`, {
      method: "PUT",
      headers: { "content-type": "application/json", "x-aegisbastion-actor": "cai" },
      body: JSON.stringify({ entries: [{ channel: "webhook", pattern: "siem.example", evidence_grade: "full" }] }),
    });
    expect(put.status).toBe(200);
    const got = await fetch(`${base}/v1/egress/org_acme`);
    expect(await got.json()).toMatchObject({ entries: [{ channel: "webhook", pattern: "siem.example" }] });
  });

  it("POST /v1/routes/test is a dry run (no persistence, no delivery)", async () => {
    const before = (await store.listDeliveries({})).length;
    const res = await post("/v1/routes/test", sampleEvent({ severity: "critical" }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.matched_policy_ids.length).toBeGreaterThan(0);
    expect((await store.listDeliveries({})).length).toBe(before);
  });
});

describe("status + metrics", () => {
  it("GET /v1/status and /v1/metrics", async () => {
    const status = await fetch(`${base}/v1/status`);
    expect(status.status).toBe(200);
    expect(await status.json()).toHaveProperty("queue_depth");
    const metrics = await fetch(`${base}/v1/metrics`);
    expect(metrics.status).toBe(200);
    expect(await metrics.text()).toContain("herald_queue_depth");
  });
});
