/**
 * herald dev smoke (doc 05) — runs the service against the compose infra
 * profile (Postgres/NATS/MinIO + gatekeeper + data-platform apps) and
 * exercises the real path end to end:
 *
 *   health/readiness → policy + egress setup (admin actor, §13.7) →
 *   REST ingest → dedup suppression → incident/delivery outbox →
 *   authz fail-closed (missing token, forged token → 403 + alerts.dlq +
 *   authz_reject audit) → bus ingest via monitor.alert → dashboard surface
 *   (policies list, routes/test dry-run, deliveries) → status/metrics.
 *
 * Usage (from services/alert, infra up):
 *   node bin/smoke-dev.mjs
 *
 * Rows use org_id "org_smoke" and are cleaned up afterwards, EXCEPT
 * alert.audit_log which is append-only by design (trigger) — smoke audit
 * rows stay in the dev DB, same convention as test/pgstore.integration.
 */
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import pg from "pg";
import { connect } from "@nats-io/transport-node";
import { jetstream, jetstreamManager } from "@nats-io/jetstream";

const BASE = "http://localhost:8096";
const ORG = "org_smoke";
const DSN = process.env.PG_TEST_DSN ?? "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable";
// dp enrichment seed (doc 09 §5 + TPEL): tenant + service_alert grant + asset.
const DP_TENANT = "0191e2b0-0000-7000-8000-0000000000aa";
const DP_ASSET = "0191e2b0-0000-7000-8000-0000000000bb";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function api(method, path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  let json = null;
  try { json = await res.json(); } catch { /* metrics text */ }
  return { status: res.status, json, text: json === null ? await res.text() : undefined };
}

function sampleEvent(over = {}) {
  return {
    schema_version: "1.0",
    event_id: `evt_smoke_${crypto.randomUUID().replaceAll("-", "").slice(0, 20)}`,
    org_id: ORG,
    source_module: "monitor",
    source_event_id: "mon_smoke_1",
    title: "Smoke: TLS certificate expires soon",
    description: "herald dev smoke event",
    severity: "high",
    confidence: "probable",
    category: "config-drift",
    asset: { asset_id: DP_ASSET, kind: "domain", identifier: "api.smoke.example" },
    pii_classification: "none",
    occurred_at: new Date().toISOString(),
    dedup_window_seconds: 3600,
    renotify_every: 0,
    requires_ack: false,
    labels: { smoke: "true" },
    ...over,
  };
}

// --- start herald -----------------------------------------------------------
const child = spawn(process.execPath, ["dist/main.js"], {
  env: {
    ...process.env,
    DATABASE_URL: DSN,
    NATS_URL: "nats://localhost:4222",
    GATEKEEPER_JWKS_URL: "http://localhost:8080/.well-known/gatekeeper-jwks.json",
    S3_ENDPOINT: "localhost:9000",
    S3_ACCESS_KEY: "aegisbastion",
    S3_SECRET_KEY: "aegisbastion-dev-secret",
    S3_USE_TLS: "false",
    DP_QUERY_URL: "http://localhost:8082",
    HERALD_HTTP_LISTEN: ":8096",
    HERALD_DELIVERY_MODE: "record",
    HERALD_ADMIN_ACTORS: "cai,hexstrike-ai",
    ALERT_WEBHOOK_SIGNING_SECRET: "smoke-secret",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
child.stdout.on("data", (d) => process.stdout.write(`  [herald] ${d}`));
child.stderr.on("data", (d) => process.stdout.write(`  [herald:err] ${d}`));

let nc;
const pool = new pg.Pool({ connectionString: DSN });
try {
  // Seed dp tenancy + asset for the live enrichment check (dev DB only; the
  // dp admin API is disabled in compose — DP_ADMIN_PRINCIPALS is empty).
  await pool.query(`INSERT INTO tenancy.tenants (tenant_id, name) VALUES ($1, 'smoke') ON CONFLICT DO NOTHING`, [DP_TENANT]);
  await pool.query(`INSERT INTO tenancy.grants (tenant_id, principal, role) VALUES ($1, 'herald', 'service_alert') ON CONFLICT DO NOTHING`, [DP_TENANT]);
  await pool.query(
    `INSERT INTO dp.assets (asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id)
     VALUES ($1, $2, 'domain', 'api.smoke.example', $3, 0.9, 'active', now(), now(), 'roe_smoke')
     ON CONFLICT (tenant_id, type, value) DO UPDATE SET attributes = EXCLUDED.attributes`,
    [DP_ASSET, DP_TENANT, JSON.stringify({ criticality: "critical", owner_group: "team-platform" })],
  );

  // wait for HTTP
  let up = false;
  for (let i = 0; i < 60 && !up; i++) {
    await sleep(500);
    up = await fetch(`${BASE}/healthz`).then((r) => r.ok).catch(() => false);
  }
  if (!up) throw new Error("herald did not come up on :8096");

  // 1. health/readiness
  const hz = await api("GET", "/healthz");
  check("GET /healthz", hz.status === 200);
  const rz = await api("GET", "/readyz");
  check("GET /readyz", rz.status === 200 && rz.json.ready === true, JSON.stringify(rz.json?.checks));

  // 2. org egress policy (§13.2) + routing policy (§13.7 admin actor)
  const eg = await api("PUT", `/v1/egress/${ORG}`, {
    entries: [{ channel: "webhook", pattern: "siem.smoke.example" }],
  }, { "x-aegisbastion-actor": "cai" });
  check("PUT /v1/egress/{org} (admin)", eg.status === 200, JSON.stringify(eg.json));

  const rp = await api("POST", "/v1/policies/routing", {
    org_id: ORG, priority: 100,
    match: { severity_gte: "low" },
    targets: [{ channel: "webhook", destination: "https://siem.smoke.example/ingest", template: "raw_json" }],
  }, { "x-aegisbastion-actor": "cai" });
  check("POST /v1/policies/routing (admin)", rp.status === 201, JSON.stringify(rp.json));

  const rpDenied = await api("POST", "/v1/policies/routing", {
    org_id: ORG, priority: 999, targets: [{ channel: "webhook", destination: "https://siem.smoke.example/x" }],
  }, { "x-aegisbastion-actor": "mallory" });
  check("POST /v1/policies/routing (non-admin → 403)", rpDenied.status === 403);

  // 3. schema rejection at ingress
  const bad = await api("POST", "/v1/alerts", { event_id: "evt_smoke_bad", severity: "catastrophic" });
  check("POST /v1/alerts invalid schema → 400", bad.status === 400, JSON.stringify(bad.json?.details?.slice?.(0, 1) ?? bad.json));

  // 4. REST ingest (no authz required: monitor/config-drift/probable)
  const ev1 = sampleEvent();
  const ing1 = await api("POST", "/v1/alerts", ev1);
  check("POST /v1/alerts → 202 processed", ing1.status === 202 && ing1.json.status === "processed", JSON.stringify(ing1.json));

  // 5. dedup: same fingerprint → suppressed
  const ev2 = sampleEvent({ fingerprint_hint: ev1.fingerprint_hint, title: "same fingerprint" });
  const ing2 = await api("POST", "/v1/alerts", ev2);
  check("duplicate fingerprint → suppressed", ing2.status === 202 && ing2.json.status === "suppressed", JSON.stringify(ing2.json));

  // 6. incident + recorded delivery outbox (dispatch loop runs every 2 s — poll)
  const alert1 = await api("GET", `/v1/alerts/${ev1.event_id}`);
  check("GET /v1/alerts/{id} correlated to incident", alert1.status === 200 && typeof alert1.json.incidentId === "string", alert1.json?.incidentId);
  check(
    "enriched via data platform (criticality + owner_group from dp attributes)",
    alert1.json?.event?.asset?.criticality === "critical" && alert1.json?.event?.asset?.owner_group === "team-platform",
    JSON.stringify(alert1.json?.event?.asset),
  );
  let sent = [];
  for (let i = 0; i < 20 && sent.length === 0; i++) {
    await sleep(1000);
    const dlvs = await api("GET", `/v1/deliveries?org_id=${ORG}`);
    sent = dlvs.json?.deliveries?.filter((d) => d.status === "sent") ?? [];
  }
  check("recorded outbox: webhook delivery sent (record mode)", sent.length >= 1, JSON.stringify(sent.map((d) => [d.channel, d.destination, d.status])));

  // 7. authz fail-closed: ddos-engine with token id but NO compact token → 403
  //    (authorization_token_id itself is schema-mandatory for ddos-engine, §5.2)
  const noTok = sampleEvent({
    source_module: "ddos-engine", category: "stress-test", confidence: "confirmed",
    authorization_token_id: "tok_smoke_missing",
    asset: { asset_id: "asset_smoke_2", kind: "domain", identifier: "target.smoke.example" },
  });
  const rNoTok = await api("POST", "/v1/alerts", noTok);
  check("ddos-engine without compact token → 403", rNoTok.status === 403 && String(rNoTok.json?.code ?? "").startsWith("AUTHZ_"), JSON.stringify(rNoTok.json));

  // 8. authz fail-closed: forged token (well-formed JWT, wrong Ed25519 key)
  const { generateKeyPairSync, sign: signCrypto } = await import("node:crypto");
  const { privateKey } = generateKeyPairSync("ed25519");
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const nowSec = Math.floor(Date.now() / 1000);
  const header = b64u({ alg: "EdDSA", typ: "JWT", kid: "gk-forged" });
  const claims = b64u({
    jti: "tok_smoke_forged", iss: "gatekeeper.platform", aud: "aegisbastion.modules",
    task_id: "task_smoke", roe_id: "roe_smoke", risk_class: "R2",
    capabilities: ["stress.http_flood"],
    targets: { manifest_sha256: "00".repeat(32), count: 1 },
    nbf: nowSec - 300, exp: nowSec + 600, iat: nowSec - 300,
  });
  const sig = signCrypto(null, Buffer.from(`${header}.${claims}`), privateKey).toString("base64url");
  const forged = `${header}.${claims}.${sig}`;
  const forgedEv = sampleEvent({
    source_module: "ddos-engine", category: "stress-test", confidence: "confirmed",
    authorization_token_id: "tok_smoke_forged",
    asset: { asset_id: "asset_smoke_2", kind: "domain", identifier: "target.smoke.example" },
  });
  const rForged = await api("POST", "/v1/alerts", forgedEv, { "authorization-token": forged });
  check("forged EdDSA token → 403 refused", rForged.status === 403 && String(rForged.json?.code ?? "").startsWith("AUTHZ_"), JSON.stringify(rForged.json?.code));
  const forgedRow = await api("GET", `/v1/alerts/${forgedEv.event_id}`);
  check("forged alert quarantined (authz_status=rejected)", forgedRow.json?.authzStatus === "rejected", forgedRow.json?.authzStatus);

  // 9. bus ingest: CloudEvents envelope on monitor.alert
  nc = await connect({ servers: "nats://localhost:4222" });
  const js = jetstream(nc);
  const busEv = sampleEvent({ title: "Smoke: bus ingest via monitor.alert" });
  await js.publish("monitor.alert", new TextEncoder().encode(JSON.stringify({
    specversion: "1.0",
    id: busEv.event_id,
    source: "//aegisbastion/monitor",
    type: "com.aegisbastion.alert.v1",
    subject: "asset/asset_smoke_1",
    time: new Date().toISOString(),
    datacontenttype: "application/json",
    data: busEv,
  })));
  let busSeen = false;
  for (let i = 0; i < 20 && !busSeen; i++) {
    await sleep(500);
    busSeen = await api("GET", `/v1/alerts/${busEv.event_id}`).then((r) => r.status === 200);
  }
  check("bus ingest monitor.alert → stored", busSeen);

  // 10. bus DLQ received the forged quarantine
  const jsm = await jetstreamManager(nc);
  const dlqStream = await jsm.streams.info("ALERTS_DLQ").catch(() => null);
  check("alerts.dlq stream has quarantine messages", (dlqStream?.state?.messages ?? 0) >= 1, `messages=${dlqStream?.state?.messages}`);

  // 11. dashboard surface (doc 10 alert-rules client, Ruling C7)
  const listRp = await api("GET", "/v1/policies/routing");
  check("GET /v1/policies/routing (dashboard list)", listRp.status === 200 && Array.isArray(listRp.json?.policies) && listRp.json.policies.some((p) => p.orgId === ORG));
  const dry = await api("POST", "/v1/routes/test", sampleEvent({ event_id: "evt_smoke_dry" }));
  check("POST /v1/routes/test dry-run", dry.status === 200 && Array.isArray(dry.json?.matched_policy_ids ?? dry.json?.matchedPolicyIds ?? []), JSON.stringify(dry.json).slice(0, 200));

  // 12. status + metrics
  const st = await api("GET", "/v1/status");
  check("GET /v1/status", st.status === 200 && typeof st.json.queue_depth === "number", JSON.stringify(st.json));
  const met = await fetch(`${BASE}/v1/metrics`).then((r) => r.text());
  check("GET /v1/metrics (prometheus)", met.includes("herald_"));

  console.log(failures === 0 ? "\nSMOKE OK" : `\nSMOKE FAILED (${failures})`);
} finally {
  if (nc) await nc.close().catch(() => {});
  child.kill("SIGTERM");
  await sleep(500);
  // cleanup (audit_log is append-only by design — smoke audit rows stay)
  // Join table first (no org_id column), then the org-scoped tables in FK order.
  await pool.query(`DELETE FROM alert.incident_alerts WHERE incident_id LIKE 'inc_%' AND event_id LIKE 'evt_smoke%'`).catch(() => {});
  for (const t of ["deliveries", "acks", "alerts", "incidents", "dedup_state", "routing_policies", "escalation_policies", "egress_policies"]) {
    await pool.query(`DELETE FROM alert.${t} WHERE org_id = $1`, [ORG]).catch(() => {});
  }
  // dp enrichment seed.
  await pool.query(`DELETE FROM dp.assets WHERE tenant_id = $1`, [DP_TENANT]).catch(() => {});
  await pool.query(`DELETE FROM tenancy.grants WHERE tenant_id = $1`, [DP_TENANT]).catch(() => {});
  await pool.query(`DELETE FROM tenancy.tenants WHERE tenant_id = $1`, [DP_TENANT]).catch(() => {});
  await pool.end();
}
process.exit(failures === 0 ? 0 : 1);
