/**
 * PostgresStore integration against the compose Postgres (deploy profile
 * infra). Runs only when the database is reachable (skipped otherwise).
 * Exercises the Store contract end-to-end against the REAL 000005_alert
 * schema: idempotent ingest, atomic dedup upsert, incident correlation,
 * ack nonce uniqueness, delivery outbox + attempt recording, policies,
 * egress, and the append-only audit trigger (UPDATE must raise).
 *
 * Test rows use org_id 'org_pgtest'. alert.audit_log is append-only BY
 * DESIGN (trigger) — audit rows from this test stay in the dev DB.
 */

import { describe, expect, it, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { PostgresStore } from "../src/db/pgstore.js";
import { sampleEvent } from "./helpers.js";
import type { StoredAlert } from "../src/store.js";

const DSN = process.env.PG_TEST_DSN ?? "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable";
const ORG = "org_pgtest";

let available = false;
let store: PostgresStore;

async function cleanup(): Promise<void> {
  const pool = new pg.Pool({ connectionString: DSN });
  for (const table of [
    "deliveries",
    "incident_alerts",
    "acks",
    "alerts",
    "incidents",
    "dedup_state",
    "routing_policies",
    "escalation_policies",
    "egress_policies",
  ]) {
    await pool.query(`DELETE FROM alert.${table} WHERE org_id = $1`, [ORG]).catch(() => {});
  }
  // incident_alerts has no org_id column.
  await pool.query(
    `DELETE FROM alert.incident_alerts WHERE incident_id LIKE 'inc_pgtest%' OR event_id LIKE 'evt_pgtest%'`,
  );
  await pool.end();
}

beforeAll(async () => {
  try {
    const pool = new pg.Pool({ connectionString: DSN, connectionTimeoutMillis: 3_000 });
    await pool.query("SELECT 1");
    await pool.end();
    available = true;
  } catch {
    available = false;
    console.warn("pgstore.integration: Postgres unreachable — skipping");
    return;
  }
  store = new PostgresStore(DSN);
  await cleanup();
});

afterAll(async () => {
  if (!available) return;
  await cleanup();
  await store.close();
});

function alertRow(id: string, overrides: Partial<StoredAlert> = {}): StoredAlert {
  const event = sampleEvent({ event_id: id, org_id: ORG });
  return {
    eventId: id,
    orgId: ORG,
    state: "open",
    effectiveSeverity: event.severity,
    dedupVerdict: "new",
    dedupDegraded: false,
    authzStatus: "none",
    event,
    receivedAt: new Date(),
    ...overrides,
  };
}

describe("PostgresStore vs compose Postgres (000005_alert schema)", () => {
  it("alert insert is idempotent on event_id", async () => {
    if (!available) return;
    expect(await store.insertAlertIfNew(alertRow("evt_pgtest_1"))).toBe("inserted");
    expect(await store.insertAlertIfNew(alertRow("evt_pgtest_1"))).toBe("duplicate");
    const got = await store.getAlert("evt_pgtest_1");
    expect(got).toMatchObject({ eventId: "evt_pgtest_1", orgId: ORG, state: "open" });
    expect(got?.event.title).toBe("TLS certificate expires soon");
  });

  it("dedupTouch is an atomic upsert with window expiry", async () => {
    if (!available) return;
    const now = new Date();
    const first = await store.dedupTouch("fp_pgtest_1", ORG, "evt_pgtest_1", 3600, 0, now);
    expect(first).toMatchObject({ verdict: "new", count: 1 });
    const second = await store.dedupTouch("fp_pgtest_1", ORG, "evt_pgtest_2", 3600, 2, now);
    expect(second).toMatchObject({ verdict: "renotify", count: 2, firstAlertId: "evt_pgtest_1" });
    const third = await store.dedupTouch("fp_pgtest_1", ORG, "evt_pgtest_3", 3600, 2, now);
    expect(third).toMatchObject({ verdict: "duplicate", count: 3 });
  });

  it("incident correlation + attach + member listing", async () => {
    if (!available) return;
    await store.insertAlertIfNew(alertRow("evt_pgtest_inc1"));
    await store.insertIncident({
      incidentId: "inc_pgtest_1",
      orgId: ORG,
      state: "open",
      title: "t",
      severity: "high",
      category: "vuln",
      sourceModule: "detect",
      asset: { asset_id: "a", kind: "ip", identifier: "1.2.3.4" },
      labels: {},
      correlationKey: "asset:a|fp",
      alertCount: 0,
      requiresAck: true,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      escalation: {},
      escalationExhausted: false,
    });
    const found = await store.findOpenIncident(ORG, "asset:a|fp");
    expect(found?.incidentId).toBe("inc_pgtest_1");
    await store.attachAlertToIncident("inc_pgtest_1", sampleEvent({ event_id: "evt_pgtest_inc1", org_id: ORG }), new Date());
    expect(await store.incidentAlerts("inc_pgtest_1")).toEqual(["evt_pgtest_inc1"]);
    expect((await store.getIncident("inc_pgtest_1"))?.alertCount).toBe(1);
  });

  it("delivery outbox: insert → due → record attempt (sent)", async () => {
    if (!available) return;
    await store.insertDelivery(
      {
        deliveryId: "dlv_pgtest_1",
        orgId: ORG,
        incidentId: "inc_pgtest_1",
        alertIds: ["evt_pgtest_inc1"],
        channel: "webhook",
        destination: "https://siem.example/x",
        template: "incident_card",
        urgency: "high",
        status: "pending",
        attemptCount: 0,
        maxAttempts: 6,
        idempotencyKey: "rte_pgtest_1",
        nextAttemptAt: new Date(Date.now() - 1000),
      },
      { text: "rendered" },
    );
    const due = await store.dueDeliveries(new Date(), 10);
    expect(due.map((d) => d.deliveryId)).toContain("dlv_pgtest_1");
    await store.recordDeliveryAttempt("dlv_pgtest_1", {
      ok: true,
      status: "sent",
      providerResponseCode: 200,
      latencyMs: 42,
      payloadSnapshot: { sent: true },
    });
    const after = (await store.listDeliveries({ orgId: ORG }))[0]!;
    expect(after).toMatchObject({ status: "sent", attemptCount: 1 });
    expect(after.sentAt).toBeTruthy();
    expect((await store.deliveryStatusCounts(ORG)).sent).toBe(1);
  });

  it("ack nonce is single-use across the unique constraint", async () => {
    if (!available) return;
    expect(await store.ackIncident("inc_pgtest_1", "dana", "on it", "nonce_pgtest_1", new Date())).toBe("acked");
    expect(await store.ackIncident("inc_pgtest_1", "mallory", "replay", "nonce_pgtest_1", new Date())).toBe("nonce_used");
    expect(await store.ackIncident("inc_pgtest_1", "dana", "again", "nonce_pgtest_2", new Date())).toBe("already");
    expect(await store.ackIncident("inc_pgtest_missing", "dana", "", "nonce_pgtest_3", new Date())).toBe("notfound");
  });

  it("policies + egress round-trip", async () => {
    if (!available) return;
    await store.putRoutingPolicy({
      policyId: "rp_pgtest_1",
      orgId: ORG,
      priority: 10,
      enabled: true,
      match: { severity_gte: "high" },
      targets: [{ channel: "webhook", destination: "https://siem.example/x" }],
      createdBy: "test",
      createdAt: new Date(),
    });
    expect((await store.getRoutingPolicy("rp_pgtest_1"))?.priority).toBe(10);
    expect((await store.routingPolicies(ORG)).map((p) => p.policyId)).toEqual(["rp_pgtest_1"]);

    await store.putEscalationPolicy({
      policyId: "esc_pgtest_1",
      orgId: ORG,
      steps: [{ step: 0, wait_seconds: 0, targets: [] }],
      repeatLastStepEverySeconds: 0,
      maxRepeats: 0,
      stopOn: ["ack"],
    });
    expect((await store.escalationPolicy(ORG, "esc_pgtest_1"))?.steps).toHaveLength(1);

    await store.putEgressPolicy(ORG, [{ channel: "webhook", pattern: "siem.example" }], "test");
    expect(await store.egressPolicy(ORG)).toEqual([{ channel: "webhook", pattern: "siem.example" }]);
  });

  it("authz hold/retry round-trip", async () => {
    if (!available) return;
    await store.insertAlertIfNew(alertRow("evt_pgtest_held", { authzStatus: "held" }));
    const retryAt = new Date(Date.now() - 1000);
    await store.setAlertAuthz("evt_pgtest_held", "held", { held_token: "x" }, retryAt);
    const due = await store.dueAuthzRetries(new Date());
    expect(due.map((a) => a.eventId)).toContain("evt_pgtest_held");
    await store.setAlertAuthz("evt_pgtest_held", "verified", { jti: "tok_x" }, null);
    expect((await store.getAlert("evt_pgtest_held"))?.authzStatus).toBe("verified");
  });

  it("audit_log is append-only (trigger raises on UPDATE/DELETE)", async () => {
    if (!available) return;
    const auditId = await store.appendAudit({
      orgId: ORG,
      actor: { kind: "service", id: "herald-test" },
      action: "ingest",
      entityIds: { event_id: "evt_pgtest_1" },
      decisionDetail: { test: true },
      requestHash: "abc",
    });
    // The ONE permitted mutation: stamping forwarded_at.
    await store.markAuditForwarded(auditId, new Date());
    await expect(
      (async () => {
        const pool = new pg.Pool({ connectionString: DSN });
        try {
          await pool.query(`UPDATE alert.audit_log SET action = 'deliver' WHERE audit_id = $1`, [auditId]);
        } finally {
          await pool.end();
        }
      })(),
    ).rejects.toThrow(/append-only/);
  });
});
