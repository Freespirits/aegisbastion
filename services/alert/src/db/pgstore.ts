/**
 * PostgresStore — the production Store (db/migrations/000005_alert.up.sql).
 * All statements are schema-qualified (`alert.*`): the compose stanza for
 * herald sets no DB_SEARCH_PATH, and schema-per-context is the platform
 * convention (deploy/docker-compose.yml postgres service comment).
 */

import pg from "pg";
import type {
  AlertEvent,
  AlertState,
  AuthzStatus,
  AuditRecord,
  Delivery,
  DeliveryStatus,
  EgressEntry,
  EscalationPolicy,
  Incident,
  IncidentState,
  RoutingPolicy,
} from "../types.js";
import type {
  AlertFilter,
  DedupOutcome,
  DeliveryAttemptResult,
  DeliveryFilter,
  IncidentFilter,
  Store,
  StoredAlert,
} from "../store.js";
import { dedupVerdictFor } from "./memory.js";
import { fingerprintFor } from "../dedup.js";
import { newAuditId } from "../ids.js";

const { Pool } = pg;

function mapAlertRow(r: Record<string, unknown>): StoredAlert {
  return {
    eventId: r.event_id as string,
    orgId: r.org_id as string,
    state: r.state as AlertState,
    effectiveSeverity: r.effective_severity as StoredAlert["effectiveSeverity"],
    dedupVerdict: r.dedup_verdict as StoredAlert["dedupVerdict"],
    dedupDegraded: r.dedup_degraded as boolean,
    authzStatus: r.authz_status as AuthzStatus,
    incidentId: (r.incident_id as string | null) ?? undefined,
    receivedAt: new Date(r.received_at as string),
    authzClaims: (r.authz as Record<string, unknown> | null) ?? undefined,
    event: r.raw as unknown as AlertEvent,
  };
}

function mapIncidentRow(r: Record<string, unknown>): Incident {
  return {
    incidentId: r.incident_id as string,
    orgId: r.org_id as string,
    state: r.state as IncidentState,
    title: r.title as string,
    severity: r.severity as Incident["severity"],
    category: r.category as Incident["category"],
    sourceModule: r.source_module as Incident["sourceModule"],
    asset: r.asset as Incident["asset"],
    labels: (r.labels as Record<string, string>) ?? {},
    correlationKey: r.correlation_key as string,
    alertCount: r.alert_count as number,
    requiresAck: r.requires_ack as boolean,
    firstSeenAt: new Date(r.first_seen_at as string),
    lastSeenAt: new Date(r.last_seen_at as string),
    ack: (r.ack as Incident["ack"] | null) ?? undefined,
    escalation: (r.escalation as Incident["escalation"]) ?? {},
    escalationExhausted: r.escalation_exhausted as boolean,
  };
}

function mapDeliveryRow(r: Record<string, unknown>): Delivery {
  return {
    deliveryId: r.delivery_id as string,
    orgId: r.org_id as string,
    incidentId: r.incident_id as string,
    alertIds: (r.alert_ids as string[]) ?? [],
    channel: r.channel as Delivery["channel"],
    destination: r.destination as string,
    template: r.template as string,
    urgency: r.urgency as Delivery["urgency"],
    status: r.status as DeliveryStatus,
    attemptCount: r.attempt_count as number,
    maxAttempts: r.max_attempts as number,
    idempotencyKey: r.idempotency_key as string,
    escalationStep: (r.escalation_step as number | null) ?? undefined,
    nextAttemptAt: new Date(r.next_attempt_at as string),
    sentAt: r.sent_at ? new Date(r.sent_at as string) : undefined,
    error: (r.error as string | null) ?? undefined,
  };
}

export class PostgresStore implements Store {
  private readonly pool: pg.Pool;

  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl, max: 10 });
  }

  async ping(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async insertAlertIfNew(row: StoredAlert): Promise<"inserted" | "duplicate"> {
    const e = row.event;
    const res = await this.pool.query(
      `INSERT INTO alert.alerts (
         event_id, org_id, source_module, source_event_id, engagement_id,
         authorization_token_id, title, description, severity, effective_severity,
         confidence, category, asset, evidence, pii_classification, occurred_at,
         fingerprint, fingerprint_hint, dedup_window_seconds, renotify_every,
         requires_ack, labels, state, dedup_verdict, dedup_degraded,
         authz_status, authz, raw)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING event_id`,
      [
        e.event_id,
        e.org_id,
        e.source_module,
        e.source_event_id,
        e.engagement_id ?? null,
        e.authorization_token_id ?? null,
        e.title,
        e.description ?? "",
        e.severity,
        row.effectiveSeverity,
        e.confidence,
        e.category,
        JSON.stringify(e.asset),
        e.evidence ? JSON.stringify(e.evidence) : null,
        e.pii_classification ?? "none",
        e.occurred_at,
        fingerprintFor(e), // §7.1 fingerprint, computed at insert (dedup stage re-derives the same value)
        e.fingerprint_hint ?? "",
        e.dedup_window_seconds ?? 86400,
        e.renotify_every ?? 0,
        e.requires_ack ?? false,
        JSON.stringify(e.labels ?? {}),
        row.state,
        row.dedupVerdict,
        row.dedupDegraded,
        row.authzStatus,
        row.authzClaims ? JSON.stringify(row.authzClaims) : null,
        JSON.stringify(e),
      ],
    );
    return res.rowCount === 1 ? "inserted" : "duplicate";
  }

  /** Fingerprint is computed in the dedup stage; stamp it there. */
  async setAlertFingerprint(eventId: string, fingerprint: string): Promise<void> {
    await this.pool.query(`UPDATE alert.alerts SET fingerprint = $2 WHERE event_id = $1`, [eventId, fingerprint]);
  }

  async getAlert(eventId: string): Promise<StoredAlert | null> {
    const res = await this.pool.query(`SELECT * FROM alert.alerts WHERE event_id = $1`, [eventId]);
    return res.rows[0] ? mapAlertRow(res.rows[0]) : null;
  }

  async listAlerts(filter: AlertFilter): Promise<StoredAlert[]> {
    const where: string[] = [];
    const args: unknown[] = [];
    if (filter.orgId) {
      args.push(filter.orgId);
      where.push(`org_id = $${args.length}`);
    }
    if (filter.state) {
      args.push(filter.state);
      where.push(`state = $${args.length}`);
    }
    if (filter.incidentId) {
      args.push(filter.incidentId);
      where.push(`incident_id = $${args.length}`);
    }
    if (filter.severityGte) {
      args.push(filter.severityGte);
      where.push(
        `array_position(ARRAY['info','low','medium','high','critical'], effective_severity) >= array_position(ARRAY['info','low','medium','high','critical'], $${args.length})`,
      );
    }
    if (filter.cursor) {
      args.push(filter.cursor);
      where.push(`(received_at, event_id) < (SELECT received_at, event_id FROM alert.alerts WHERE event_id = $${args.length})`);
    }
    args.push(filter.limit ?? 100);
    const sql = `SELECT * FROM alert.alerts ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
                 ORDER BY received_at DESC, event_id DESC LIMIT $${args.length}`;
    const res = await this.pool.query(sql, args);
    return res.rows.map(mapAlertRow);
  }

  async setAlertState(eventId: string, state: AlertState): Promise<void> {
    await this.pool.query(`UPDATE alert.alerts SET state = $2 WHERE event_id = $1`, [eventId, state]);
  }

  async setAlertAuthz(
    eventId: string,
    status: AuthzStatus,
    claims?: Record<string, unknown>,
    retryAt?: Date | null,
  ): Promise<void> {
    await this.pool.query(
      `UPDATE alert.alerts SET authz_status = $2,
         authz = COALESCE($3, authz),
         authz_retry_at = $4
       WHERE event_id = $1`,
      [eventId, status, claims ? JSON.stringify(claims) : null, retryAt ?? null],
    );
  }

  async setAlertIncident(eventId: string, incidentId: string): Promise<void> {
    await this.pool.query(`UPDATE alert.alerts SET incident_id = $2 WHERE event_id = $1`, [eventId, incidentId]);
  }

  async setAlertDedup(eventId: string, verdict: "new" | "duplicate" | "renotify", degraded: boolean): Promise<void> {
    await this.pool.query(`UPDATE alert.alerts SET dedup_verdict = $2, dedup_degraded = $3 WHERE event_id = $1`, [
      eventId,
      verdict,
      degraded,
    ]);
  }

  async dueAuthzRetries(now: Date): Promise<StoredAlert[]> {
    const res = await this.pool.query(
      `SELECT * FROM alert.alerts WHERE authz_status = 'held' AND authz_retry_at IS NOT NULL AND authz_retry_at <= $1
       ORDER BY authz_retry_at LIMIT 100`,
      [now],
    );
    return res.rows.map(mapAlertRow);
  }

  async dedupTouch(
    fingerprint: string,
    orgId: string,
    alertId: string,
    windowSeconds: number,
    renotifyEvery: number,
    _now: Date,
  ): Promise<DedupOutcome> {
    // Single atomic upsert. Only live (unexpired) rows increment; an expired
    // row is replaced below. DB now() is the clock source (§12 clock rule).
    const res = await this.pool.query(
      `INSERT INTO alert.dedup_state (fingerprint, org_id, alert_id, occurrence_count, first_seen_at, last_seen_at, expires_at)
       VALUES ($1, $2, $3, 1, now(), now(), LEAST(now() + make_interval(secs => $4), now() + interval '7 days'))
       ON CONFLICT (fingerprint) DO UPDATE
         SET occurrence_count = alert.dedup_state.occurrence_count + 1,
             last_seen_at = now(),
             expires_at = LEAST(now() + make_interval(secs => $4), alert.dedup_state.first_seen_at + interval '7 days')
         WHERE alert.dedup_state.expires_at > now()
       RETURNING occurrence_count, alert_id`,
      [fingerprint, orgId, alertId, windowSeconds],
    );
    if (res.rows[0]) {
      const count = res.rows[0].occurrence_count as number;
      return {
        verdict: dedupVerdictFor(count, renotifyEvery),
        count,
        firstAlertId: res.rows[0].alert_id as string,
        degraded: false,
      };
    }
    // Fingerprint exists but expired: evict and retry as fresh (§7.1 window).
    await this.pool.query(`DELETE FROM alert.dedup_state WHERE fingerprint = $1 AND expires_at <= now()`, [fingerprint]);
    const retry = await this.pool.query(
      `INSERT INTO alert.dedup_state (fingerprint, org_id, alert_id, occurrence_count, first_seen_at, last_seen_at, expires_at)
       VALUES ($1, $2, $3, 1, now(), now(), LEAST(now() + make_interval(secs => $4), now() + interval '7 days'))
       ON CONFLICT (fingerprint) DO NOTHING
       RETURNING occurrence_count, alert_id`,
      [fingerprint, orgId, alertId, windowSeconds],
    );
    if (retry.rows[0]) {
      return { verdict: "new", count: 1, firstAlertId: alertId, degraded: false };
    }
    // A racer won between DELETE and INSERT — treat as duplicate of their row.
    const winner = await this.pool.query(
      `SELECT alert_id, occurrence_count FROM alert.dedup_state WHERE fingerprint = $1`,
      [fingerprint],
    );
    const count = (winner.rows[0]?.occurrence_count as number | undefined) ?? 2;
    return {
      verdict: dedupVerdictFor(Math.max(count, 2), renotifyEvery),
      count,
      firstAlertId: (winner.rows[0]?.alert_id as string | undefined) ?? alertId,
      degraded: false,
    };
  }

  async findOpenIncident(orgId: string, correlationKey: string): Promise<Incident | null> {
    const res = await this.pool.query(
      `SELECT * FROM alert.incidents
       WHERE org_id = $1 AND correlation_key = $2 AND state IN ('open','acknowledged','escalated')
       ORDER BY first_seen_at DESC LIMIT 1`,
      [orgId, correlationKey],
    );
    return res.rows[0] ? mapIncidentRow(res.rows[0]) : null;
  }

  async insertIncident(incident: Incident): Promise<void> {
    await this.pool.query(
      `INSERT INTO alert.incidents (
         incident_id, org_id, state, title, severity, category, source_module, asset, labels,
         correlation_key, alert_count, requires_ack, first_seen_at, last_seen_at, ack, escalation,
         escalation_exhausted)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [
        incident.incidentId,
        incident.orgId,
        incident.state,
        incident.title,
        incident.severity,
        incident.category,
        incident.sourceModule,
        JSON.stringify(incident.asset),
        JSON.stringify(incident.labels),
        incident.correlationKey,
        incident.alertCount,
        incident.requiresAck,
        incident.firstSeenAt,
        incident.lastSeenAt,
        incident.ack ? JSON.stringify(incident.ack) : null,
        JSON.stringify(incident.escalation),
        incident.escalationExhausted,
      ],
    );
  }

  async getIncident(incidentId: string): Promise<Incident | null> {
    const res = await this.pool.query(`SELECT * FROM alert.incidents WHERE incident_id = $1`, [incidentId]);
    return res.rows[0] ? mapIncidentRow(res.rows[0]) : null;
  }

  async listIncidents(filter: IncidentFilter): Promise<Incident[]> {
    const where: string[] = [];
    const args: unknown[] = [];
    if (filter.orgId) {
      args.push(filter.orgId);
      where.push(`org_id = $${args.length}`);
    }
    if (filter.state) {
      args.push(filter.state);
      where.push(`state = $${args.length}`);
    }
    if (filter.severityGte) {
      args.push(filter.severityGte);
      where.push(
        `array_position(ARRAY['info','low','medium','high','critical'], severity) >= array_position(ARRAY['info','low','medium','high','critical'], $${args.length})`,
      );
    }
    args.push(filter.limit ?? 100);
    const res = await this.pool.query(
      `SELECT * FROM alert.incidents ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
       ORDER BY last_seen_at DESC, incident_id DESC LIMIT $${args.length}`,
      args,
    );
    return res.rows.map(mapIncidentRow);
  }

  async attachAlertToIncident(incidentId: string, event: AlertEvent, now: Date): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO alert.incident_alerts (incident_id, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [incidentId, event.event_id],
      );
      await client.query(
        `UPDATE alert.incidents SET
           alert_count = (SELECT count(*) FROM alert.incident_alerts WHERE incident_id = $1),
           last_seen_at = $2,
           severity = CASE
             WHEN array_position(ARRAY['info','low','medium','high','critical'], $3)
                > array_position(ARRAY['info','low','medium','high','critical'], severity)
             THEN $3 ELSE severity END,
           requires_ack = requires_ack OR $4,
           updated_at = now()
         WHERE incident_id = $1`,
        [incidentId, now, event.severity, event.requires_ack ?? false],
      );
      await client.query(`UPDATE alert.alerts SET incident_id = $2 WHERE event_id = $1`, [event.event_id, incidentId]);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async incidentAlerts(incidentId: string): Promise<string[]> {
    const res = await this.pool.query(
      `SELECT event_id FROM alert.incident_alerts WHERE incident_id = $1 ORDER BY attached_at`,
      [incidentId],
    );
    return res.rows.map((r) => r.event_id as string);
  }

  async ackIncident(
    incidentId: string,
    by: string,
    note: string,
    nonce: string,
    now: Date,
  ): Promise<"acked" | "already" | "notfound" | "nonce_used"> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      try {
        await client.query(
          `INSERT INTO alert.acks (ack_id, org_id, incident_id, actor, note, nonce, created_at)
           SELECT $1, org_id, $2, $3, $4, $5, $6 FROM alert.incidents WHERE incident_id = $2`,
          [`ack_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`, incidentId, by, note, nonce, now],
        );
      } catch (err) {
        if ((err as { code?: string }).code === "23505") {
          await client.query("ROLLBACK");
          return "nonce_used";
        }
        throw err;
      }
      const res = await client.query(
        `UPDATE alert.incidents SET state = 'acknowledged', ack = $2, updated_at = now()
         WHERE incident_id = $1 AND state NOT IN ('acknowledged','resolved') RETURNING incident_id`,
        [incidentId, JSON.stringify({ by, at: now.toISOString(), note })],
      );
      if (res.rowCount === 0) {
        const exists = await client.query(`SELECT 1 FROM alert.incidents WHERE incident_id = $1`, [incidentId]);
        await client.query("ROLLBACK");
        return exists.rowCount === 0 ? "notfound" : "already";
      }
      // Ack cascades to member alerts (§7.3 transitions via ack callback).
      await client.query(
        `UPDATE alert.alerts SET state = 'acknowledged' WHERE incident_id = $1 AND state = 'open'`,
        [incidentId],
      );
      await client.query("COMMIT");
      return "acked";
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async resolveIncident(incidentId: string, _now: Date): Promise<void> {
    await this.pool.query(
      `UPDATE alert.incidents SET state = 'resolved', updated_at = now() WHERE incident_id = $1`,
      [incidentId],
    );
    await this.pool.query(
      `UPDATE alert.alerts SET state = 'resolved' WHERE incident_id = $1 AND state IN ('open','acknowledged')`,
      [incidentId],
    );
  }

  async setIncidentEscalation(
    incidentId: string,
    escalation: Incident["escalation"],
    state?: "open" | "escalated",
    exhausted?: boolean,
  ): Promise<void> {
    await this.pool.query(
      `UPDATE alert.incidents SET escalation = $2,
         state = COALESCE($3, state),
         escalation_exhausted = COALESCE($4, escalation_exhausted),
         updated_at = now()
       WHERE incident_id = $1`,
      [incidentId, JSON.stringify(escalation), state ?? null, exhausted ?? null],
    );
  }

  async dueEscalations(now: Date): Promise<Incident[]> {
    const res = await this.pool.query(
      `SELECT * FROM alert.incidents
       WHERE requires_ack AND state IN ('open','escalated')
         AND escalation->>'next_fire_at' IS NOT NULL
         AND (escalation->>'next_fire_at')::timestamptz <= $1
       ORDER BY (escalation->>'next_fire_at')::timestamptz LIMIT 100`,
      [now],
    );
    return res.rows.map(mapIncidentRow);
  }

  async routingPolicies(orgId: string): Promise<RoutingPolicy[]> {
    // Empty orgId = control-plane list across orgs (the doc 10 alert-rules UI
    // calls GET /v1/policies/routing unfiltered, Ruling C7). The pipeline's
    // route evaluation always queries with the event's concrete org.
    const res = orgId === ""
      ? await this.pool.query(
          `SELECT * FROM alert.routing_policies WHERE enabled ORDER BY org_id, priority, created_at`,
        )
      : await this.pool.query(
          `SELECT * FROM alert.routing_policies WHERE org_id = $1 AND enabled ORDER BY priority, created_at`,
          [orgId],
        );
    return res.rows.map((r) => ({
      policyId: r.policy_id as string,
      orgId: r.org_id as string,
      priority: r.priority as number,
      enabled: r.enabled as boolean,
      match: r.match as RoutingPolicy["match"],
      targets: r.targets as RoutingPolicy["targets"],
      escalationPolicyId: (r.escalation_policy_id as string | null) ?? undefined,
      suppressIfAcknowledgedWithin: (r.suppress_if_acknowledged_within as number | null) ?? undefined,
      createdBy: r.created_by as string,
      createdAt: new Date(r.created_at as string),
    }));
  }

  async getRoutingPolicy(policyId: string): Promise<RoutingPolicy | null> {
    const res = await this.pool.query(`SELECT * FROM alert.routing_policies WHERE policy_id = $1`, [policyId]);
    const r = res.rows[0];
    if (!r) return null;
    return {
      policyId: r.policy_id as string,
      orgId: r.org_id as string,
      priority: r.priority as number,
      enabled: r.enabled as boolean,
      match: r.match as RoutingPolicy["match"],
      targets: r.targets as RoutingPolicy["targets"],
      escalationPolicyId: (r.escalation_policy_id as string | null) ?? undefined,
      suppressIfAcknowledgedWithin: (r.suppress_if_acknowledged_within as number | null) ?? undefined,
      createdBy: r.created_by as string,
      createdAt: new Date(r.created_at as string),
    };
  }

  async putRoutingPolicy(policy: RoutingPolicy): Promise<void> {
    await this.pool.query(
      `INSERT INTO alert.routing_policies
         (policy_id, org_id, priority, enabled, match, targets, escalation_policy_id,
          suppress_if_acknowledged_within, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (policy_id) DO UPDATE SET
         priority = EXCLUDED.priority, enabled = EXCLUDED.enabled, match = EXCLUDED.match,
         targets = EXCLUDED.targets, escalation_policy_id = EXCLUDED.escalation_policy_id,
         suppress_if_acknowledged_within = EXCLUDED.suppress_if_acknowledged_within,
         version = alert.routing_policies.version + 1, updated_at = now()`,
      [
        policy.policyId,
        policy.orgId,
        policy.priority,
        policy.enabled,
        JSON.stringify(policy.match),
        JSON.stringify(policy.targets),
        policy.escalationPolicyId ?? null,
        policy.suppressIfAcknowledgedWithin ?? null,
        policy.createdBy,
      ],
    );
  }

  async escalationPolicy(orgId: string, policyId: string): Promise<EscalationPolicy | null> {
    const res = await this.pool.query(
      `SELECT * FROM alert.escalation_policies WHERE org_id = $1 AND policy_id = $2`,
      [orgId, policyId],
    );
    const r = res.rows[0];
    if (!r) return null;
    return {
      policyId: r.policy_id as string,
      orgId: r.org_id as string,
      steps: r.steps as EscalationPolicy["steps"],
      repeatLastStepEverySeconds: r.repeat_last_step_every_seconds as number,
      maxRepeats: r.max_repeats as number,
      stopOn: r.stop_on as string[],
    };
  }

  async putEscalationPolicy(policy: EscalationPolicy): Promise<void> {
    await this.pool.query(
      `INSERT INTO alert.escalation_policies
         (policy_id, org_id, steps, repeat_last_step_every_seconds, max_repeats, stop_on, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'herald')
       ON CONFLICT (policy_id) DO UPDATE SET
         steps = EXCLUDED.steps, repeat_last_step_every_seconds = EXCLUDED.repeat_last_step_every_seconds,
         max_repeats = EXCLUDED.max_repeats, stop_on = EXCLUDED.stop_on,
         version = alert.escalation_policies.version + 1, updated_at = now()`,
      [
        policy.policyId,
        policy.orgId,
        JSON.stringify(policy.steps),
        policy.repeatLastStepEverySeconds,
        policy.maxRepeats,
        JSON.stringify(policy.stopOn),
      ],
    );
  }

  async egressPolicy(orgId: string): Promise<EgressEntry[] | null> {
    const res = await this.pool.query(`SELECT entries FROM alert.egress_policies WHERE org_id = $1`, [orgId]);
    return res.rows[0] ? (res.rows[0].entries as EgressEntry[]) : null;
  }

  async putEgressPolicy(orgId: string, entries: EgressEntry[], updatedBy: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO alert.egress_policies (org_id, entries, updated_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (org_id) DO UPDATE SET
         entries = EXCLUDED.entries, updated_by = EXCLUDED.updated_by,
         version = alert.egress_policies.version + 1, updated_at = now()`,
      [orgId, JSON.stringify(entries), updatedBy],
    );
  }

  async insertDelivery(delivery: Delivery, payloadSnapshot: unknown): Promise<void> {
    await this.pool.query(
      `INSERT INTO alert.deliveries
         (delivery_id, org_id, incident_id, alert_ids, channel, destination, template, payload,
          urgency, status, attempt_count, max_attempts, idempotency_key, escalation_step, next_attempt_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       ON CONFLICT (org_id, idempotency_key) DO NOTHING`,
      [
        delivery.deliveryId,
        delivery.orgId,
        delivery.incidentId,
        JSON.stringify(delivery.alertIds),
        delivery.channel,
        delivery.destination,
        delivery.template,
        payloadSnapshot ? JSON.stringify(payloadSnapshot) : null,
        delivery.urgency,
        delivery.status,
        delivery.attemptCount,
        delivery.maxAttempts,
        delivery.idempotencyKey,
        delivery.escalationStep ?? null,
        delivery.nextAttemptAt,
      ],
    );
  }

  async dueDeliveries(now: Date, limit: number): Promise<Delivery[]> {
    const res = await this.pool.query(
      `SELECT * FROM alert.deliveries
       WHERE status IN ('pending','failed') AND next_attempt_at <= $1
       ORDER BY next_attempt_at LIMIT $2`,
      [now, limit],
    );
    return res.rows.map(mapDeliveryRow);
  }

  async recordDeliveryAttempt(deliveryId: string, result: DeliveryAttemptResult): Promise<void> {
    await this.pool.query(
      `UPDATE alert.deliveries SET
         attempt_count = attempt_count + 1,
         status = $2,
         attempts = attempts || $3::jsonb,
         provider_response_code = COALESCE($4, provider_response_code),
         latency_ms = COALESCE($5, latency_ms),
         error = $6,
         next_attempt_at = COALESCE($7, next_attempt_at),
         sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END,
         payload = COALESCE($8, payload),
         updated_at = now()
       WHERE delivery_id = $1`,
      [
        deliveryId,
        result.status,
        JSON.stringify([
          {
            at: new Date().toISOString(),
            status: result.status,
            provider_response_code: result.providerResponseCode ?? null,
            latency_ms: result.latencyMs ?? null,
            error: result.error ?? null,
          },
        ]),
        result.providerResponseCode ?? null,
        result.latencyMs ?? null,
        result.error ?? null,
        result.nextAttemptAt ?? null,
        result.payloadSnapshot ? JSON.stringify(result.payloadSnapshot) : null,
      ],
    );
  }

  async listDeliveries(filter: DeliveryFilter): Promise<Delivery[]> {
    const where: string[] = [];
    const args: unknown[] = [];
    if (filter.orgId) {
      args.push(filter.orgId);
      where.push(`org_id = $${args.length}`);
    }
    if (filter.incidentId) {
      args.push(filter.incidentId);
      where.push(`incident_id = $${args.length}`);
    }
    if (filter.alertId) {
      args.push(JSON.stringify([filter.alertId]));
      where.push(`alert_ids @> $${args.length}::jsonb`);
    }
    if (filter.channel) {
      args.push(filter.channel);
      where.push(`channel = $${args.length}`);
    }
    if (filter.status) {
      args.push(filter.status);
      where.push(`status = $${args.length}`);
    }
    args.push(filter.limit ?? 100);
    const res = await this.pool.query(
      `SELECT * FROM alert.deliveries ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
       ORDER BY created_at DESC, delivery_id DESC LIMIT $${args.length}`,
      args,
    );
    return res.rows.map(mapDeliveryRow);
  }

  async deliveryStatusCounts(orgId?: string): Promise<Record<DeliveryStatus, number>> {
    const res = await this.pool.query(
      `SELECT status, count(*)::int AS n FROM alert.deliveries ${orgId ? "WHERE org_id = $1" : ""} GROUP BY status`,
      orgId ? [orgId] : [],
    );
    const counts: Record<DeliveryStatus, number> = { pending: 0, sent: 0, failed: 0, dlq: 0 };
    for (const r of res.rows) counts[r.status as DeliveryStatus] = r.n as number;
    return counts;
  }

  async appendAudit(record: AuditRecord): Promise<string> {
    const auditId = newAuditId();
    await this.pool.query(
      `INSERT INTO alert.audit_log (audit_id, org_id, actor, action, entity_ids, decision_detail, request_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        auditId,
        record.orgId,
        JSON.stringify(record.actor),
        record.action,
        JSON.stringify(record.entityIds),
        JSON.stringify(record.decisionDetail),
        record.requestHash,
      ],
    );
    return auditId;
  }

  async markAuditForwarded(auditId: string, at: Date): Promise<void> {
    await this.pool.query(`UPDATE alert.audit_log SET forwarded_at = $2 WHERE audit_id = $1`, [auditId, at]);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
