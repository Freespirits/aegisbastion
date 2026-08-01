/**
 * In-memory Store for unit tests. Mirrors PostgresStore semantics exactly
 * (same dedup verdict math, same incident attach rules, same ack nonce rules)
 * so pipeline tests exercise real behavior. Timers are caller-injected (`now`
 * parameters) — no wall-clock reads inside.
 */
import { severityRank, maxSeverity, } from "../types.js";
import { newAuditId } from "../ids.js";
export function dedupVerdictFor(count, renotifyEvery) {
    if (count <= 1)
        return "new";
    if (renotifyEvery > 0 && count % renotifyEvery === 0)
        return "renotify";
    return "duplicate";
}
export class MemoryStore {
    alerts = new Map();
    incidents = new Map();
    routing = new Map(); // policyId
    escalationPolicies = new Map();
    egress = new Map(); // orgId
    deliveries = new Map();
    dedup = new Map();
    audit = [];
    ackNonces = new Set();
    async insertAlertIfNew(row) {
        if (this.alerts.has(row.eventId))
            return "duplicate";
        this.alerts.set(row.eventId, structuredClone(row));
        return "inserted";
    }
    async getAlert(eventId) {
        const a = this.alerts.get(eventId);
        return a ? structuredClone(a) : null;
    }
    async listAlerts(filter) {
        let rows = [...this.alerts.values()];
        if (filter.orgId)
            rows = rows.filter((r) => r.orgId === filter.orgId);
        if (filter.state)
            rows = rows.filter((r) => r.state === filter.state);
        if (filter.incidentId)
            rows = rows.filter((r) => r.incidentId === filter.incidentId);
        if (filter.severityGte) {
            const min = severityRank(filter.severityGte);
            rows = rows.filter((r) => severityRank(r.effectiveSeverity) >= min);
        }
        rows.sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime() || (a.eventId < b.eventId ? 1 : -1));
        if (filter.cursor) {
            const idx = rows.findIndex((r) => r.eventId === filter.cursor);
            if (idx >= 0)
                rows = rows.slice(idx + 1);
        }
        return rows.slice(0, filter.limit ?? 100).map((r) => structuredClone(r));
    }
    async setAlertState(eventId, state) {
        const a = this.alerts.get(eventId);
        if (a)
            a.state = state;
    }
    async setAlertAuthz(eventId, status, claims, retryAt) {
        const a = this.alerts.get(eventId);
        if (!a)
            return;
        a.authzStatus = status;
        if (claims !== undefined)
            a.authzClaims = structuredClone(claims);
        if (retryAt !== undefined)
            a.authzRetryAt = retryAt;
    }
    async setAlertIncident(eventId, incidentId) {
        const a = this.alerts.get(eventId);
        if (a)
            a.incidentId = incidentId;
    }
    async setAlertDedup(eventId, verdict, degraded) {
        const a = this.alerts.get(eventId);
        if (a) {
            a.dedupVerdict = verdict;
            a.dedupDegraded = degraded;
        }
    }
    async dueAuthzRetries(now) {
        return [...this.alerts.values()]
            .filter((a) => {
            if (a.authzStatus !== "held")
                return false;
            const retryAt = a.authzRetryAt;
            return retryAt != null && retryAt.getTime() <= now.getTime();
        })
            .map((a) => structuredClone(a));
    }
    async dedupTouch(fingerprint, orgId, alertId, windowSeconds, renotifyEvery, now) {
        const hardCapMs = 7 * 24 * 3600 * 1000;
        const existing = this.dedup.get(fingerprint);
        if (!existing || existing.expiresAt <= now.getTime()) {
            this.dedup.set(fingerprint, {
                orgId,
                alertId,
                count: 1,
                firstSeen: now.getTime(),
                expiresAt: now.getTime() + Math.min(windowSeconds * 1000, hardCapMs),
            });
            return { verdict: "new", count: 1, firstAlertId: alertId, degraded: false };
        }
        existing.count += 1;
        existing.expiresAt = Math.min(now.getTime() + windowSeconds * 1000, existing.firstSeen + hardCapMs);
        return {
            verdict: dedupVerdictFor(existing.count, renotifyEvery),
            count: existing.count,
            firstAlertId: existing.alertId,
            degraded: false,
        };
    }
    async findOpenIncident(orgId, correlationKey) {
        for (const inc of this.incidents.values()) {
            if (inc.orgId === orgId &&
                inc.correlationKey === correlationKey &&
                (inc.state === "open" || inc.state === "acknowledged" || inc.state === "escalated")) {
                return structuredClone(inc);
            }
        }
        return null;
    }
    async insertIncident(incident) {
        this.incidents.set(incident.incidentId, { ...structuredClone(incident), alertIds: [] });
    }
    async getIncident(incidentId) {
        const inc = this.incidents.get(incidentId);
        return inc ? structuredClone(inc) : null;
    }
    async listIncidents(filter) {
        let rows = [...this.incidents.values()];
        if (filter.orgId)
            rows = rows.filter((r) => r.orgId === filter.orgId);
        if (filter.state)
            rows = rows.filter((r) => r.state === filter.state);
        if (filter.severityGte) {
            const min = severityRank(filter.severityGte);
            rows = rows.filter((r) => severityRank(r.severity) >= min);
        }
        rows.sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime() || (a.incidentId < b.incidentId ? 1 : -1));
        return rows.slice(0, filter.limit ?? 100).map((r) => structuredClone(r));
    }
    async attachAlertToIncident(incidentId, event, now) {
        const inc = this.incidents.get(incidentId);
        if (!inc)
            throw new Error(`incident not found: ${incidentId}`);
        if (!inc.alertIds.includes(event.event_id)) {
            inc.alertIds.push(event.event_id);
            inc.alertCount = inc.alertIds.length;
        }
        inc.lastSeenAt = now;
        inc.severity = maxSeverity(inc.severity, event.severity);
        if (event.requires_ack)
            inc.requiresAck = true;
        if (severityRank(event.severity) > severityRank(inc.severity))
            inc.severity = event.severity;
    }
    async incidentAlerts(incidentId) {
        return [...(this.incidents.get(incidentId)?.alertIds ?? [])];
    }
    async ackIncident(incidentId, by, note, nonce, now) {
        if (this.ackNonces.has(nonce))
            return "nonce_used";
        const inc = this.incidents.get(incidentId);
        if (!inc)
            return "notfound";
        if (inc.state === "acknowledged" || inc.state === "resolved")
            return "already";
        this.ackNonces.add(nonce);
        inc.state = "acknowledged";
        inc.ack = { by, at: now.toISOString(), note };
        return "acked";
    }
    async resolveIncident(incidentId, _now) {
        const inc = this.incidents.get(incidentId);
        if (inc)
            inc.state = "resolved";
    }
    async setIncidentEscalation(incidentId, escalation, state, exhausted) {
        const inc = this.incidents.get(incidentId);
        if (!inc)
            return;
        inc.escalation = structuredClone(escalation);
        if (state)
            inc.state = state;
        if (exhausted !== undefined)
            inc.escalationExhausted = exhausted;
    }
    async dueEscalations(now) {
        return [...this.incidents.values()]
            .filter((inc) => {
            if (!inc.requiresAck)
                return false;
            if (inc.state !== "open" && inc.state !== "escalated")
                return false;
            const next = inc.escalation.next_fire_at;
            return next != null && Date.parse(next) <= now.getTime();
        })
            .map((i) => structuredClone(i));
    }
    async routingPolicies(orgId) {
        // Empty orgId = control-plane list across orgs (see pgstore).
        return [...this.routing.values()]
            .filter((p) => (orgId === "" || p.orgId === orgId) && p.enabled)
            .sort((a, b) => a.priority - b.priority || a.createdAt.getTime() - b.createdAt.getTime())
            .map((p) => structuredClone(p));
    }
    async getRoutingPolicy(policyId) {
        const p = this.routing.get(policyId);
        return p ? structuredClone(p) : null;
    }
    async putRoutingPolicy(policy) {
        this.routing.set(policy.policyId, structuredClone(policy));
    }
    async escalationPolicy(orgId, policyId) {
        const p = this.escalationPolicies.get(policyId);
        return p && p.orgId === orgId ? structuredClone(p) : null;
    }
    async putEscalationPolicy(policy) {
        this.escalationPolicies.set(policy.policyId, structuredClone(policy));
    }
    async egressPolicy(orgId) {
        const e = this.egress.get(orgId);
        return e ? structuredClone(e) : null;
    }
    async putEgressPolicy(orgId, entries, _updatedBy) {
        this.egress.set(orgId, structuredClone(entries));
    }
    async insertDelivery(delivery, payloadSnapshot) {
        this.deliveries.set(delivery.deliveryId, { ...structuredClone(delivery), payload: payloadSnapshot, attempts: [] });
    }
    async dueDeliveries(now, limit) {
        return [...this.deliveries.values()]
            .filter((d) => (d.status === "pending" || d.status === "failed") && d.nextAttemptAt.getTime() <= now.getTime())
            .sort((a, b) => a.nextAttemptAt.getTime() - b.nextAttemptAt.getTime())
            .slice(0, limit)
            .map((d) => structuredClone(d));
    }
    async recordDeliveryAttempt(deliveryId, result) {
        const d = this.deliveries.get(deliveryId);
        if (!d)
            return;
        d.attemptCount += 1;
        d.attempts.push({
            at: new Date().toISOString(),
            status: result.status,
            provider_response_code: result.providerResponseCode,
            latency_ms: result.latencyMs,
            error: result.error,
        });
        d.status = result.status;
        if (result.nextAttemptAt)
            d.nextAttemptAt = result.nextAttemptAt;
        if (result.status === "sent")
            d.sentAt = new Date();
        if (result.error !== undefined)
            d.error = result.error;
        if (result.payloadSnapshot !== undefined)
            d.payload = result.payloadSnapshot;
    }
    async listDeliveries(filter) {
        let rows = [...this.deliveries.values()];
        if (filter.orgId)
            rows = rows.filter((r) => r.orgId === filter.orgId);
        if (filter.incidentId)
            rows = rows.filter((r) => r.incidentId === filter.incidentId);
        if (filter.alertId)
            rows = rows.filter((r) => r.alertIds.includes(filter.alertId));
        if (filter.channel)
            rows = rows.filter((r) => r.channel === filter.channel);
        if (filter.status)
            rows = rows.filter((r) => r.status === filter.status);
        rows.sort((a, b) => (a.deliveryId < b.deliveryId ? 1 : -1));
        return rows.slice(0, filter.limit ?? 100).map((d) => structuredClone(d));
    }
    async deliveryStatusCounts(orgId) {
        const counts = { pending: 0, sent: 0, failed: 0, dlq: 0 };
        for (const d of this.deliveries.values()) {
            if (orgId && d.orgId !== orgId)
                continue;
            counts[d.status] += 1;
        }
        return counts;
    }
    async appendAudit(record) {
        const auditId = newAuditId();
        this.audit.push({ auditId, ts: new Date(), ...structuredClone(record) });
        return auditId;
    }
    async markAuditForwarded(auditId, at) {
        const row = this.audit.find((a) => a.auditId === auditId);
        if (row)
            row.forwardedAt = at;
    }
    async close() { }
}
