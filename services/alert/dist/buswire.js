/**
 * Bus wiring (doc 05 §5.9, Ruling C3): herald consumes the ALERT_INGRESS
 * work-queue stream (detect.alert / monitor.alert / discover.alert /
 * ddos.alert / redteam.alert / phish.alert / alert.outbound) where every
 * message is a CloudEvents 1.0 JSON envelope carrying AlertEvent v1
 * (schemas/alert/v1 — validated at ingress, poison messages are terminated,
 * never redelivered). Lifecycle transitions publish CloudEvents JSON to
 * alerts.lifecycle (§4.3); quarantines and dead letters to alerts.dlq; local
 * audit records forward to gatekeeper's audit of record on audit.events
 * (§5.8, doc 11 §3.4) as hash-chained platform AuditEvents.
 *
 * The compact gatekeeper Scope Token rides the `Authorization-Token` NATS
 * header — see README deviation 3 (doc 05 §5.7's in-event field vs the
 * ratified Phase-0 schema's additionalProperties:false).
 */
import { AckPolicy, DeliverPolicy, jetstreamManager } from "@nats-io/jetstream";
import { ulid, AuditEmitter, AuditEventSchema, AuditEventType } from "@aegisbastion/agent-sdk";
import { validationErrors } from "./schemas.js";
export const INGRESS_STREAM = "ALERT_INGRESS";
export const INGRESS_DURABLE = "herald-ingest";
export const INGRESS_SUBJECTS = [
    "detect.alert",
    "monitor.alert",
    "discover.alert",
    "ddos.alert",
    "redteam.alert",
    "phish.alert",
    "alert.outbound",
];
export const SUBJECT_LIFECYCLE = "alerts.lifecycle";
export const SUBJECT_DLQ = "alerts.dlq";
export const SUBJECT_AUDIT = "audit.events";
export const AUTHZ_TOKEN_HEADER = "Authorization-Token";
/** CloudEvents JSON wrapper for herald-produced bus messages (§5.1). */
function cloudEvent(type, subject, data) {
    return new TextEncoder().encode(JSON.stringify({
        specversion: "1.0",
        id: `evt_${ulid()}`,
        source: "//aegisbastion/alert",
        type,
        subject,
        time: new Date().toISOString(),
        datacontenttype: "application/json",
        data,
    }));
}
/**
 * PipelineSinks backed by the bus. Audit forwarding keeps ONE hash chain per
 * herald process (AuditEmitter) serialized through a promise queue; failure
 * leaves the local spool row unforwarded (forwarded_at NULL) for later
 * reconciliation — the local append-only log is never lost (§5.8).
 */
export function busSinks(bus, opts = {}) {
    const emitter = new AuditEmitter(async (event) => {
        await bus.publish(SUBJECT_AUDIT, AuditEventSchema, event);
    });
    let chain = Promise.resolve();
    return {
        async publishLifecycle(transition, subject, data) {
            await bus.js.publish(SUBJECT_LIFECYCLE, cloudEvent("com.aegisbastion.alert.lifecycle.v1", subject, { transition, ...data }));
        },
        async publishDlq(reason, data) {
            await bus.js.publish(SUBJECT_DLQ, cloudEvent("com.aegisbastion.alert.dlq.v1", `dlq/${reason}`, { reason, ...data }));
        },
        async forwardAudit(record, auditId) {
            // Serialize so the hash chain's seq/prev_hash stay consistent.
            const run = chain.then(async () => {
                const isViolation = record.action === "authz_reject" || record.action === "authz_hold";
                await emitter.emit({
                    type: isViolation ? AuditEventType.SCOPE_VIOLATION : AuditEventType.UNSPECIFIED,
                    actor: { kind: record.actor.kind, id: record.actor.id },
                    subject: {},
                    payload: {
                        herald_action: record.action,
                        herald_audit_id: auditId,
                        org_id: record.orgId,
                        entity_ids: record.entityIds,
                        decision_detail: record.decisionDetail,
                        request_hash: record.requestHash,
                    },
                });
                await opts.onForwarded?.(auditId);
            });
            chain = run.catch(() => { });
            return run;
        },
    };
}
/**
 * Durable work-queue consumer on ALERT_INGRESS. Ack semantics:
 *  - schema-invalid → term() (poison; audited ingest_reject, never processable)
 *  - pipeline outcome (processed/suppressed/held/rejected/duplicate) → ack()
 *    (held alerts are persisted with a retry schedule — §12)
 *  - transient pipeline throw (store down…) → nak(5s) for redelivery
 */
export async function startIngestConsumer(bus, pipeline, validators, opts = {}) {
    const jsm = await jetstreamManager(bus.nc);
    await jsm.consumers.add(INGRESS_STREAM, {
        durable_name: INGRESS_DURABLE,
        filter_subjects: [...INGRESS_SUBJECTS],
        ack_policy: AckPolicy.Explicit,
        deliver_policy: DeliverPolicy.All,
        ack_wait: 30_000_000_000, // ns
        max_deliver: 5,
    });
    const consumer = await bus.js.consumers.get(INGRESS_STREAM, INGRESS_DURABLE);
    const messages = await consumer.consume();
    const loop = (async () => {
        for await (const msg of messages) {
            try {
                let parsed;
                try {
                    parsed = JSON.parse(new TextDecoder().decode(msg.data));
                }
                catch {
                    await opts.onPoison?.(msg.subject, ["body is not valid JSON"]);
                    msg.term("not JSON");
                    continue;
                }
                if (!validators.envelope(parsed)) {
                    await opts.onPoison?.(msg.subject, validationErrors(validators.envelope));
                    msg.term("schema-invalid CloudEvents envelope");
                    continue;
                }
                const envelope = parsed;
                if (!validators.alertEvent(envelope.data)) {
                    await opts.onPoison?.(msg.subject, validationErrors(validators.alertEvent));
                    msg.term("schema-invalid AlertEvent");
                    continue;
                }
                await pipeline.ingest(envelope.data, {
                    receivedAt: new Date(),
                    envelopeSource: envelope.source,
                    ...(msg.headers?.get(AUTHZ_TOKEN_HEADER) ? { authorizationToken: msg.headers.get(AUTHZ_TOKEN_HEADER) } : {}),
                });
                msg.ack();
            }
            catch (err) {
                console.error(`herald: ingest consumer error on ${msg.subject}: ${err.message}`);
                msg.nak(5_000);
            }
        }
    })();
    return {
        stop: async () => {
            messages.stop();
            await loop.catch(() => { });
        },
    };
}
