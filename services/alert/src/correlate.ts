/**
 * Correlation (doc 05 §7.2 — MVP: deterministic key #1 only, §15).
 * correlation_key = asset:<asset_id>|<finding-identity>, where
 * finding-identity is the producer's fingerprint_hint (producers own identity
 * semantics, §7.1). Alerts sharing the key within an open incident join it;
 * otherwise a new incident is created. Routing then happens per incident
 * (§3.2 step 5) to avoid notification storms.
 */

import { newIncidentId } from "./ids.js";
import type { Store } from "./store.js";
import type { AlertEvent, Incident, Severity } from "./types.js";

export function correlationKeyFor(event: AlertEvent): string {
  const identity = event.fingerprint_hint ?? event.source_event_id;
  return `asset:${event.asset.asset_id}|${identity}`;
}

export interface CorrelationResult {
  incident: Incident;
  created: boolean;
}

export async function correlate(
  store: Store,
  event: AlertEvent,
  effectiveSeverity: Severity,
  now: Date,
): Promise<CorrelationResult> {
  const key = correlationKeyFor(event);
  const existing = await store.findOpenIncident(event.org_id, key);
  if (existing) {
    await store.attachAlertToIncident(existing.incidentId, event, now);
    await store.setAlertIncident(event.event_id, existing.incidentId);
    const updated = (await store.getIncident(existing.incidentId)) ?? existing;
    return { incident: updated, created: false };
  }

  const incident: Incident = {
    incidentId: newIncidentId(),
    orgId: event.org_id,
    state: "open",
    title: event.title,
    severity: effectiveSeverity,
    category: event.category,
    sourceModule: event.source_module,
    asset: event.asset,
    labels: event.labels ?? {},
    correlationKey: key,
    alertCount: 0,
    requiresAck: event.requires_ack ?? false,
    firstSeenAt: now,
    lastSeenAt: now,
    escalation: {},
    escalationExhausted: false,
  };
  await store.insertIncident(incident);
  await store.attachAlertToIncident(incident.incidentId, event, now);
  await store.setAlertIncident(event.event_id, incident.incidentId);
  const stored = (await store.getIncident(incident.incidentId)) ?? { ...incident, alertCount: 1 };
  return { incident: stored, created: true };
}
