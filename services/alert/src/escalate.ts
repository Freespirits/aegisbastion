/**
 * Escalation manager (doc 05 §9). Scans incidents with requires_ack whose
 * escalation.next_fire_at has passed (§9: every 5 s, leader only — single
 * compose replica at MVP-A, so the loop is unopposed). Firing a step creates
 * DeliveryTasks at the step's targets with urgency bumped one notch. Acks and
 * resolution stop the chain (stop_on). Chains repeat the last step up to
 * max_repeats; exhausted chains emit a final operational/critical alert to
 * the org fail-safe channel and mark escalation_exhausted=true.
 *
 * The driver callbacks are supplied by the pipeline so this module is
 * transport-free and unit-testable with injected clocks.
 */

import type { Store } from "./store.js";
import type { EscalationPolicy, EscalationStep, Incident } from "./types.js";

export interface EscalationDriver {
  /** Create deliveries for one escalation step (urgency bumped by the caller). */
  fireStep(incident: Incident, step: EscalationStep, policy: EscalationPolicy): Promise<void>;
  /** Final operational/critical alert to the org fail-safe channel (§9). */
  fireExhausted(incident: Incident): Promise<void>;
}

export function nextEscalationState(
  incident: Incident,
  policy: EscalationPolicy,
  now: Date,
): { action: "step"; step: EscalationStep; next: Incident["escalation"] } | { action: "exhausted"; next: Incident["escalation"] } | { action: "none" } {
  const esc = incident.escalation;
  const current = esc.current_step ?? 0;
  const attachedAt = Date.parse(esc.attached_at ?? incident.firstSeenAt.toISOString());
  const repeatCount = esc.repeat_count ?? 0;

  const nextStep = policy.steps.find((s) => s.step === current + 1);
  if (nextStep) {
    const fireAt = attachedAt + nextStep.wait_seconds * 1000;
    if (now.getTime() < fireAt) {
      return { action: "none" };
    }
    return {
      action: "step",
      step: nextStep,
      next: {
        ...esc,
        current_step: nextStep.step,
        next_fire_at: undefined,
        attached_at: new Date(attachedAt).toISOString(),
      },
    };
  }

  // Chain finished its steps: repeat the last step while repeats remain.
  const lastStep = policy.steps[policy.steps.length - 1];
  if (lastStep && policy.repeatLastStepEverySeconds > 0 && repeatCount < policy.maxRepeats) {
    const base = Date.parse(esc.last_fired_at ?? new Date(attachedAt).toISOString());
    const fireAt = base + policy.repeatLastStepEverySeconds * 1000;
    if (now.getTime() < fireAt) return { action: "none" };
    return {
      action: "step",
      step: lastStep,
      next: {
        ...esc,
        repeat_count: repeatCount + 1,
        next_fire_at: undefined,
        last_fired_at: now.toISOString(),
      },
    };
  }
  return { action: "exhausted", next: { ...esc, next_fire_at: undefined } };
}

/** Schedule the FIRST escalation fire time when a policy attaches at route time. */
export function initialEscalationState(policy: EscalationPolicy, now: Date): Incident["escalation"] {
  const first = policy.steps.find((s) => s.step === 1);
  return {
    policy_id: policy.policyId,
    current_step: 0,
    attached_at: now.toISOString(),
    ...(first ? { next_fire_at: new Date(now.getTime() + first.wait_seconds * 1000).toISOString() } : {}),
  };
}

/**
 * Process all due escalations once. Returns the number of incidents stepped.
 */
export async function runDueEscalations(store: Store, driver: EscalationDriver, now: Date): Promise<number> {
  const due = await store.dueEscalations(now);
  let fired = 0;
  for (const incident of due) {
    const policyId = incident.escalation.policy_id;
    if (!policyId) {
      await store.setIncidentEscalation(incident.incidentId, { ...incident.escalation, next_fire_at: undefined });
      continue;
    }
    const policy = await store.escalationPolicy(incident.orgId, policyId);
    if (!policy) {
      await store.setIncidentEscalation(incident.incidentId, { ...incident.escalation, next_fire_at: undefined });
      continue;
    }
    const outcome = nextEscalationState(incident, policy, now);
    if (outcome.action === "none") {
      // Not actually due under this policy's math — park until the computed time.
      continue;
    }
    if (outcome.action === "step") {
      await driver.fireStep(incident, outcome.step, policy);
      // Schedule the following step (or repeat cadence) now.
      const following = policy.steps.find((s) => s.step === outcome.step.step + 1);
      const esc = { ...outcome.next, last_fired_at: now.toISOString() };
      if (following) {
        const attachedAt = Date.parse(esc.attached_at ?? now.toISOString());
        esc.next_fire_at = new Date(attachedAt + following.wait_seconds * 1000).toISOString();
      } else if (policy.repeatLastStepEverySeconds > 0) {
        esc.next_fire_at = new Date(now.getTime() + policy.repeatLastStepEverySeconds * 1000).toISOString();
      }
      await store.setIncidentEscalation(incident.incidentId, esc, "escalated");
      fired++;
    } else {
      await driver.fireExhausted(incident);
      await store.setIncidentEscalation(incident.incidentId, outcome.next, "escalated", true);
      fired++;
    }
  }
  return fired;
}

/** Interval loop wrapper (5 s cadence per §9). */
export class EscalationLoop {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly store: Store,
    private readonly driver: EscalationDriver,
    private readonly intervalMs: number,
    private readonly onError: (err: unknown) => void = () => {},
  ) {}

  start(): void {
    this.timer = setInterval(() => {
      runDueEscalations(this.store, this.driver, new Date()).catch(this.onError);
    }, this.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
