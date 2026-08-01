/** Prefixed ULID ids (doc 05 §16: evt_/inc_/rp_/esc_/dlv_ + ULID). */

import { ulid } from "@aegisbastion/agent-sdk";

export const newAlertId = (): string => `evt_${ulid()}`;
export const newIncidentId = (): string => `inc_${ulid()}`;
export const newRoutingPolicyId = (): string => `rp_${ulid()}`;
export const newEscalationPolicyId = (): string => `esc_${ulid()}`;
export const newDeliveryId = (): string => `dlv_${ulid()}`;
export const newAuditId = (): string => `aud_${ulid()}`;
export const newAckId = (): string => `ack_${ulid()}`;
export const newDlqId = (): string => `dlq_${ulid()}`;
