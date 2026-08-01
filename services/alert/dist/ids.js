/** Prefixed ULID ids (doc 05 §16: evt_/inc_/rp_/esc_/dlv_ + ULID). */
import { ulid } from "@aegisbastion/agent-sdk";
export const newAlertId = () => `evt_${ulid()}`;
export const newIncidentId = () => `inc_${ulid()}`;
export const newRoutingPolicyId = () => `rp_${ulid()}`;
export const newEscalationPolicyId = () => `esc_${ulid()}`;
export const newDeliveryId = () => `dlv_${ulid()}`;
export const newAuditId = () => `aud_${ulid()}`;
export const newAckId = () => `ack_${ulid()}`;
export const newDlqId = () => `dlq_${ulid()}`;
