/**
 * Signed ack callback tokens (doc 05 §9/§12): channel messages carry an ack
 * link/button whose token proves the callback is ours. HMAC-SHA256 over
 * `<incident_id>.<expiry_epoch>.<nonce>`, 10-minute expiry, single-use nonce
 * (enforced by the store's ack nonce uniqueness). Replay/forgery → rejected.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { ulid } from "@aegisbastion/agent-sdk";

export const ACK_TOKEN_TTL_SECONDS = 600; // §12: 10-min expiry

function hmac(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload, "utf8").digest("hex");
}

export interface AckToken {
  incidentId: string;
  expiresAt: number; // epoch seconds
  nonce: string;
}

/** Mint a callback token: `<incident_id>.<exp>.<nonce>.<hex>`. */
export function mintAckToken(secret: string, incidentId: string, nowSeconds = Math.floor(Date.now() / 1000)): string {
  const expiresAt = nowSeconds + ACK_TOKEN_TTL_SECONDS;
  const nonce = ulid();
  const payload = `${incidentId}.${expiresAt}.${nonce}`;
  return `${payload}.${hmac(secret, payload)}`;
}

/**
 * Verify a callback token. Returns the decoded token when the signature is
 * valid and unexpired; null otherwise (fail-closed). Nonce single-use is the
 * caller's responsibility (store.ackIncident returns "nonce_used").
 */
export function verifyAckToken(secret: string, token: string, nowSeconds = Math.floor(Date.now() / 1000)): AckToken | null {
  const parts = token.split(".");
  if (parts.length !== 4) return null;
  const [incidentId, expStr, nonce, sig] = parts as [string, string, string, string];
  if (!incidentId || !nonce || !/^\d+$/.test(expStr) || !/^[0-9a-f]{64}$/.test(sig)) return null;
  const expiresAt = Number(expStr);
  if (nowSeconds > expiresAt) return null;
  const expected = Buffer.from(hmac(secret, `${incidentId}.${expStr}.${nonce}`), "hex");
  const given = Buffer.from(sig, "hex");
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  return { incidentId, expiresAt, nonce };
}

/** Absolute ack-callback URL embedded in channel messages. */
export function ackCallbackUrl(publicBaseUrl: string, token: string): string {
  return `${publicBaseUrl.replace(/\/$/, "")}/v1/acks?token=${encodeURIComponent(token)}`;
}
