/**
 * Signed outbound webhooks (doc 05 §6/§13.5): HMAC-SHA256 in
 * `X-AegisBastion-Signature: t=<ts>,v1=<hex>` over `<ts>.<body>` with
 * per-endpoint secrets. Receivers verify authenticity + freshness (ts).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
export function signWebhookBody(secret, body, timestampSeconds) {
    const payload = `${timestampSeconds}.${body}`;
    const hex = createHmac("sha256", secret).update(payload, "utf8").digest("hex");
    return `t=${timestampSeconds},v1=${hex}`;
}
/** Constant-time verification helper for tests and for receiver-side docs. */
export function verifyWebhookSignature(secret, body, header, toleranceSeconds = 300) {
    const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header);
    if (!match)
        return false;
    const ts = Number(match[1]);
    if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSeconds)
        return false;
    const expected = createHmac("sha256", secret).update(`${ts}.${body}`, "utf8").digest();
    const given = Buffer.from(match[2], "hex");
    return expected.length === given.length && timingSafeEqual(expected, given);
}
