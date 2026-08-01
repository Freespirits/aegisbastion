/**
 * Deduplication (doc 05 §7.1). fingerprint = SHA-256(org_id | source_module |
 * fingerprint_hint | asset.asset_id) — the producer owns identity semantics
 * via fingerprint_hint; herald never guesses.
 *
 * Store-backed sliding window (Postgres on MVP-A, no Redis on the compose
 * host — same simplification as gatekeeper deviation 1). FAIL-OPEN on store
 * outage: the event is treated as `new` and stamped dedup_degraded=true, so a
 * dedup outage causes duplicate notifications, never silent dropping.
 */
import { createHash } from "node:crypto";
export const DEDUP_DEFAULT_WINDOW_SECONDS = 86_400; // 24 h
export const DEDUP_HARD_MAX_SECONDS = 7 * 86_400; // 7 d
export function fingerprintFor(event) {
    const hint = event.fingerprint_hint ?? "";
    return createHash("sha256")
        .update(`${event.org_id}|${event.source_module}|${hint}|${event.asset.asset_id}`)
        .digest("hex");
}
export async function dedupCheck(store, event, now) {
    const fp = fingerprintFor(event);
    const windowSeconds = Math.min(Math.max(event.dedup_window_seconds ?? DEDUP_DEFAULT_WINDOW_SECONDS, 0) || DEDUP_DEFAULT_WINDOW_SECONDS, DEDUP_HARD_MAX_SECONDS);
    const renotifyEvery = event.renotify_every ?? 0;
    try {
        const outcome = await store.dedupTouch(fp, event.org_id, event.event_id, windowSeconds, renotifyEvery, now);
        return { ...outcome, windowSeconds };
    }
    catch {
        // §7.1 fail-open: never silently drop on a dedup-store outage.
        return { verdict: "new", count: 1, firstAlertId: event.event_id, degraded: true, windowSeconds };
    }
}
