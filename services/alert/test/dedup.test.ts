/**
 * Dedup (doc 05 §7.1): fingerprint = SHA-256(org|module|hint|asset_id);
 * sliding-window suppression with occurrence counters; renotify verdicts;
 * hard max 7 d; FAIL-OPEN on store outage (dedup_degraded=true, treated as
 * new — never silent dropping).
 */

import { describe, expect, it } from "vitest";
import { dedupCheck, fingerprintFor, DEDUP_HARD_MAX_SECONDS } from "../src/dedup.js";
import { MemoryStore } from "../src/db/memory.js";
import type { Store } from "../src/store.js";
import { sampleEvent } from "./helpers.js";

describe("fingerprintFor", () => {
  it("is stable and sensitive to org/module/hint/asset", () => {
    const a = fingerprintFor(sampleEvent({ fingerprint_hint: "cve-1|443" }));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(fingerprintFor(sampleEvent({ fingerprint_hint: "cve-1|443" }))).toBe(a);
    expect(fingerprintFor(sampleEvent({ fingerprint_hint: "cve-2|443" }))).not.toBe(a);
    expect(fingerprintFor(sampleEvent({ fingerprint_hint: "cve-1|443", org_id: "org_other" }))).not.toBe(a);
    expect(fingerprintFor(sampleEvent({ fingerprint_hint: "cve-1|443", source_module: "detect" }))).not.toBe(a);
    expect(
      fingerprintFor(sampleEvent({ fingerprint_hint: "cve-1|443", asset: { asset_id: "asset_2", kind: "ip", identifier: "1.2.3.4" } })),
    ).not.toBe(a);
  });
});

describe("dedupCheck window semantics (§7.1)", () => {
  it("new → duplicate within the (sliding) window → new after expiry", async () => {
    const store = new MemoryStore();
    const t0 = new Date("2026-07-30T00:00:00Z");
    const event = sampleEvent({ dedup_window_seconds: 3600 });

    const first = await dedupCheck(store, event, t0);
    expect(first).toMatchObject({ verdict: "new", count: 1, degraded: false });

    const second = await dedupCheck(store, sampleEvent({ ...event, event_id: "evt_2" }), new Date(t0.getTime() + 600_000));
    expect(second).toMatchObject({ verdict: "duplicate", count: 2, firstAlertId: event.event_id });

    // Sliding window (§7.1): each touch extends the expiry.
    const stillInWindow = await dedupCheck(store, sampleEvent({ ...event, event_id: "evt_3" }), new Date(t0.getTime() + 4_000_000));
    expect(stillInWindow.verdict).toBe("duplicate"); // extends expiry to t0+4000s+3600s
    const afterWindow = await dedupCheck(store, sampleEvent({ ...event, event_id: "evt_4" }), new Date(t0.getTime() + 7_800_000));
    expect(afterWindow).toMatchObject({ verdict: "new", count: 1 });
  });

  it("renotify_every emits 'renotify' on multiples of the threshold", async () => {
    const store = new MemoryStore();
    const t0 = new Date("2026-07-30T00:00:00Z");
    const base = sampleEvent({ dedup_window_seconds: 86_400, renotify_every: 3 });
    const verdicts = [];
    for (let i = 0; i < 7; i++) {
      verdicts.push(
        (await dedupCheck(store, sampleEvent({ ...base, event_id: `evt_${i}` }), new Date(t0.getTime() + i * 60_000))).verdict,
      );
    }
    expect(verdicts).toEqual(["new", "duplicate", "renotify", "duplicate", "duplicate", "renotify", "duplicate"]);
  });

  it("caps the window at the 7-day hard max", async () => {
    const store = new MemoryStore();
    const t0 = new Date("2026-07-30T00:00:00Z");
    const event = sampleEvent({ dedup_window_seconds: 30 * 86_400 });
    const first = await dedupCheck(store, event, t0);
    expect(first.windowSeconds).toBe(DEDUP_HARD_MAX_SECONDS);
    // Still suppressed at +6 days, new again after the hard cap.
    const dup = await dedupCheck(store, sampleEvent({ ...event, event_id: "evt_late" }), new Date(t0.getTime() + 6 * 86_400_000));
    expect(dup.verdict).toBe("duplicate");
    const fresh = await dedupCheck(store, sampleEvent({ ...event, event_id: "evt_later" }), new Date(t0.getTime() + 8 * 86_400_000));
    expect(fresh.verdict).toBe("new");
  });

  it("defaults to 24 h when the event sets no window", async () => {
    const store = new MemoryStore();
    const result = await dedupCheck(store, sampleEvent(), new Date());
    expect(result.windowSeconds).toBe(86_400);
  });

  it("FAILS OPEN on store outage: verdict new + degraded, never suppressed", async () => {
    const broken = new MemoryStore();
    broken.dedupTouch = async () => {
      throw new Error("postgres connection refused");
    };
    const result = await dedupCheck(broken as Store, sampleEvent(), new Date());
    expect(result).toMatchObject({ verdict: "new", degraded: true });
  });
});
