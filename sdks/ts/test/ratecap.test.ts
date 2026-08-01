/**
 * Rate-cap enforcement (doc 01 §10.3, doc 11 §3.2): token buckets and
 * concurrency slots from the token's embedded caps; exceeding = hard denial.
 */

import { describe, expect, it } from "vitest";
import {
  ConcurrencyLimiter,
  RateCapsEnforcer,
  TokenBucketRateLimiter,
  DEFAULT_MAX_RPS_R1,
} from "../src/ratecap.js";

describe("TokenBucketRateLimiter", () => {
  it("allows up to max_rps then denies", () => {
    let now = 1_000_000;
    const b = new TokenBucketRateLimiter(3, () => now);
    expect(b.tryAcquire()).toBe(true);
    expect(b.tryAcquire()).toBe(true);
    expect(b.tryAcquire()).toBe(true);
    expect(b.tryAcquire()).toBe(false);
  });

  it("refills over time", () => {
    let now = 1_000_000;
    const b = new TokenBucketRateLimiter(10, () => now);
    for (let i = 0; i < 10; i++) expect(b.tryAcquire()).toBe(true);
    expect(b.tryAcquire()).toBe(false);
    now += 500; // 5 tokens back
    for (let i = 0; i < 5; i++) expect(b.tryAcquire()).toBe(true);
    expect(b.tryAcquire()).toBe(false);
  });

  it("async acquire waits for a permit and aborts on kill", async () => {
    let now = 1_000_000;
    const b = new TokenBucketRateLimiter(1, () => now);
    await b.acquire();
    const ac = new AbortController();
    const pending = b.acquire(ac.signal);
    ac.abort();
    await expect(pending).rejects.toMatchObject({ code: "KILLED" });
  });
});

describe("ConcurrencyLimiter", () => {
  it("caps in-flight slots and grants waiters on release", async () => {
    const c = new ConcurrencyLimiter(2);
    const r1 = await c.acquireSlot();
    const r2 = await c.acquireSlot();
    expect(c.current).toBe(2);
    expect(c.tryAcquireSlot()).toBeNull();

    let granted = false;
    const waiter = c.acquireSlot().then((release) => {
      granted = true;
      return release;
    });
    await Promise.resolve();
    expect(granted).toBe(false);
    r1();
    const r3 = await waiter;
    expect(granted).toBe(true);
    r2();
    r3();
  });

  it("withSlot always releases, even on error", async () => {
    const c = new ConcurrencyLimiter(1);
    await expect(
      c.withSlot(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(c.current).toBe(0);
  });
});

describe("RateCapsEnforcer", () => {
  it("throws RATE_LIMITED past the embedded max_rps", () => {
    const e = new RateCapsEnforcer({ max_rps: 2 });
    e.check();
    e.check();
    expect(() => e.check()).toThrowError(
      expect.objectContaining({ code: "RATE_LIMITED" }),
    );
  });

  it("applies the platform default (100 rps) for R1 when the token embeds no cap", () => {
    const e = new RateCapsEnforcer(undefined, { riskClass: "R1" });
    expect(e.rps).not.toBeNull();
    expect(DEFAULT_MAX_RPS_R1).toBe(100);
  });

  it("has no invented cap for R2/R3 when the token embeds none", () => {
    const e = new RateCapsEnforcer(undefined, { riskClass: "R2" });
    expect(e.rps).toBeNull();
    e.check(); // must not throw
  });
});
