/**
 * Agent-side rate-cap enforcement (doc 01 §10.3, doc 11 §3.2): the token is
 * NOT a capability to bypass rate limits — the PEP enforces the token's
 * embedded `rate_caps` (max_rps / max_concurrent) locally per burst, with no
 * PDP call per request. Exceeding a cap is a hard refusal (fail-closed).
 */

import { PepError } from "./errors.js";
import type { TokenRateCaps } from "./token.js";

/** Doc 01 §10.3 / types.proto: default platform cap is 100 rps for R1. */
export const DEFAULT_MAX_RPS_R1 = 100;

/**
 * Token bucket for the max_rps cap. Tokens refill continuously at maxRps per
 * second; capacity is one second's worth (burst of maxRps).
 */
export class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefillMs: number;

  constructor(
    private readonly maxRps: number,
    private readonly nowMs: () => number = () => Date.now(),
  ) {
    if (maxRps <= 0) {
      throw new PepError("RATE_LIMITED", "max_rps must be positive when set");
    }
    this.tokens = maxRps;
    this.lastRefillMs = nowMs();
  }

  private refill(): void {
    const now = this.nowMs();
    const elapsed = (now - this.lastRefillMs) / 1000;
    if (elapsed > 0) {
      this.tokens = Math.min(this.maxRps, this.tokens + elapsed * this.maxRps);
      this.lastRefillMs = now;
    }
  }

  /** Consume one permit if available; false (deny) when the cap is exceeded. */
  tryAcquire(n = 1): boolean {
    this.refill();
    if (this.tokens >= n) {
      this.tokens -= n;
      return true;
    }
    return false;
  }

  /**
   * Wait for a permit. Rejects immediately with PepError(KILLED) when the
   * abort signal fires (kill-switch handling, doc 01 §10.5: stop target
   * contact within 5 s — workers must not linger in rate-limit sleep).
   */
  async acquire(signal?: AbortSignal): Promise<void> {
    for (;;) {
      if (signal?.aborted) {
        throw new PepError("KILLED", "aborted while waiting on rate limiter");
      }
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const deficitMs = ((1 - this.tokens) / this.maxRps) * 1000;
      await sleep(Math.min(Math.max(deficitMs, 1), 1000), signal);
    }
  }
}

/**
 * Semaphore for the max_concurrent cap. Slots are held for the duration of a
 * network action and MUST be released (use `withSlot`).
 */
export class ConcurrencyLimiter {
  private inFlight = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private readonly maxConcurrent: number) {
    if (maxConcurrent <= 0) {
      throw new PepError("CONCURRENCY_LIMITED", "max_concurrent must be positive when set");
    }
  }

  get current(): number {
    return this.inFlight;
  }

  tryAcquireSlot(): (() => void) | null {
    if (this.inFlight >= this.maxConcurrent) return null;
    this.inFlight += 1;
    return () => this.release();
  }

  async acquireSlot(signal?: AbortSignal): Promise<() => void> {
    const immediate = this.tryAcquireSlot();
    if (immediate !== null) return immediate;
    return new Promise<() => void>((resolve, reject) => {
      const onAbort = () => {
        const i = this.waiters.indexOf(grant);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new PepError("KILLED", "aborted while waiting on concurrency slot"));
      };
      const grant = () => {
        signal?.removeEventListener("abort", onAbort);
        this.inFlight += 1;
        resolve(() => this.release());
      };
      this.waiters.push(grant);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.inFlight = Math.max(0, this.inFlight - 1);
    }
  }

  /** Run `fn` holding a slot; the slot is always released afterwards. */
  async withSlot<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const release = await this.acquireSlot(signal);
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

/**
 * Combined per-token rate caps from the Scope Token claims. A cap that is
 * unset (0/absent) means "no token-embedded cap" — the RoE/Scheduler-level
 * caps still apply upstream; the SDK never invents a looser local cap than
 * the platform default for R1 when nothing is embedded.
 */
export class RateCapsEnforcer {
  readonly rps: TokenBucketRateLimiter | null;
  readonly concurrency: ConcurrencyLimiter | null;

  constructor(caps: TokenRateCaps | undefined, opts: { riskClass?: "R1" | "R2" | "R3"; nowMs?: () => number } = {}) {
    const maxRps = caps?.max_rps && caps.max_rps > 0 ? caps.max_rps : null;
    const maxConcurrent = caps?.max_concurrent && caps.max_concurrent > 0 ? caps.max_concurrent : null;
    const effectiveRps =
      maxRps ?? (opts.riskClass === "R1" ? DEFAULT_MAX_RPS_R1 : null);
    this.rps = effectiveRps !== null ? new TokenBucketRateLimiter(effectiveRps, opts.nowMs) : null;
    this.concurrency = maxConcurrent !== null ? new ConcurrencyLimiter(maxConcurrent) : null;
  }

  /** Fail-closed check used by the PEP guard before every network action. */
  check(): void {
    if (this.rps !== null && !this.rps.tryAcquire()) {
      throw new PepError("RATE_LIMITED", "token max_rps exceeded");
    }
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new PepError("KILLED", "aborted during rate-limit wait"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
