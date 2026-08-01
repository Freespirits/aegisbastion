/**
 * In-process per-destination token buckets (doc 05 §11: per-channel rate
 * caps are the bottleneck BY DESIGN — e.g. Slack 1 msg/s + burst 20; webhook
 * 10 req/s/endpoint). MVP-A is single-process, so the buckets live here; the
 * §12 Redis fallback story ("in-process conservative limits") is exactly
 * this. 429 responses pause the destination bucket for Retry-After.
 */
export class TokenBucket {
    capacity;
    refillPerSecond;
    tokens;
    lastRefill;
    pausedUntil = 0;
    constructor(capacity, refillPerSecond, nowMs = Date.now) {
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.tokens = capacity;
        this.lastRefill = nowMs();
        this.now = nowMs;
    }
    now;
    refill() {
        const t = this.now();
        const elapsed = (t - this.lastRefill) / 1000;
        if (elapsed > 0) {
            this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSecond);
            this.lastRefill = t;
        }
    }
    /** Take one token if available and not paused. */
    tryTake() {
        this.refill();
        if (this.now() < this.pausedUntil)
            return false;
        if (this.tokens >= 1) {
            this.tokens -= 1;
            return true;
        }
        return false;
    }
    /** 429 handling (§12): pause this destination's bucket, keep others flowing. */
    pauseFor(ms) {
        this.pausedUntil = Math.max(this.pausedUntil, this.now() + ms);
    }
    pausedRemainingMs() {
        return Math.max(0, this.pausedUntil - this.now());
    }
}
export class BucketRegistry {
    perSecond;
    burst;
    nowMs;
    buckets = new Map();
    constructor(perSecond, burst, nowMs = Date.now) {
        this.perSecond = perSecond;
        this.burst = burst;
        this.nowMs = nowMs;
    }
    forKey(key) {
        let b = this.buckets.get(key);
        if (!b) {
            b = new TokenBucket(this.burst, this.perSecond, this.nowMs);
            this.buckets.set(key, b);
        }
        return b;
    }
}
/** Bucket key: per-channel per-destination (doc 05 §11). */
export function bucketKey(channel, destination) {
    return `${channel}:${destination}`;
}
