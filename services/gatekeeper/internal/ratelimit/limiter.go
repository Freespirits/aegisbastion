// Package ratelimit implements the decision-time rate-cap check (pipeline
// step 10 RATE, doc 11 §3.3). MVP-A runs as a single gatekeeper binary with
// no Redis in the Compose host (doc 00 §4 MVP-A infra), so counters are
// in-process token buckets keyed (roe_id, capability-pattern); the doc 11 §6
// Redis design lands with horizontal scaling in MVP-B. Fail-closed: unknown
// counter state for R2/R3 denies (here counters are always known in-process).
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a per-key token bucket. Capacity = rps (1 s burst), refill = rps/s.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns an empty Limiter.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: time.Now}
}

// Allow reports whether one unit of work under key at rate rps may proceed
// right now. rps <= 0 means "no cap" and always allows. The returned
// retryAfter is the earliest time a token will be available when denied.
func (l *Limiter) Allow(key string, rps uint32) (allowed bool, retryAfter time.Duration) {
	if rps == 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rps), last: now}
		l.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(rps)
	if b.tokens > float64(rps) {
		b.tokens = float64(rps)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	deficit := 1 - b.tokens
	return false, time.Duration(deficit / float64(rps) * float64(time.Second))
}

// SetNow overrides the clock (tests).
func (l *Limiter) SetNow(f func() time.Time) { l.now = f }
