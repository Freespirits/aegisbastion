package pep

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// ErrRateLimited — the burst exceeds the token's rate caps (the token is NOT
// a capability to bypass rate limits, doc 11 §3.2).
var ErrRateLimited = errors.New("pep: token rate caps exceeded")

// maxThrottleDelay bounds how long AuthorizeTarget will block waiting for the
// token bucket before denying instead — a task that would be delayed longer
// is over its sustained budget, not just bursting.
const maxThrottleDelay = 5 * time.Second

// RateLimiter enforces the token's self-contained rate_caps claim
// (max_rps ≡ rps; max_concurrent) locally — no PDP call per request
// (doc 11 §3.2). Zero caps mean "unset" (no SDK-side limit; the Scheduler's
// per-RoE buckets still apply centrally).
type RateLimiter struct {
	rps *rate.Limiter
	sem chan struct{}

	mu      sync.Mutex
	running int
}

// NewRateLimiter builds a limiter from token claims. caps may be nil.
func NewRateLimiter(caps *token.RateCaps) *RateLimiter {
	l := &RateLimiter{}
	if caps != nil {
		if caps.MaxRPS > 0 {
			n := int(caps.MaxRPS)
			// One second's worth of burst: the per-second ceiling may be
			// consumed in a single burst, never exceeded sustained.
			l.rps = rate.NewLimiter(rate.Limit(n), n)
		}
		if caps.MaxConcurrent > 0 {
			l.sem = make(chan struct{}, caps.MaxConcurrent)
		}
	}
	return l
}

// Allow reports whether one request may fire right now (non-blocking).
func (l *RateLimiter) Allow() bool {
	if l.rps == nil {
		return true
	}
	return l.rps.Allow()
}

// Wait blocks until the token bucket admits one request, denying with
// ErrRateLimited when the wait would exceed the burst-tolerance bound or the
// context expires first.
func (l *RateLimiter) Wait(ctx context.Context) error {
	if l.rps == nil {
		return nil
	}
	res := l.rps.Reserve()
	if !res.OK() {
		return ErrRateLimited
	}
	delay := res.Delay()
	if delay > maxThrottleDelay {
		res.Cancel()
		return ErrRateLimited
	}
	if delay == 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		res.Cancel()
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Acquire takes a concurrency slot (max_concurrent). It blocks until a slot
// frees or ctx expires.
func (l *RateLimiter) Acquire(ctx context.Context) error {
	if l.sem == nil {
		l.mu.Lock()
		l.running++
		l.mu.Unlock()
		return nil
	}
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryAcquire takes a concurrency slot without blocking.
func (l *RateLimiter) TryAcquire() bool {
	if l.sem == nil {
		l.mu.Lock()
		l.running++
		l.mu.Unlock()
		return true
	}
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a concurrency slot.
func (l *RateLimiter) Release() {
	if l.sem == nil {
		l.mu.Lock()
		if l.running > 0 {
			l.running--
		}
		l.mu.Unlock()
		return
	}
	select {
	case <-l.sem:
	default:
	}
}
