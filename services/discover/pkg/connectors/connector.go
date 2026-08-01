// Package connectors implements doc 02 §4.3's Connector plugin interface: one
// plugin per external source (passive DNS, CT logs, BGP/RDAP aggregators).
// Every connector is interface-driven and fixture-capable so tests and the
// offline mode run without internet (doc 02 §9: recorded-fixture tests, no
// live API in CI).
//
// Connectors contact SOURCES (third-party data APIs), never the order's
// targets — R0's contract is zero target contact (doc 11 §1). Egress passes
// the netguard dialer wrapper (doc 02 §6.3).
package connectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// Health states (doc 02 §4.3 healthcheck).
type Health string

const (
	HealthOK       Health = "ok"
	HealthDegraded Health = "degraded"
	HealthDown     Health = "down"
)

// RateSpec is the connector's declared rate envelope (doc 02 §4.3).
type RateSpec struct {
	RPS        float64 `json:"rps" yaml:"rps"`
	Burst      int     `json:"burst" yaml:"burst"`
	DailyQuota int     `json:"daily_quota" yaml:"daily_quota"` // 0 = none
}

// RunInput is one task's worth of work for a connector.
type RunInput struct {
	Task model.Task
	// ScopeToken is passed through verbatim (doc 02 §4.3 run(ctx, seed,
	// scope_token)) — passive connectors never forward it to sources; it
	// exists for the worker's verification and future active connectors.
	ScopeToken string
	// ObservedAt pins the observation time (fixtures/tests).
	ObservedAt time.Time
}

// EmitFunc receives findings as they stream out of a connector, each with
// its inferred edges (possibly empty).
type EmitFunc func(f model.RawFinding, edges []EdgeRef) error

// Connector is the doc 02 §4.3 plugin interface.
type Connector interface {
	// Name — "crt.sh", "censys", "aws_resource_explorer", …
	Name() string
	// Techniques this connector serves.
	Techniques() []model.Technique
	// RateSpec — declared envelope enforced by the registry's limiter.
	RateSpec() RateSpec
	// RequiresCredentials — API keys/secrets fetched by the worker per tenant
	// (never embedded in task payloads, doc 02 §2.2).
	RequiresCredentials() bool
	// Run executes the task's seed query, streaming 0..N RawFindings.
	Run(ctx context.Context, in RunInput, emit EmitFunc) error
	// Healthcheck reports ok|degraded|down (circuit-breaker informed).
	Healthcheck(ctx context.Context) Health
}

// Fetcher retrieves one source response. The live implementation is the
// netguard-guarded HTTP client; the fixture implementation replays recorded
// responses (offline mode + tests).
type Fetcher interface {
	Fetch(ctx context.Context, req *Request) ([]byte, error)
}

// Request is a source request (method, URL, headers, body).
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// FetcherFunc adapts a function (tests).
type FetcherFunc func(ctx context.Context, req *Request) ([]byte, error)

// Fetch implements Fetcher.
func (f FetcherFunc) Fetch(ctx context.Context, req *Request) ([]byte, error) {
	return f(ctx, req)
}

// ErrNotFound marks a source-side "no data" (404 or empty page) — not an
// error for the task; zero findings.
var ErrNotFound = errors.New("connectors: source returned no data")

// KeyProvider resolves per-tenant source credentials at task time (doc 02
// §2.2: secrets pulled from the platform vault, keyed by tenant; MVP-A reads
// them from a local config file — see internal/config).
type KeyProvider interface {
	APIKey(ctx context.Context, tenantID, connector string) (string, error)
}

// KeyProviderFunc adapts a function.
type KeyProviderFunc func(ctx context.Context, tenantID, connector string) (string, error)

// APIKey implements KeyProvider.
func (f KeyProviderFunc) APIKey(ctx context.Context, tenantID, connector string) (string, error) {
	return f(ctx, tenantID, connector)
}

// StaticKeys is a config-file KeyProvider (tenant "*" is the fallback).
type StaticKeys map[string]map[string]string // tenant → connector → key

// APIKey implements KeyProvider.
func (k StaticKeys) APIKey(_ context.Context, tenantID, connector string) (string, error) {
	if k == nil {
		return "", fmt.Errorf("no credentials configured")
	}
	if byConn, ok := k[tenantID]; ok {
		if key, ok := byConn[connector]; ok && key != "" {
			return key, nil
		}
	}
	if byConn, ok := k["*"]; ok {
		if key, ok := byConn[connector]; ok && key != "" {
			return key, nil
		}
	}
	return "", fmt.Errorf("no api key for connector %q (tenant %s)", connector, tenantID)
}

// Entry couples a Connector with its runtime state (limiter, breaker).
type Entry struct {
	Connector Connector
	limiter   *tokenBucket
	breaker   *circuitBreaker
}

// Registry holds the enabled connectors (from connectors.yaml) and enforces
// per-source rate specs + circuit breakers (doc 02 §7.1).
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry // by connector name
	keys    KeyProvider
	now     func() time.Time
}

// NewRegistry builds a registry. keys may be nil (credentialed connectors
// will fail closed at Run).
func NewRegistry(keys KeyProvider) *Registry {
	return &Registry{
		entries: map[string]*Entry{},
		keys:    keys,
		now:     time.Now,
	}
}

// Register adds a connector (called by DefaultRegistry per the manifest).
func (r *Registry) Register(c Connector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	spec := c.RateSpec()
	r.entries[c.Name()] = &Entry{
		Connector: c,
		limiter:   newTokenBucket(spec.RPS, spec.Burst, spec.DailyQuota, r.now),
		breaker:   newCircuitBreaker(5, 30*time.Second, r.now),
	}
}

// Names lists registered connector names (sorted, stable).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for n := range r.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns a connector by name.
func (r *Registry) Get(name string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, false
	}
	return e.Connector, true
}

// ForTechnique returns connector names serving a technique (sorted).
func (r *Registry) ForTechnique(t model.Technique) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for n, e := range r.entries {
		for _, ct := range e.Connector.Techniques() {
			if ct == t {
				out = append(out, n)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Health reports per-source health for the status surface.
func (r *Registry) Health(ctx context.Context) map[string]Health {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]Health{}
	for n, e := range r.entries {
		if e.breaker.Open() {
			out[n] = HealthDown
			continue
		}
		out[n] = e.Connector.Healthcheck(ctx)
	}
	return out
}

// Run executes a connector with rate-limit + circuit-breaker enforcement and
// credential injection (doc 02 §2.2: keys fetched at task time, keyed by
// tenant). Fail-closed: circuit open ⇒ SOURCE_UNAVAILABLE-style error; the
// caller maps it onto the order's PARTIAL accounting.
func (r *Registry) Run(ctx context.Context, name string, in RunInput, emit EmitFunc) error {
	r.mu.RLock()
	e, ok := r.entries[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("connector %q not registered", name)
	}
	if !e.breaker.Allow() {
		return fmt.Errorf("%w: connector %s circuit open", ErrSourceUnavailable, name)
	}
	if err := e.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("connector %s rate wait: %w", name, err)
	}
	err := e.Connector.Run(ctx, in, emit)
	e.breaker.Observe(err == nil || errors.Is(err, ErrNotFound))
	return err
}

// ErrSourceUnavailable maps to the doc 02 §3.3 SOURCE_UNAVAILABLE reason.
var ErrSourceUnavailable = errors.New("SOURCE_UNAVAILABLE")

// --- token bucket (per-source, in-process) --------------------------------
// MVP-A deviation (mirroring gatekeeper's): doc 02 §5 lists Redis for rate
// buckets, but the MVP-A Compose host has no Redis; buckets are in-process
// per worker. Redis lands with horizontal scaling (MVP-B).

type tokenBucket struct {
	mu       sync.Mutex
	rps      float64
	burst    int
	quota    int
	tokens   float64
	lastFill time.Time
	dayStart time.Time
	dayUsed  int
	now      func() time.Time
}

func newTokenBucket(rps float64, burst, quota int, now func() time.Time) *tokenBucket {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = 1
	}
	return &tokenBucket{
		rps: rps, burst: burst, quota: quota,
		tokens: float64(burst), lastFill: now(), dayStart: now(), now: now,
	}
}

// Wait blocks until one token is available or ctx ends.
func (b *tokenBucket) Wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := b.now()
		elapsed := now.Sub(b.lastFill).Seconds()
		b.tokens += elapsed * b.rps
		if b.tokens > float64(b.burst) {
			b.tokens = float64(b.burst)
		}
		b.lastFill = now
		if now.Sub(b.dayStart) >= 24*time.Hour {
			b.dayStart = now
			b.dayUsed = 0
		}
		if b.quota > 0 && b.dayUsed >= b.quota {
			b.mu.Unlock()
			return fmt.Errorf("daily quota %d exhausted", b.quota)
		}
		if b.tokens >= 1 {
			b.tokens--
			b.dayUsed++
			b.mu.Unlock()
			return nil
		}
		deficit := 1 - b.tokens
		b.mu.Unlock()
		wait := time.Duration(deficit / b.rps * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// --- circuit breaker (doc 02 §7.1: open after 5 consecutive failures, ------
// half-open probe) ------------------------------------------------------------

type circuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	cooldown    time.Duration
	consecFails int
	openedAt    time.Time
	now         func() time.Time
}

func newCircuitBreaker(threshold int, cooldown time.Duration, now func() time.Time) *circuitBreaker {
	return &circuitBreaker{threshold: threshold, cooldown: cooldown, now: now}
}

// Allow reports whether a request may proceed (half-open probe after the
// cooldown).
func (b *circuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.consecFails < b.threshold {
		return true
	}
	return b.now().Sub(b.openedAt) >= b.cooldown
}

// Open reports the breaker state (for health surfacing).
func (b *circuitBreaker) Open() bool { return !b.Allow() }

// Observe records an outcome.
func (b *circuitBreaker) Observe(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.consecFails = 0
		return
	}
	b.consecFails++
	if b.consecFails >= b.threshold && b.openedAt.IsZero() {
		b.openedAt = b.now()
	}
	// Keep openedAt fresh while failing so the cooldown slides.
	if b.consecFails > b.threshold {
		b.openedAt = b.now()
	}
}
