package pep

import (
	"sync"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/scope"
)

// RevocationCache is the PEP-side revocation set (doc 11 §2.1.7/§7): fed by
// tasks.revocations.v1 events (≤ 5 s halt SLA) and reconciled against
// RevocationService.ListRevocations at ≤ 30 s. It answers, for every intended
// action, "has this been revoked?" — global, per-RoE, per-target, or
// per-capability.
//
// Fail-closed posture: a missed refresh keeps the last known set (never
// silently clears); a revoked entry without expiry holds until a snapshot
// from the service lifts it.
type RevocationCache struct {
	now func() time.Time

	mu      sync.RWMutex
	entries map[revocationKey]revocationEntry
}

type revocationKey struct {
	scope gatekeeperv1.RevocationScope
	key   string // canonicalized for TARGET scope
}

type revocationEntry struct {
	id        string
	expiresAt time.Time // zero = until lifted
	reason    string
}

// RevocationCacheOption configures a RevocationCache.
type RevocationCacheOption func(*RevocationCache)

// WithRevocationClock injects a clock (tests).
func WithRevocationClock(now func() time.Time) RevocationCacheOption {
	return func(c *RevocationCache) { c.now = now }
}

// NewRevocationCache builds an empty cache.
func NewRevocationCache(opts ...RevocationCacheOption) *RevocationCache {
	c := &RevocationCache{
		now:     time.Now,
		entries: map[revocationKey]revocationEntry{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func canonicalRevKey(s gatekeeperv1.RevocationScope, key string) revocationKey {
	if s == gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET {
		if t, err := scope.Canonicalize(key); err == nil {
			key = t.Canonical
		}
	}
	return revocationKey{scope: s, key: key}
}

// ApplyEvent applies one tasks.revocations.v1 event (the ≤ 5 s halt path).
func (c *RevocationCache) ApplyEvent(evt *gatekeeperv1.RevocationEvent) {
	if evt == nil || evt.GetRevocation() == nil {
		return
	}
	c.Apply(evt.GetRevocation())
}

// Apply records one revocation. Expired temporary revocations are dropped.
func (c *RevocationCache) Apply(rev *gatekeeperv1.Revocation) {
	if rev == nil || rev.GetScope() == gatekeeperv1.RevocationScope_REVOCATION_SCOPE_UNSPECIFIED {
		return
	}
	var exp time.Time
	if rev.GetExpiresAt() != nil {
		exp = rev.GetExpiresAt().AsTime()
		if !exp.IsZero() && !c.now().Before(exp) {
			return // already lapsed
		}
	}
	k := canonicalRevKey(rev.GetScope(), rev.GetKey())
	c.mu.Lock()
	c.entries[k] = revocationEntry{id: rev.GetRevocationId(), expiresAt: exp, reason: rev.GetReason()}
	c.mu.Unlock()
}

// Replace swaps in a full snapshot from RevocationService.ListRevocations —
// the ≤ 30 s reconciliation that lifts cleared revocations and backfills
// missed events.
func (c *RevocationCache) Replace(revs []*gatekeeperv1.Revocation) {
	fresh := map[revocationKey]revocationEntry{}
	for _, rev := range revs {
		if rev == nil || rev.GetScope() == gatekeeperv1.RevocationScope_REVOCATION_SCOPE_UNSPECIFIED {
			continue
		}
		var exp time.Time
		if rev.GetExpiresAt() != nil {
			exp = rev.GetExpiresAt().AsTime()
			if !exp.IsZero() && !c.now().Before(exp) {
				continue
			}
		}
		fresh[canonicalRevKey(rev.GetScope(), rev.GetKey())] = revocationEntry{
			id: rev.GetRevocationId(), expiresAt: exp, reason: rev.GetReason(),
		}
	}
	c.mu.Lock()
	c.entries = fresh
	c.mu.Unlock()
}

// Revoked reports whether an action under (roeID, capability, target) is
// revoked, and why. GLOBAL revokes everything. target may be "" (then the
// TARGET scope is not consulted).
func (c *RevocationCache) Revoked(roeID, capability, target string) (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	hit := func(k revocationKey) (string, bool) {
		e, ok := c.entries[k]
		if !ok {
			return "", false
		}
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			return "", false
		}
		reason := e.reason
		if reason == "" {
			reason = "revocation " + e.id
		}
		return reason, true
	}
	if r, ok := hit(revocationKey{scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL}); ok {
		return true, "global revocation: " + r
	}
	if roeID != "" {
		if r, ok := hit(revocationKey{scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE, key: roeID}); ok {
			return true, "RoE revocation: " + r
		}
	}
	if capability != "" {
		if r, ok := hit(revocationKey{scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY, key: capability}); ok {
			return true, "capability revocation: " + r
		}
	}
	if target != "" {
		if r, ok := hit(canonicalRevKey(gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET, target)); ok {
			return true, "target revocation: " + r
		}
	}
	return false, ""
}

// Halted reports whether a GLOBAL revocation is active.
func (c *RevocationCache) Halted() (bool, string) {
	return c.Revoked("", "", "")
}

// KillDecision interprets a control.kill broadcast envelope (core NATS, no
// stream) for this agent. The Orchestrator maps gatekeeper revocations onto
// control.kill (Ruling C11), so the payload is a gatekeeper RevocationEvent
// when typed; a per-mission kill may instead arrive as an envelope whose
// mission_id matches with no typed payload. Pure function — side-effect free
// so it is trivially testable.
//
// missionID/agentID scope the decision: a kill for another mission or agent
// does not halt this one.
func KillDecision(env *platformv1.Envelope, missionID string) (kill bool, reason string) {
	if env == nil {
		return false, ""
	}
	if env.GetPayload() != nil {
		if evt, err := env.GetPayload().UnmarshalNew(); err == nil {
			if rev, ok := evt.(*gatekeeperv1.RevocationEvent); ok {
				r := rev.GetRevocation()
				switch r.GetScope() {
				case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL:
					return true, "global kill: " + r.GetReason()
				case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
					gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET,
					gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY:
					// Scoped revocations halt only tasks matching the key —
					// the Guard consults the RevocationCache per target;
					// a broadcast of one is a platform-wide signal to check.
					return true, "scoped kill (" + r.GetScope().String() + " " + r.GetKey() + "): " + r.GetReason()
				}
			}
		}
	}
	// Untyped per-mission kill: envelope mission_id matches ours.
	if missionID != "" && env.GetMissionId() == missionID {
		return true, "mission kill: " + missionID
	}
	return false, ""
}
