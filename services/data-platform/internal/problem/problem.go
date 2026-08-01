// Package problem renders RFC 9457 problem+json responses with the
// machine-readable reason codes of doc 09 §12. dp NEVER emits authorization
// denial codes (NOT_IN_SCOPE, ROE_EXPIRED, …) — those are gatekeeper's enum
// (doc 11 §3.3); dp only re-verifies and reports AUTHORIZATION_UNVERIFIABLE.
package problem

import (
	"encoding/json"
	"net/http"
)

// Reason codes (doc 09 §12), plus the few service-local codes the doc's list
// does not cover (grant bootstrap, state machine, lookup misses).
const (
	// AuthorizationUnverifiable — an R1+ batch's Scope Token could not be
	// re-verified (JWKS/expiry/task-binding/manifest/scope), or is missing.
	AuthorizationUnverifiable = "AUTHORIZATION_UNVERIFIABLE"
	// SchemaInvalid — payload failed schema validation.
	SchemaInvalid = "SCHEMA_INVALID"
	// TenantMismatch — payload/requested tenant does not match the tenant
	// resolved from the caller's credential.
	TenantMismatch = "TENANT_MISMATCH"
	// RetentionLocked — legal hold freezes the retention subtree (doc 09 §10).
	RetentionLocked = "RETENTION_LOCKED"
	// GrantRequired — caller principal holds no dp grant for any tenant.
	GrantRequired = "GRANT_REQUIRED"
	// StateTransitionInvalid — findings lifecycle edge not in doc 04 §7.3.
	StateTransitionInvalid = "STATE_TRANSITION_INVALID"
	// NotFound — the addressed object does not exist (in this tenant).
	NotFound = "NOT_FOUND"
)

// Problem is an RFC 9457 problem document.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

func (p *Problem) Error() string { return p.Reason + ": " + p.Detail }

// New builds a problem. typ is the URN suffix under
// https://dp.platform/errors/ (doc 09 §3.3 example).
func New(status int, typ, title, reason, detail string) *Problem {
	return &Problem{
		Type:   "https://dp.platform/errors/" + typ,
		Title:  title,
		Status: status,
		Reason: reason,
		Detail: detail,
	}
}

// Write renders the problem as application/problem+json.
func Write(w http.ResponseWriter, p *Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// Convenience constructors for the common cases.

func Invalid(detail string) *Problem {
	return New(http.StatusBadRequest, "schema-invalid", "Payload failed schema validation", SchemaInvalid, detail)
}

func Unverifiable(detail string) *Problem {
	return New(http.StatusForbidden, "authorization-unverifiable", "Scope Token verification failed", AuthorizationUnverifiable, detail)
}

func Mismatch(detail string) *Problem {
	return New(http.StatusForbidden, "tenant-mismatch", "Tenant does not match credential", TenantMismatch, detail)
}

func NoGrant(detail string) *Problem {
	return New(http.StatusForbidden, "grant-required", "Caller holds no data-platform grant", GrantRequired, detail)
}

func NotFoundProblem(detail string) *Problem {
	return New(http.StatusNotFound, "not-found", "Object not found", NotFound, detail)
}

func TransitionInvalid(detail string) *Problem {
	return New(http.StatusConflict, "state-transition-invalid", "Illegal findings lifecycle transition", StateTransitionInvalid, detail)
}

func RetentionLockedProblem(detail string) *Problem {
	return New(http.StatusConflict, "retention-locked", "Legal hold freezes this object", RetentionLocked, detail)
}

func Internal(detail string) *Problem {
	return New(http.StatusInternalServerError, "internal", "Internal error", "INTERNAL", detail)
}
