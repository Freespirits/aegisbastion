// Package token verifies gatekeeper Scope Tokens — the ONLY execution
// credential in the platform (Ruling C5): Ed25519-signed JWTs (EdDSA),
// JWKS-verified, task-bound, audience "aegisbastion.modules", 15-minute TTL for
// all active classes R1–R3 (doc 01 §5.5 Authorization Token v1.1, doc 11 §3.2).
//
// Verification is fully local: signatures are checked against a cached JWKS
// (refreshed at most every 5 minutes, doc 11 §6), exp/nbf carry 60 s of
// leeway, and tokens whose iat is more than 120 s in the future are rejected
// as clock-skew/replay suspects (doc 11 §7). Every check is fail-closed: any
// anomaly returns a typed error and the caller (pep.Guard) refuses target
// contact — doc 01 §15 acceptance test 2.
package token

import (
	"errors"
	"time"
)

// Claim constants (doc 01 §5.5, doc 11 §3.2).
const (
	// Issuer is the only accepted iss claim.
	Issuer = "gatekeeper.platform"
	// Audience is the only accepted aud claim.
	Audience = "aegisbastion.modules"
	// MaxTTLSecs is the maximum exp−iat: 15 minutes for ALL active classes
	// R1–R3 (Ruling C5 — uniform).
	MaxTTLSecs int64 = 900
	// Leeway applied to nbf and exp verification (doc 01 §13 clock skew).
	Leeway = 60 * time.Second
	// MaxClockSkew bounds how far iat may be in the future before the token
	// is rejected as a replay/tamper suspect (doc 11 §7).
	MaxClockSkew = 120 * time.Second
	// JWKSTTL is the maximum JWKS cache age (doc 11 §6: "JWKS cached, 5-min
	// refresh"; key compromise propagates within 5 min, doc 11 §7).
	JWKSTTL = 5 * time.Minute
)

// ScopeBoundCapabilities are the only capabilities a scope_bound=true token
// may carry — the R1 standing capabilities monitor.watch / monitor.rescan
// (Ruling A.1, A.2).
var ScopeBoundCapabilities = []string{"monitor.watch", "monitor.rescan"}

// Verification failure kinds. All are wrapped with detail via fmt.Errorf %w,
// so callers classify with errors.Is.
var (
	// ErrMalformed — the compact JWT does not have three base64url segments
	// or its JSON does not decode.
	ErrMalformed = errors.New("token: malformed JWT")
	// ErrAlgorithm — header alg is not "EdDSA".
	ErrAlgorithm = errors.New("token: unexpected signing algorithm")
	// ErrUnknownKey — the kid is not in the JWKS (even after a forced refresh).
	ErrUnknownKey = errors.New("token: unknown key id")
	// ErrJWKS — the JWKS could not be fetched (fail-closed).
	ErrJWKS = errors.New("token: JWKS unavailable")
	// ErrSignature — Ed25519 signature verification failed (forged token).
	ErrSignature = errors.New("token: signature verification failed")
	// ErrIssuer — iss is not gatekeeper.platform.
	ErrIssuer = errors.New("token: unexpected issuer")
	// ErrAudience — aud is not aegisbastion.modules.
	ErrAudience = errors.New("token: unexpected audience")
	// ErrMissingClaim — a required claim is absent or empty.
	ErrMissingClaim = errors.New("token: required claim missing or empty")
	// ErrRiskClass — risk_class is not R1/R2/R3 (tokens are minted only for
	// active classes; R0 requires no token, doc 11 §1).
	ErrRiskClass = errors.New("token: invalid risk class")
	// ErrExpired — exp passed (with Leeway applied).
	ErrExpired = errors.New("token: expired")
	// ErrNotYetValid — nbf is in the future (with Leeway applied).
	ErrNotYetValid = errors.New("token: not yet valid (nbf)")
	// ErrClockSkew — iat is more than MaxClockSkew in the future.
	ErrClockSkew = errors.New("token: issued-at too far in the future (clock skew)")
	// ErrTTL — exp−iat exceeds MaxTTLSecs.
	ErrTTL = errors.New("token: TTL exceeds the 15-minute maximum")
	// ErrScopeBound — scope_bound=true on a non-R1 token or with capabilities
	// outside monitor.watch/monitor.rescan (Ruling A.1 — narrow applicability).
	ErrScopeBound = errors.New("token: scope_bound misuse")
	// ErrApproval — R3 token without the mandatory four-eyes approval_id
	// (Ruling B.4; schemas/gatekeeper/v1/scope-token-claims.schema.json).
	ErrApproval = errors.New("token: R3 token missing approval_id")
)
