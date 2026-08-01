// Package scopeverify implements the defense-in-depth ingest check of
// doc 09 §2.2/§9.1: for output of R1+ tasks, dp RE-VERIFIES the
// gatekeeper-issued Scope Token — Ed25519 signature via gatekeeper JWKS,
// expiry, task binding, and target ∈ manifest/scope (doc 01 §10.1
// canonicalized matching, exclusions always win). dp never GRANTS anything
// (Ruling B): it re-verifies gatekeeper's grant so a compromised scanner
// cannot poison out-of-scope tenants. Fail-closed: any verification failure
// rejects the batch with AUTHORIZATION_UNVERIFIABLE.
package scopeverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// Verifier re-verifies Scope Tokens on ingest.
type Verifier struct {
	tokens  *token.Verifier
	fetcher manifest.Fetcher
}

// New builds a Verifier from the gatekeeper JWKS URL and the MinIO/S3
// manifest source (token-manifests bucket, doc 11 §3.2).
func New(jwksURL string, s3cfg manifest.S3Config, httpClient *http.Client) *Verifier {
	src := token.NewHTTPKeySource(jwksURL, httpClient)
	cache := token.NewKeyCache(src)
	return &Verifier{
		tokens:  token.NewVerifier(cache),
		fetcher: manifest.NewS3Fetcher(s3cfg),
	}
}

// NewWithSources builds a Verifier over injected sources (tests).
func NewWithSources(src token.KeySource, fetcher manifest.Fetcher) *Verifier {
	return &Verifier{
		tokens:  token.NewVerifier(token.NewKeyCache(src)),
		fetcher: fetcher,
	}
}

// Failure classifies a re-verification failure (all map to the single
// RFC 9457 reason AUTHORIZATION_UNVERIFIABLE — dp never emits gatekeeper's
// denial codes, doc 09 §12).
type Failure struct {
	Stage  string // token|task_binding|manifest|scope
	Detail string
	Err    error
}

func (f *Failure) Error() string { return f.Stage + ": " + f.Detail }

// Unwrap exposes the underlying typed SDK error.
func (f *Failure) Unwrap() error { return f.Err }

// Result is a successful re-verification.
type Result struct {
	Claims *token.Claims
	// JTI is the token id recorded in dp.ingest_batches.scope_token_jti.
	JTI string
	// ScopeAuditValue is the "scope:sha256:<hash>" audit value for
	// scope-bound tokens (Ruling A.3); empty otherwise.
	ScopeAuditValue string
}

// Verify re-verifies rawToken for a batch attributed to taskID touching
// targets. Order (fail-closed at each step):
//
//  1. Token structure + Ed25519 signature vs cached JWKS + full claim
//     checks (iss/aud/TTL ≤ 15 min/expiry, scope_bound applicability, R3
//     approval) — the SDK's canonical verifier.
//  2. Task binding: the batch's task_id must equal the token's task_id
//     (a token is bound to one task and useless elsewhere, Ruling C5).
//  3. Manifest: fetch the hashed target manifest (MinIO), sha256 pinned to
//     the token claim.
//  4. Target check: every target the batch touches must be in the manifest
//     (exact-enumerated form) or allowed by the embedded scope (scope-bound
//     watch tokens, Ruling A). Exclusions always win.
func (v *Verifier) Verify(ctx context.Context, rawToken, taskID string, targets []string) (*Result, error) {
	if rawToken == "" {
		return nil, &Failure{Stage: "token", Detail: "R1+ batch presented no scope_token"}
	}
	claims, err := v.tokens.Verify(ctx, rawToken)
	if err != nil {
		return nil, &Failure{Stage: "token", Detail: err.Error(), Err: err}
	}
	if taskID != "" && claims.TaskID != taskID {
		return nil, &Failure{Stage: "task_binding", Detail: fmt.Sprintf(
			"batch task_id %q does not match token task_id %q", taskID, claims.TaskID)}
	}
	m, err := manifest.Load(ctx, v.fetcher, claims.Targets, claims.ScopeBound)
	if err != nil {
		return nil, &Failure{Stage: "manifest", Detail: err.Error(), Err: err}
	}
	for _, t := range targets {
		if claims.ScopeBound {
			if d := m.EvaluateScope(t); !d.Allowed {
				return nil, &Failure{Stage: "scope", Detail: fmt.Sprintf(
					"target %q rejected by scope-bound manifest: %s", t, d.Reason)}
			}
			continue
		}
		if !m.Contains(t) {
			return nil, &Failure{Stage: "scope", Detail: fmt.Sprintf(
				"target %q is not in the token's exact-enumerated manifest", t)}
		}
	}
	return &Result{Claims: claims, JTI: claims.ID, ScopeAuditValue: m.ScopeAuditValue()}, nil
}

// IsFailure reports whether err is a re-verification failure (vs an
// infrastructure error).
func IsFailure(err error) bool {
	var f *Failure
	return errors.As(err, &f)
}

// JWKSUnavailable reports whether the failure root-causes to an unreachable
// JWKS (doc 09 §8: unreachable JWKS cache + expired token ⇒ fail closed).
func JWKSUnavailable(err error) bool { return errors.Is(err, token.ErrJWKS) }

// Leeway re-export for callers logging expiry diagnostics.
const Leeway = token.Leeway

// MaxTTLSecs re-export (15-minute TTL, Ruling C5).
const MaxTTLSecs = token.MaxTTLSecs
