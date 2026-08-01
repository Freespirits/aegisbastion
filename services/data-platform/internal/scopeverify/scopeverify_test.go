package scopeverify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// testKey is one throwaway Ed25519 identity standing in for gatekeeper's
// signing key (tests never touch the real key file).
type testKey struct {
	priv ed25519.PrivateKey
	jwk  token.JWK
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{
		priv: priv,
		jwk: token.JWK{
			Kty: "OKP", Crv: "Ed25519", Kid: "test-key-1", Alg: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(pub),
		},
	}
}

// sign mints a compact EdDSA JWT exactly as gatekeeper's token-service does
// (doc 11 §3.2): base64url(header).base64url(claims).base64url(sig).
func (k *testKey) sign(t *testing.T, claims token.Claims) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": k.jwk.Kid})
	body, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hdr)
	b := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(k.priv, []byte(h+"."+b))
	return h + "." + b + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// exactManifest builds an exact-enumerated manifest (canonical JSON target
// list) and the matching TargetManifestRef (doc 11 §3.2).
func exactManifest(t *testing.T, targets []string) (uri string, raw []byte, ref token.TargetManifestRef) {
	t.Helper()
	raw, _ = json.Marshal(targets)
	sum := sha256.Sum256(raw)
	uri = "blob://tokens/tok_test/targets.json"
	return uri, raw, token.TargetManifestRef{
		HashAlg:        "sha256",
		ManifestURI:    uri,
		ManifestSHA256: hex.EncodeToString(sum[:]),
		Count:          uint32(len(targets)),
	}
}

func validClaims(ref token.TargetManifestRef) token.Claims {
	now := time.Now().Unix()
	return token.Claims{
		Issuer:       token.Issuer,
		Audience:     token.Audience,
		ID:           "tok_test_1",
		Subject:      "svc-detect",
		TaskID:       "tsk_01JTEST",
		ROEID:        "roe_01JTEST",
		ROEVersion:   1,
		RiskClass:    "R2",
		Capabilities: []string{"detect.scan"},
		Targets:      ref,
		IssuedAt:     now,
		NotBefore:    now - 5,
		ExpiresAt:    now + 600,
	}
}

func newTestVerifier(t *testing.T, key *testKey, fetcher manifest.Fetcher) *Verifier {
	t.Helper()
	return NewWithSources(token.KeySourceFunc(
		func(ctx context.Context) ([]token.JWK, error) { return []token.JWK{key.jwk}, nil }), fetcher)
}

func TestVerifyValidExactManifest(t *testing.T) {
	key := newTestKey(t)
	uri, raw, ref := exactManifest(t, []string{"api.example.com", "203.0.113.10"})
	claims := validClaims(ref)
	tok := key.sign(t, claims)

	v := newTestVerifier(t, key, manifest.FetcherFunc(
		func(ctx context.Context, u string) ([]byte, error) {
			if u != uri {
				t.Fatalf("fetch %q, want %q", u, uri)
			}
			return raw, nil
		}))

	res, err := v.Verify(context.Background(), tok, "tsk_01JTEST",
		[]string{"api.example.com", "203.0.113.10"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.JTI != "tok_test_1" {
		t.Errorf("JTI = %q", res.JTI)
	}
	if res.ScopeAuditValue != "" {
		t.Errorf("ScopeAuditValue = %q, want empty for exact-enumerated", res.ScopeAuditValue)
	}
}

func TestVerifyFailuresFailClosed(t *testing.T) {
	key := newTestKey(t)
	_, raw, ref := exactManifest(t, []string{"api.example.com"})
	fetcher := manifest.FetcherFunc(func(ctx context.Context, u string) ([]byte, error) { return raw, nil })

	t.Run("no token", func(t *testing.T) {
		v := newTestVerifier(t, key, fetcher)
		if _, err := v.Verify(context.Background(), "", "tsk_01JTEST", nil); err == nil {
			t.Fatal("accepted empty token")
		} else if !IsFailure(err) {
			t.Fatalf("err %v not a Failure", err)
		}
	})

	t.Run("forged signature", func(t *testing.T) {
		evil := newTestKey(t)
		tok := evil.sign(t, validClaims(ref))
		v := newTestVerifier(t, key, fetcher)
		if _, err := v.Verify(context.Background(), tok, "tsk_01JTEST", nil); err == nil {
			t.Fatal("accepted forged token (doc 01 §15 acceptance: forged ⇒ refuse)")
		} else if !errors.Is(err, token.ErrSignature) {
			t.Fatalf("err = %v, want ErrSignature", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		claims := validClaims(ref)
		claims.IssuedAt = time.Now().Unix() - 2000
		claims.NotBefore = claims.IssuedAt
		claims.ExpiresAt = claims.IssuedAt + 900 // ≤ 15 min TTL but long past
		tok := key.sign(t, claims)
		v := newTestVerifier(t, key, fetcher)
		if _, err := v.Verify(context.Background(), tok, "tsk_01JTEST", nil); err == nil {
			t.Fatal("accepted expired token")
		} else if !errors.Is(err, token.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("task binding", func(t *testing.T) {
		tok := key.sign(t, validClaims(ref)) // bound to tsk_01JTEST
		v := newTestVerifier(t, key, fetcher)
		_, err := v.Verify(context.Background(), tok, "tsk_OTHER", nil)
		if err == nil {
			t.Fatal("accepted token bound to a different task (Ruling C5: useless elsewhere)")
		}
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "task_binding" {
			t.Fatalf("err = %v, want task_binding Failure", err)
		}
	})

	t.Run("target outside manifest", func(t *testing.T) {
		tok := key.sign(t, validClaims(ref))
		v := newTestVerifier(t, key, fetcher)
		_, err := v.Verify(context.Background(), tok, "tsk_01JTEST", []string{"evil.example.net"})
		if err == nil {
			t.Fatal("accepted out-of-manifest target")
		}
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "scope" {
			t.Fatalf("err = %v, want scope Failure", err)
		}
	})

	t.Run("manifest hash mismatch", func(t *testing.T) {
		tok := key.sign(t, validClaims(ref))
		v := newTestVerifier(t, key, manifest.FetcherFunc(
			func(ctx context.Context, u string) ([]byte, error) { return []byte(`["tampered"]`), nil }))
		_, err := v.Verify(context.Background(), tok, "tsk_01JTEST", []string{"api.example.com"})
		if err == nil {
			t.Fatal("accepted tampered manifest")
		}
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "manifest" {
			t.Fatalf("err = %v, want manifest Failure", err)
		}
	})

	t.Run("jwks unreachable", func(t *testing.T) {
		v := NewWithSources(token.KeySourceFunc(
			func(ctx context.Context) ([]token.JWK, error) { return nil, errors.New("connection refused") }),
			fetcher)
		tok := key.sign(t, validClaims(ref))
		_, err := v.Verify(context.Background(), tok, "tsk_01JTEST", nil)
		if err == nil {
			t.Fatal("accepted token with JWKS down (doc 09 §8: fail closed)")
		}
	})

	t.Run("overlong ttl", func(t *testing.T) {
		claims := validClaims(ref)
		claims.ExpiresAt = claims.IssuedAt + 3600 // > 15 min (Ruling C5)
		tok := key.sign(t, claims)
		v := newTestVerifier(t, key, fetcher)
		if _, err := v.Verify(context.Background(), tok, "tsk_01JTEST", nil); err == nil {
			t.Fatal("accepted token with TTL > 15 min")
		} else if !errors.Is(err, token.ErrTTL) {
			t.Fatalf("err = %v, want ErrTTL", err)
		}
	})

	t.Run("target canonicalization", func(t *testing.T) {
		// Case + trailing-dot host forms match the canonical manifest entry
		// (exact-enumerated manifests hold canonical target strings; a URL
		// form stays a URL and would need its own entry — doc 01 §10.1).
		tok := key.sign(t, validClaims(ref))
		v := newTestVerifier(t, key, fetcher)
		if _, err := v.Verify(context.Background(), tok, "tsk_01JTEST",
			[]string{"API.Example.Com."}); err != nil {
			t.Fatalf("canonical form of manifest target rejected: %v", err)
		}
	})
}

func TestScopeBoundWatchToken(t *testing.T) {
	key := newTestKey(t)
	// Scope-bound manifest (Ruling A): canonical scope document; sha256 IS the
	// "scope:sha256:<hash>" audit value.
	scopeDoc := map[string]any{
		"roe_id": "roe_01JTEST", "roe_version": 1,
		"scope": map[string]any{
			// exact apex + wildcard subdomain coverage (doc 01 §10.1: a
			// wildcard does not imply the apex; both are listed explicitly).
			"domains":           []string{"example.com", "*.example.com"},
			"cidrs":             []string{},
			"explicit_excludes": []string{"internal.example.com"},
		},
	}
	raw, _ := json.Marshal(scopeDoc)
	sum := sha256.Sum256(raw)
	uri := "blob://tokens/tok_watch/scope.json"
	now := time.Now().Unix()
	claims := token.Claims{
		Issuer: token.Issuer, Audience: token.Audience,
		ID: "tok_watch", Subject: "svc-monitor", TaskID: "tsk_WATCH",
		ROEID: "roe_01JTEST", ROEVersion: 1, RiskClass: "R1",
		Capabilities: []string{"monitor.watch"},
		Targets: token.TargetManifestRef{
			HashAlg: "sha256", ManifestURI: uri, ManifestSHA256: hex.EncodeToString(sum[:]),
		},
		ScopeBound: true,
		IssuedAt:   now, NotBefore: now - 5, ExpiresAt: now + 600,
	}
	tok := key.sign(t, claims)
	v := newTestVerifier(t, key, manifest.FetcherFunc(
		func(ctx context.Context, u string) ([]byte, error) { return raw, nil }))

	res, err := v.Verify(context.Background(), tok, "tsk_WATCH", []string{"api.example.com"})
	if err != nil {
		t.Fatalf("in-scope target rejected: %v", err)
	}
	if !strings.HasPrefix(res.ScopeAuditValue, "scope:sha256:") {
		t.Errorf("ScopeAuditValue = %q, want scope:sha256:…", res.ScopeAuditValue)
	}
	if _, err := v.Verify(context.Background(), tok, "tsk_WATCH", []string{"internal.example.com"}); err == nil {
		t.Fatal("excluded target accepted — exclusions must always win (Ruling A.5)")
	}
	if _, err := v.Verify(context.Background(), tok, "tsk_WATCH", []string{"other.org"}); err == nil {
		t.Fatal("out-of-scope target accepted by scope-bound token")
	}
}
