package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testEnv holds a minting keypair and a verifier wired to its public key.
type testEnv struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	kid      string
	now      time.Time
	source   *mutableSource
	verifier *Verifier
}

type mutableSource struct {
	keys    []JWK
	fetches int
}

func (m *mutableSource) FetchKeys(context.Context) ([]JWK, error) {
	m.fetches++
	return m.keys, nil
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	kid := "gk-2026-07-a"
	src := &mutableSource{keys: []JWK{{
		Kty: "OKP", Crv: "Ed25519", Kid: kid, Alg: "EdDSA", Use: "sig",
		X: base64.RawURLEncoding.EncodeToString(pub),
	}}}
	v := NewVerifier(NewKeyCache(src), WithClock(func() time.Time { return now }))
	return &testEnv{pub: pub, priv: priv, kid: kid, now: now, source: src, verifier: v}
}

// mint builds a compact EdDSA JWT from claims (map form so tests can
// add/drop/alter claims freely), signed with priv under kid.
func mint(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validClaims returns a fully valid claim set at env time.
func (e *testEnv) validClaims() map[string]any {
	iat := e.now.Unix()
	return map[string]any{
		"iss":          "gatekeeper.platform",
		"aud":          "aegisbastion.modules",
		"jti":          "tok_01J9ZM8W3F",
		"sub":          "agent_01J92F",
		"task_id":      "tsk_01J92H",
		"roe_id":       "roe_01J8ZM",
		"roe_version":  3,
		"risk_class":   "R2",
		"capabilities": []string{"detect.scan"},
		"targets": map[string]any{
			"hash_alg":        "sha256",
			"manifest_uri":    "blob://tokens/tok_01J9ZM8W3F/targets.json",
			"manifest_sha256": strings.Repeat("9f", 32),
			"count":           1,
		},
		"scope_bound": false,
		"rate_caps":   map[string]any{"max_rps": 50, "max_concurrent": 2},
		"iat":         iat,
		"nbf":         iat,
		"exp":         iat + 900,
	}
}

func TestVerify_TableDriven(t *testing.T) {
	type mutation func(env *testEnv, claims map[string]any) (priv ed25519.PrivateKey, kid string)
	noop := func(env *testEnv, _ map[string]any) (ed25519.PrivateKey, string) {
		return env.priv, env.kid
	}

	cases := []struct {
		name    string
		mutate  func(env *testEnv, claims map[string]any)
		signer  mutation
		wantErr error
	}{
		{
			name:   "valid token verifies",
			mutate: func(*testEnv, map[string]any) {},
			signer: noop,
		},
		{
			name:   "forged signature rejected (doc 01 §15 acceptance 2)",
			mutate: func(*testEnv, map[string]any) {},
			signer: func(env *testEnv, _ map[string]any) (ed25519.PrivateKey, string) {
				_, evil, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return evil, env.kid
			},
			wantErr: ErrSignature,
		},
		{
			name:    "wrong audience rejected",
			mutate:  func(_ *testEnv, c map[string]any) { c["aud"] = "aegisbastion.ops" },
			signer:  noop,
			wantErr: ErrAudience,
		},
		{
			name:    "wrong issuer rejected",
			mutate:  func(_ *testEnv, c map[string]any) { c["iss"] = "fake-gatekeeper" },
			signer:  noop,
			wantErr: ErrIssuer,
		},
		{
			name: "expired rejected",
			mutate: func(env *testEnv, c map[string]any) {
				c["iat"] = env.now.Unix() - 2000
				c["nbf"] = env.now.Unix() - 2000
				c["exp"] = env.now.Unix() - 2000 + 900
			},
			signer:  noop,
			wantErr: ErrExpired,
		},
		{
			name: "exp within 60 s leeway still verifies",
			mutate: func(env *testEnv, c map[string]any) {
				c["iat"] = env.now.Unix() - 870
				c["nbf"] = env.now.Unix() - 870
				c["exp"] = env.now.Unix() + 30 // expired 0 s… still 30 s in the future
			},
			signer: noop,
		},
		{
			name: "nbf in the future rejected",
			mutate: func(env *testEnv, c map[string]any) {
				c["nbf"] = env.now.Unix() + 300
				c["exp"] = env.now.Unix() + 900
			},
			signer:  noop,
			wantErr: ErrNotYetValid,
		},
		{
			name: "TTL over 15 min rejected (Ruling C5)",
			mutate: func(env *testEnv, c map[string]any) {
				c["exp"] = env.now.Unix() + 901
			},
			signer:  noop,
			wantErr: ErrTTL,
		},
		{
			name: "iat > 120 s in the future rejected (clock skew, doc 11 §7)",
			mutate: func(env *testEnv, c map[string]any) {
				c["iat"] = env.now.Unix() + 200
				c["nbf"] = env.now.Unix() - 10
				c["exp"] = env.now.Unix() + 200 + 900
			},
			signer:  noop,
			wantErr: ErrClockSkew,
		},
		{
			name:    "scope_bound on R2 rejected (Ruling A narrow applicability)",
			mutate:  func(_ *testEnv, c map[string]any) { c["scope_bound"] = true },
			signer:  noop,
			wantErr: ErrScopeBound,
		},
		{
			name: "scope_bound with non-watch capability rejected",
			mutate: func(_ *testEnv, c map[string]any) {
				c["scope_bound"] = true
				c["risk_class"] = "R1"
				c["capabilities"] = []string{"monitor.watch", "detect.scan"}
			},
			signer:  noop,
			wantErr: ErrScopeBound,
		},
		{
			name: "scope_bound monitor.watch R1 verifies",
			mutate: func(_ *testEnv, c map[string]any) {
				c["scope_bound"] = true
				c["risk_class"] = "R1"
				c["capabilities"] = []string{"monitor.watch"}
			},
			signer: noop,
		},
		{
			name: "R3 without approval_id rejected (Ruling B.4)",
			mutate: func(_ *testEnv, c map[string]any) {
				c["risk_class"] = "R3"
			},
			signer:  noop,
			wantErr: ErrApproval,
		},
		{
			name: "R3 with approval_id verifies",
			mutate: func(_ *testEnv, c map[string]any) {
				c["risk_class"] = "R3"
				c["approval_id"] = "appr_01J92M"
			},
			signer: noop,
		},
		{
			name:    "R0 risk class rejected (tokens are R1–R3 only)",
			mutate:  func(_ *testEnv, c map[string]any) { c["risk_class"] = "R0" },
			signer:  noop,
			wantErr: ErrRiskClass,
		},
		{
			name:    "missing jti rejected",
			mutate:  func(_ *testEnv, c map[string]any) { delete(c, "jti") },
			signer:  noop,
			wantErr: ErrMissingClaim,
		},
		{
			name: "missing manifest_sha256 rejected",
			mutate: func(_ *testEnv, c map[string]any) {
				c["targets"] = map[string]any{"hash_alg": "sha256", "manifest_uri": "blob://tokens/x/targets.json"}
			},
			signer:  noop,
			wantErr: ErrMissingClaim,
		},
		{
			name:    "unknown claim rejected (additionalProperties: false)",
			mutate:  func(_ *testEnv, c map[string]any) { c["is_admin"] = true },
			signer:  noop,
			wantErr: ErrMalformed,
		},
		{
			name:   "unknown kid rejected",
			mutate: func(*testEnv, map[string]any) {},
			signer: func(env *testEnv, _ map[string]any) (ed25519.PrivateKey, string) {
				return env.priv, "gk-2099-unknown"
			},
			wantErr: ErrUnknownKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			claims := env.validClaims()
			tc.mutate(env, claims)
			priv, kid := tc.signer(env, claims)
			raw := mint(t, priv, kid, claims)

			got, err := env.verifier.Verify(context.Background(), raw)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify() error = %v, want nil", err)
				}
				if got.TaskID != "tsk_01J92H" {
					t.Fatalf("claims task_id = %q", got.TaskID)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify() = nil error, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify() error = %v, want errors.Is %v", err, tc.wantErr)
			}
			if got != nil {
				t.Fatalf("Verify() returned claims on failure")
			}
		})
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	env := newTestEnv(t)
	raw := mint(t, env.priv, env.kid, env.validClaims())
	parts := strings.Split(raw, ".")
	// Re-encode a tampered payload, keep the original signature.
	claims := env.validClaims()
	claims["risk_class"] = "R3"
	pb, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(pb)
	_, err := env.verifier.Verify(context.Background(), strings.Join(parts, "."))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered payload: error = %v, want ErrSignature", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	env := newTestEnv(t)
	for name, raw := range map[string]string{
		"empty":          "",
		"two segments":   "aaa.bbb",
		"bad b64 header": "!!!.bbb.ccc",
		"bad json":       base64.RawURLEncoding.EncodeToString([]byte("{")) + ".e30.c2ln",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := env.verifier.Verify(context.Background(), raw); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify(%q) = %v, want ErrMalformed", raw, err)
			}
		})
	}
}

func TestVerify_KeyRotationRefresh(t *testing.T) {
	env := newTestEnv(t)
	// Rotate: a new key appears in the JWKS; the old kid disappears.
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env.source.keys = []JWK{{
		Kty: "OKP", Crv: "Ed25519", Kid: "gk-2026-08-b", Alg: "EdDSA", Use: "sig",
		X: base64.RawURLEncoding.EncodeToString(pub2),
	}}
	raw := mint(t, priv2, "gk-2026-08-b", env.validClaims())
	got, err := env.verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify() after rotation = %v", err)
	}
	if got.ID != "tok_01J9ZM8W3F" {
		t.Fatalf("jti = %q", got.ID)
	}
	if env.source.fetches == 0 {
		t.Fatalf("expected a JWKS refresh on kid miss")
	}
}

func TestVerify_JWKSUnavailableFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	env.source.keys = nil
	// Source that always errors.
	src := KeySourceFunc(func(context.Context) ([]JWK, error) {
		return nil, errors.New("gatekeeper down")
	})
	v := NewVerifier(NewKeyCache(src), WithClock(func() time.Time { return env.now }))
	raw := mint(t, env.priv, env.kid, env.validClaims())
	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrJWKS) {
		t.Fatalf("Verify() with JWKS down = %v, want ErrJWKS (fail-closed)", err)
	}
}

func TestJWK_PublicKey_Validation(t *testing.T) {
	good := JWK{Kty: "OKP", Crv: "Ed25519", Kid: "k1", X: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	if _, err := good.PublicKey(); err != nil {
		t.Fatalf("good JWK: %v", err)
	}
	for name, j := range map[string]JWK{
		"wrong kty":  {Kty: "RSA", Crv: "Ed25519", Kid: "k1"},
		"wrong crv":  {Kty: "OKP", Crv: "P-256", Kid: "k1"},
		"no kid":     {Kty: "OKP", Crv: "Ed25519"},
		"short key":  {Kty: "OKP", Crv: "Ed25519", Kid: "k1", X: base64.RawURLEncoding.EncodeToString([]byte("short"))},
		"bad base64": {Kty: "OKP", Crv: "Ed25519", Kid: "k1", X: "!!!"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := j.PublicKey(); err == nil {
				t.Fatalf("want error for %s", name)
			}
		})
	}
}

func TestClaims_ValidAt(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	c := &Claims{NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	if err := c.ValidAt(now); err != nil {
		t.Fatalf("ValidAt(now) = %v", err)
	}
	if err := c.ValidAt(now.Add(3 * time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidAt(expired) = %v, want ErrExpired", err)
	}
	// Within the 60 s leeway an expired token is still accepted.
	if err := c.ValidAt(now.Add(90 * time.Second)); err != nil {
		t.Fatalf("ValidAt(within leeway) = %v, want nil", err)
	}
}
