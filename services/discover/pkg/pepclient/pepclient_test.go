package pepclient

// PEP wrapper test matrix (doc 02 §9): expired Scope Token, seed outside the
// token manifest, revoked RoE, gatekeeper (JWKS) unreachable ⇒ fail closed,
// R1+ task without a token, forged signature. The module mints nothing —
// tokens here are minted by the TEST (playing gatekeeper) purely to exercise
// the re-verification path.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

const testKid = "gk-key-1"

// testKeyring mints EdDSA Scope Tokens and serves the matching JWKS.
type testKeyring struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	srv  *httptest.Server
}

func newTestKeyring(t *testing.T) *testKeyring {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &testKeyring{priv: priv, pub: pub}
	kr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"keys": []map[string]any{{
			"kty": "OKP", "crv": "Ed25519", "kid": testKid,
			"alg": "EdDSA", "use": "sig",
			"x": base64.RawURLEncoding.EncodeToString(pub),
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(kr.srv.Close)
	return kr
}

// exactManifest builds an exact-enumerated manifest + its claim ref fields.
func exactManifest(targets ...string) (raw []byte, sha256Hex string, count uint32) {
	raw, _ = json.Marshal(targets)
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), uint32(len(targets))
}

func (kr *testKeyring) mint(t *testing.T, mutate func(c *token.Claims)) string {
	t.Helper()
	manRaw, manHash, manCount := exactManifest("example.com")
	_ = manRaw
	now := time.Now().UTC()
	claims := token.Claims{
		Issuer:       token.Issuer,
		Audience:     token.Audience,
		ID:           "tok_test1",
		Subject:      "discover-worker",
		TaskID:       "task-1",
		ROEID:        "roe_1",
		ROEVersion:   1,
		RiskClass:    "R1",
		Capabilities: []string{"discover.active.subdomain"},
		Targets: token.TargetManifestRef{
			HashAlg:        "sha256",
			ManifestURI:    "blob://tokens/tok_test1/targets.json",
			ManifestSHA256: manHash,
			Count:          manCount,
		},
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(&claims)
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": testKid})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(kr.priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newClient wires a Client around the test JWKS + a manifest fetcher serving
// the exact-enumerated manifest ["example.com"].
func (kr *testKeyring) newClient() *Client {
	manRaw, _, _ := exactManifest("example.com")
	fetcher := manifest.FetcherFunc(func(context.Context, string) ([]byte, error) {
		return manRaw, nil
	})
	return &Client{
		verifier:    NewVerifier(kr.srv.URL),
		fetcher:     fetcher,
		Revocations: pep.NewRevocationCache(),
		ActorID:     "discover-test",
		Now:         time.Now,
	}
}

func r1Task(tok string) model.Task {
	return model.Task{
		TaskID:     "task-1",
		OrderID:    "order-1",
		TenantID:   "tenant-1",
		Technique:  model.TechniqueSubdomainActive,
		Source:     "wordlist",
		Seed:       model.Seed{Type: model.SeedDomain, Value: "example.com"},
		ScopeToken: tok,
		ROEID:      "roe_1",
		RiskClass:  "R1",
	}
}

func TestVerifyTaskToken_R0WithoutTokenAllowed(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	task := model.Task{
		TaskID: "task-r0", Technique: model.TechniqueCT,
		Seed:      model.Seed{Type: model.SeedDomain, Value: "example.com"},
		RiskClass: "R0",
	}
	claims, err := c.VerifyTaskToken(context.Background(), task)
	if err != nil {
		t.Fatalf("R0 task without token must be allowed: %v", err)
	}
	if claims != nil {
		t.Error("R0 without token yields no claims")
	}
}

func TestVerifyTaskToken_R1WithoutTokenRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	_, err := c.VerifyTaskToken(context.Background(), r1Task(""))
	if !errors.Is(err, pep.ErrNoAuthorization) {
		t.Fatalf("R1 task without token must refuse (ErrNoAuthorization), got %v", err)
	}
}

func TestVerifyTaskToken_ValidTokenAllowed(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, nil)
	claims, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if claims.TaskID != "task-1" || claims.ID == "" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifyTaskToken_ExpiredRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, func(c *token.Claims) {
		past := time.Now().Add(-30 * time.Minute).Unix()
		c.IssuedAt = past
		c.NotBefore = past
		c.ExpiresAt = past + 600 // exp−iat valid TTL, but expired 20 min ago
	})
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if err == nil {
		t.Fatal("expired token must be refused")
	}
	if !errors.Is(err, token.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyTaskToken_TTLTooLongRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, func(c *token.Claims) {
		c.ExpiresAt = c.IssuedAt + 3600 // > 15 min (Ruling C5)
	})
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if !errors.Is(err, token.ErrTTL) {
		t.Fatalf("TTL > 15 min must refuse (ErrTTL), got %v", err)
	}
}

func TestVerifyTaskToken_TaskBindingRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, func(c *token.Claims) { c.TaskID = "task-OTHER" })
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if !errors.Is(err, pep.ErrTaskBinding) {
		t.Fatalf("task-bound token on another task must refuse, got %v", err)
	}
}

func TestVerifyTaskToken_CapabilityNotGrantedRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, func(c *token.Claims) {
		c.Capabilities = []string{"discover.active.cloud_probe"} // not the task's capability
	})
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if !errors.Is(err, pep.ErrTaskBinding) {
		t.Fatalf("ungranted capability must refuse, got %v", err)
	}
}

func TestVerifyTaskToken_SeedOutsideManifestRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	tok := kr.mint(t, nil)
	task := r1Task(tok)
	task.Seed = model.Seed{Type: model.SeedDomain, Value: "evil.example.org"}
	_, err := c.VerifyTaskToken(context.Background(), task)
	if !errors.Is(err, pep.ErrTargetNotInManifest) {
		t.Fatalf("seed outside manifest must refuse, got %v", err)
	}
}

func TestVerifyTaskToken_ForgedSignatureRefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	// Mint with a DIFFERENT key: the JWKS lookup succeeds, the signature fails.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	forged := &testKeyring{priv: priv}
	tok := forged.mint(t, nil)
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if !errors.Is(err, token.ErrSignature) {
		t.Fatalf("forged token must refuse (ErrSignature), got %v", err)
	}
}

func TestVerifyTaskToken_JWKSUnreachableRefused(t *testing.T) {
	manRaw, _, _ := exactManifest("example.com")
	c := &Client{
		verifier:    NewVerifier("http://127.0.0.1:1/jwks.json"), // nothing listening
		fetcher:     manifest.FetcherFunc(func(context.Context, string) ([]byte, error) { return manRaw, nil }),
		Revocations: pep.NewRevocationCache(),
		Now:         time.Now,
	}
	kr := newTestKeyring(t)
	tok := kr.mint(t, nil)
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if err == nil {
		t.Fatal("unreachable JWKS must fail closed")
	}
}

func TestVerifyTaskToken_RevokedROERefused(t *testing.T) {
	kr := newTestKeyring(t)
	c := kr.newClient()
	c.Revocations.Apply(&gatekeeperv1.Revocation{
		Scope:  gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
		Key:    "roe_1",
		Reason: "test revocation",
	})
	tok := kr.mint(t, nil)
	_, err := c.VerifyTaskToken(context.Background(), r1Task(tok))
	if !errors.Is(err, pep.ErrRevoked) {
		t.Fatalf("revoked RoE must refuse, got %v", err)
	}
}
