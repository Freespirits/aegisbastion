package token

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
)

func testKey(t *testing.T) *keys.Keypair {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func baseClaims() *claimsJSON {
	now := time.Now().Unix()
	return &claimsJSON{
		Iss: "gatekeeper.platform", Aud: "aegisbastion.modules",
		Jti: "tok_01JTEST", Sub: "agent_01J", TaskID: "task_01J",
		RoeID: "roe_01J", RoeVersion: 3, RiskClass: "R2",
		Capabilities: []string{"stress.http_flood"},
		Targets: manifestRefJSON{
			HashAlg: "sha256", ManifestURI: "blob://tokens/tok_01JTEST/targets.json",
			ManifestSHA256: strings.Repeat("a", 64), Count: 1,
		},
		ScopeBound: false,
		RateCaps:   &rateCapsJSON{MaxRPS: 5000, MaxConcurrent: 2},
		Iat:        now, Nbf: now, Exp: now + 900,
	}
}

func resolverFor(kp *keys.Keypair) KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		if kid != kp.KID {
			return nil, errUnknownKID
		}
		return kp.Public(), nil
	}
}

var errUnknownKID = errString("unknown kid")

type errString string

func (e errString) Error() string { return string(e) }

func verifyOpts() VerifyOptions {
	return VerifyOptions{Issuer: "gatekeeper.platform", Audience: "aegisbastion.modules", RequireExp: true}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kp := testKey(t)
	raw, err := signJWT(kp.KID, kp.Private(), baseClaims())
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Verify(raw, resolverFor(kp), verifyOpts())
	if err != nil {
		t.Fatal(err)
	}
	c := pt.Claims
	if c.Jti != "tok_01JTEST" || c.TaskID != "task_01J" || c.RiskClass != "R2" ||
		c.Targets.ManifestSHA256 != strings.Repeat("a", 64) || c.RateCaps.MaxRPS != 5000 {
		t.Fatalf("claims mangled: %+v", c)
	}
	if pt.Kid != kp.KID {
		t.Fatalf("kid mismatch: %s", pt.Kid)
	}
}

func TestVerifyRejects(t *testing.T) {
	kp := testKey(t)
	other := testKey(t)
	raw, err := signJWT(kp.KID, kp.Private(), baseClaims())
	if err != nil {
		t.Fatal(err)
	}

	// Wrong key / unknown kid.
	if _, err := Verify(raw, resolverFor(other), verifyOpts()); err == nil {
		t.Error("unknown kid must fail")
	}
	// Tampered payload.
	parts := strings.Split(raw, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "xx." + parts[2]
	if _, err := Verify(tampered, resolverFor(kp), verifyOpts()); err == nil {
		t.Error("tampered payload must fail")
	}
	// Bad audience.
	bad := baseClaims()
	bad.Aud = "someone.else"
	rawBad, _ := signJWT(kp.KID, kp.Private(), bad)
	if _, err := Verify(rawBad, resolverFor(kp), verifyOpts()); err == nil {
		t.Error("wrong audience must fail")
	}
	// Expired.
	expired := baseClaims()
	expired.Iat -= 3600
	expired.Nbf -= 3600
	expired.Exp = expired.Iat + 900
	rawExp, _ := signJWT(kp.KID, kp.Private(), expired)
	if _, err := Verify(rawExp, resolverFor(kp), verifyOpts()); err == nil {
		t.Error("expired token must fail")
	}
	// TTL > 15 min must fail even when otherwise valid.
	long := baseClaims()
	long.Exp = long.Iat + 3600
	rawLong, _ := signJWT(kp.KID, kp.Private(), long)
	if _, err := Verify(rawLong, resolverFor(kp), verifyOpts()); err == nil {
		t.Error("TTL > 900s must fail (Ruling C5)")
	}
	// Far-future iat (clock skew / replay) must fail.
	skewed := baseClaims()
	skewed.Iat += 3600
	skewed.Nbf = skewed.Iat
	skewed.Exp = skewed.Iat + 900
	rawSkew, _ := signJWT(kp.KID, kp.Private(), skewed)
	if _, err := Verify(rawSkew, resolverFor(kp), verifyOpts()); err == nil {
		t.Error("iat > 120s in the future must fail (doc 11 §7)")
	}
}

func TestScopeBoundClaimsRoundTrip(t *testing.T) {
	kp := testKey(t)
	c := baseClaims()
	c.RiskClass = "R1"
	c.Capabilities = []string{"monitor.watch"}
	c.ScopeBound = true
	c.Targets.Count = 0
	c.Targets.ManifestURI = "blob://tokens/tok_01JTEST/scope.json"
	raw, err := signJWT(kp.KID, kp.Private(), c)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Verify(raw, resolverFor(kp), verifyOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !pt.Claims.ScopeBound || pt.Claims.RiskClass != "R1" {
		t.Fatalf("scope-bound claims lost: %+v", pt.Claims)
	}
}
