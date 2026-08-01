package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRoundTripUnsealed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gk.key")
	kp, err := LoadOrCreate(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if kp.KID == "" || len(kp.KID) < 4 || kp.KID[:3] != "gk-" {
		t.Fatalf("bad kid %q", kp.KID)
	}
	// Second load returns the same key.
	kp2, err := LoadOrCreate(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if kp2.KID != kp.KID {
		t.Fatalf("kid changed across loads: %s vs %s", kp.KID, kp2.KID)
	}
	// Sign/verify round trip.
	msg := []byte("aegisbastion")
	if !kp2.Verify(msg, kp.Sign(msg)) {
		t.Fatal("signature did not verify after reload")
	}
	if runtime.GOOS != "windows" { // Windows ACLs don't map 0600
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("key file permissions too open: %v", info.Mode().Perm())
		}
	}
}

func TestSealedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gk.key")
	kp, err := LoadOrCreate(path, "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"sealed":true`) && !strings.Contains(string(raw), `"sealed": true`) {
		t.Fatal("expected sealed key file")
	}
	if _, err := LoadOrCreate(path, ""); err == nil {
		t.Fatal("sealed key must require a passphrase")
	}
	if _, err := LoadOrCreate(path, "wrong-pass"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	kp2, err := LoadOrCreate(path, "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if kp2.KID != kp.KID {
		t.Fatal("sealed reload returned a different key")
	}
}

func TestJWKShape(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	jwk := kp.JWK()
	for _, k := range []string{"kty", "crv", "kid", "alg", "use", "x"} {
		if jwk[k] == "" {
			t.Errorf("JWK missing %s", k)
		}
	}
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || jwk["alg"] != "EdDSA" {
		t.Errorf("bad JWK: %v", jwk)
	}
}
