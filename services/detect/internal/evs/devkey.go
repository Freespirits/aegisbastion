package evs

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// devPublicKeyHex is the LOCAL-DEV-ONLY pack verification key (doc 00 §5 Q1
// MVP-A file-key posture; production deployments set DETECT_EVS_POC_PUBLIC_KEY
// to the platform pack-signing key). The matching private key ships in
// devkey_test.go for pack-authoring tests and must never sign production
// packs.
const devPublicKeyHex = "0d684b856e2cc0e3540cd58f11383cc2384b4b9695feea353770ea176ae2a259"

// PackVerificationKey resolves the Ed25519 public key for PoC pack
// signature verification: the configured hex key when present, else the
// embedded dev key (local dev only — logged by main).
func PackVerificationKey(configuredHex string) (ed25519.PublicKey, bool, error) {
	hexKey := configuredHex
	dev := false
	if hexKey == "" {
		hexKey = devPublicKeyHex
		dev = true
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, dev, fmt.Errorf("evs: invalid pack public key (want %d-byte hex)", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), dev, nil
}
