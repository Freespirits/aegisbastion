package evs

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
)

// Safety classes (doc 04 §7.1). MVP ships non_destructive only;
// state_changing is post-MVP behind RoE opt-in + safe_mode:false.
const (
	SafetyNonDestructive = "non_destructive"
	SafetyStateChanging  = "state_changing"
)

// Pack is one curated PoC pack ("poc-pack:{id}:{version}", doc 04 §7.1): a
// signed bundle with a manifest (target classes, safety class, OOB
// requirement) and a deterministic verifier program. No agentic/LLM-driven
// exploitation — that is module 08's job.
type Pack struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Safety        string   `json:"safety"`
	TargetClasses []string `json:"target_classes"`
	RequiresOOB   bool     `json:"requires_oob"`
	Program       Program  `json:"program"`
}

// signedPack is the on-disk/wire form: the manifest plus its detached
// Ed25519 signature over the JCS-canonical manifest (doc 01 §10.2).
type signedPack struct {
	Pack
	Signature string `json:"signature"`
}

// ErrPackSignature marks a signature verification failure — a compromised or
// forged pack is never executed (doc 04 §12: pack signature re-verified on
// any sandbox-compromise signal).
var ErrPackSignature = errors.New("evs: PoC pack signature invalid")

// ErrSafetyClass marks a pack whose safety class is not runnable here.
var ErrSafetyClass = errors.New("evs: PoC pack safety class not permitted")

// LoadPack parses and verifies a signed pack against pub. The signature
// covers the JCS-canonical manifest (everything except the signature field).
func LoadPack(data []byte, pub ed25519.PublicKey) (*Pack, error) {
	var sp signedPack
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("evs: pack decode: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sp.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature not base64", ErrPackSignature)
	}
	signed, err := json.Marshal(sp.Pack)
	if err != nil {
		return nil, err
	}
	canon, err := audit.CanonicalizeJSON(signed)
	if err != nil {
		return nil, fmt.Errorf("evs: pack canonicalize: %w", err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		return nil, ErrPackSignature
	}
	p := sp.Pack
	if p.ID == "" || p.Version == "" {
		return nil, errors.New("evs: pack manifest missing id/version")
	}
	if len(p.Program.Steps) == 0 {
		return nil, errors.New("evs: pack has an empty program")
	}
	return &p, nil
}

// SignPack renders the signed wire form of p (pack authoring / tests).
func SignPack(p *Pack, priv ed25519.PrivateKey) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	canon, err := audit.CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	sp := signedPack{Pack: *p, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))}
	return json.Marshal(sp)
}

// CheckSafety enforces the MVP safety-class policy (doc 04 §7.1): only
// non_destructive packs run; state_changing requires RoE opt-in surfaced as
// safeMode=false (post-MVP — refused here regardless at MVP).
func CheckSafety(p *Pack, safeMode bool) error {
	switch p.Safety {
	case SafetyNonDestructive:
		return nil
	case SafetyStateChanging:
		return fmt.Errorf("%w: state_changing packs are post-MVP (safe_mode=%v)", ErrSafetyClass, safeMode)
	default:
		return fmt.Errorf("%w: unknown safety class %q", ErrSafetyClass, p.Safety)
	}
}

// ForClass picks the first pack covering a vuln class (pack order = curation
// priority).
func ForClass(packs []*Pack, class string) *Pack {
	for _, p := range packs {
		for _, c := range p.TargetClasses {
			if c == class {
				return p
			}
		}
	}
	return nil
}
