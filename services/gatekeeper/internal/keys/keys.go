// Package keys implements MVP-A Ed25519 signing-key custody for gatekeeper
// (doc 00 §5 Q1 ruling: sealed file key, zero cloud dependency; Azure Key
// Vault lands at MVP-B). The key file is JSON; with
// GATEKEEPER_SIGNING_KEY_PASSPHRASE set, the private key is sealed at rest
// with AES-256-GCM under a scrypt-derived key. kid rotation (two active keys
// max, 30-day rotation, JWKS overlap) is a MVP-B item — MVP-A runs one key.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// Keypair is the active signing key.
type Keypair struct {
	KID string
	pvt ed25519.PrivateKey
	pub ed25519.PublicKey
}

// fileDoc is the on-disk key format.
type fileDoc struct {
	KID    string `json:"kid"`
	Sealed bool   `json:"sealed"`
	Key    string `json:"key"`            // base64 raw seed (Sealed=false) or base64 ciphertext (Sealed=true)
	Salt   string `json:"salt,omitempty"` // base64 scrypt salt (Sealed)
	Nonce  string `json:"nonce,omitempty"`
}

// LoadOrCreate loads the signing key from path, generating and persisting a
// fresh keypair when the file does not exist. Passphrase "" stores the raw
// seed (file-permission protected); non-empty seals it at rest.
func LoadOrCreate(path, passphrase string) (*Keypair, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parse(raw, passphrase)
	case errors.Is(err, os.ErrNotExist):
		kp, err := Generate()
		if err != nil {
			return nil, err
		}
		if err := kp.Save(path, passphrase); err != nil {
			return nil, err
		}
		return kp, nil
	default:
		return nil, fmt.Errorf("keys: read %s: %w", path, err)
	}
}

// Generate creates a fresh Ed25519 keypair with a derived kid
// ("gk-" + first 8 hex chars of sha256(pubkey)).
func Generate() (*Keypair, error) {
	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generate: %w", err)
	}
	sum := sha256.Sum256(pub)
	return &Keypair{KID: "gk-" + hex.EncodeToString(sum[:])[:8], pvt: pvt, pub: pub}, nil
}

// FromSeed builds a keypair from a 32-byte seed (tests).
func FromSeed(seed []byte) (*Keypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keys: seed must be %d bytes", ed25519.SeedSize)
	}
	pvt := ed25519.NewKeyFromSeed(seed)
	pub := pvt.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Keypair{KID: "gk-" + hex.EncodeToString(sum[:])[:8], pvt: pvt, pub: pub}, nil
}

// Save writes the key file (0600), sealed when passphrase is non-empty.
func (k *Keypair) Save(path, passphrase string) error {
	seed := k.pvt.Seed()
	doc := fileDoc{KID: k.KID}
	if passphrase == "" {
		doc.Key = base64.StdEncoding.EncodeToString(seed)
	} else {
		sealed, salt, nonce, err := seal(seed, passphrase)
		if err != nil {
			return err
		}
		doc.Sealed = true
		doc.Key = base64.StdEncoding.EncodeToString(sealed)
		doc.Salt = base64.StdEncoding.EncodeToString(salt)
		doc.Nonce = base64.StdEncoding.EncodeToString(nonce)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("keys: mkdir %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("keys: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("keys: rename to %s: %w", path, err)
	}
	return nil
}

func parse(raw []byte, passphrase string) (*Keypair, error) {
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("keys: parse key file: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(doc.Key)
	if err != nil {
		return nil, fmt.Errorf("keys: decode key: %w", err)
	}
	var seed []byte
	if doc.Sealed {
		if passphrase == "" {
			return nil, fmt.Errorf("keys: key file is sealed; GATEKEEPER_SIGNING_KEY_PASSPHRASE is required")
		}
		salt, err := base64.StdEncoding.DecodeString(doc.Salt)
		if err != nil {
			return nil, fmt.Errorf("keys: decode salt: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(doc.Nonce)
		if err != nil {
			return nil, fmt.Errorf("keys: decode nonce: %w", err)
		}
		seed, err = unseal(blob, passphrase, salt, nonce)
		if err != nil {
			return nil, err
		}
	} else {
		seed = blob
	}
	kp, err := FromSeed(seed)
	if err != nil {
		return nil, err
	}
	if doc.KID != "" && doc.KID != kp.KID {
		return nil, fmt.Errorf("keys: kid mismatch: file says %s, key derives %s", doc.KID, kp.KID)
	}
	return kp, nil
}

func seal(seed []byte, passphrase string) (ciphertext, salt, nonce []byte, err error) {
	salt = make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keys: scrypt: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	return gcm.Seal(nil, nonce, seed, nil), salt, nonce, nil
}

func unseal(ciphertext []byte, passphrase string, salt, nonce []byte) ([]byte, error) {
	dk, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("keys: scrypt: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keys: unseal failed (wrong passphrase?)")
	}
	return seed, nil
}

// Sign produces an Ed25519 signature over msg.
func (k *Keypair) Sign(msg []byte) []byte { return ed25519.Sign(k.pvt, msg) }

// Public returns the raw public key.
func (k *Keypair) Public() ed25519.PublicKey { return k.pub }

// Private returns the raw private key (signing only; never leaves the process).
func (k *Keypair) Private() ed25519.PrivateKey { return k.pvt }

// Verify checks a signature against this keypair's public key.
func (k *Keypair) Verify(msg, sig []byte) bool { return ed25519.Verify(k.pub, msg, sig) }

// JWK renders the public key in RFC 8037 JWK form for the JWKS endpoint.
func (k *Keypair) JWK() map[string]string {
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": k.KID,
		"alg": "EdDSA",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(k.pub),
	}
}
