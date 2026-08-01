// Package jsonx provides JCS (RFC 8785) canonical JSON serialization.
// RoE signatures, audit hash chains, and scope-manifest hashes are all
// computed over JCS-canonical bytes (doc 01 §10.2, doc 11 §3.4, Ruling A.3).
package jsonx

import (
	"encoding/json"
	"fmt"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonical marshals v to JSON and returns its JCS (RFC 8785) canonical form.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jsonx: marshal: %w", err)
	}
	canon, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jsonx: canonicalize: %w", err)
	}
	return canon, nil
}

// CanonicalRaw canonicalizes already-encoded JSON.
func CanonicalRaw(raw []byte) ([]byte, error) {
	canon, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jsonx: canonicalize: %w", err)
	}
	return canon, nil
}
