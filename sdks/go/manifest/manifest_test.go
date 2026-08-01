package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func staticFetcher(files map[string][]byte) Fetcher {
	return FetcherFunc(func(_ context.Context, uri string) ([]byte, error) {
		b, ok := files[uri]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrFetch, uri)
		}
		return b, nil
	})
}

func ref(uri string, body []byte, count uint32) token.TargetManifestRef {
	return token.TargetManifestRef{
		HashAlg:        "sha256",
		ManifestURI:    uri,
		ManifestSHA256: sha256Hex(body),
		Count:          count,
	}
}

func TestMapURI(t *testing.T) {
	cases := []struct {
		uri, override, wantBucket, wantKey string
		wantErr                            bool
	}{
		{uri: "blob://tokens/tok_1/targets.json", wantBucket: DefaultBucket, wantKey: "tok_1/targets.json"},
		{uri: "blob://tokens/tok_1/scope.json", override: "token-manifests", wantBucket: "token-manifests", wantKey: "tok_1/scope.json"},
		{uri: "blob://other-bucket/x/y.json", wantBucket: "other-bucket", wantKey: "x/y.json"},
		{uri: "s3://bucket/key.json", wantBucket: "bucket", wantKey: "key.json"},
		{uri: "blob://tokens/tok_1/targets.json", override: "pinned", wantBucket: "pinned", wantKey: "tok_1/targets.json"},
		{uri: "http://evil.example/x", wantErr: true},
		{uri: "blob://nokey", wantErr: true},
		{uri: "blob://bucket/", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.uri+"/"+tc.override, func(t *testing.T) {
			b, k, err := MapURI(tc.uri, tc.override)
			if tc.wantErr {
				if !errors.Is(err, ErrURI) {
					t.Fatalf("MapURI = %v, want ErrURI", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("MapURI error = %v", err)
			}
			if b != tc.wantBucket || k != tc.wantKey {
				t.Fatalf("MapURI = (%q,%q), want (%q,%q)", b, k, tc.wantBucket, tc.wantKey)
			}
		})
	}
}

func TestLoad_ExactEnumerated(t *testing.T) {
	uri := "blob://tokens/tok_1/targets.json"
	arrayForm := []byte(`["API.Acme.COM", "https://api.acme.com/graphql", "203.0.113.10"]`)
	objectForm := []byte(`{"targets": ["acme.com"]}`)

	cases := []struct {
		name        string
		body        []byte
		count       uint32
		mutateHash  bool
		wantErr     error
		wantMembers []string
		wantNot     []string
	}{
		{
			name:        "bare array form, canonicalized membership",
			body:        arrayForm,
			count:       3,
			wantMembers: []string{"api.acme.com", "https://api.acme.com/graphql", "203.0.113.10", "API.ACME.COM"},
			wantNot:     []string{"evil.acme.com", "203.0.113.11"},
		},
		{
			name:        "object form",
			body:        objectForm,
			count:       1,
			wantMembers: []string{"acme.com"},
			wantNot:     []string{"www.acme.com"},
		},
		{
			name:    "count claim mismatch",
			body:    arrayForm,
			count:   2,
			wantErr: ErrCount,
		},
		{
			name:       "hash mismatch (tampered manifest)",
			body:       arrayForm,
			count:      3,
			mutateHash: true,
			wantErr:    ErrHash,
		},
		{
			name:    "garbage bytes",
			body:    []byte("not json at all"),
			wantErr: ErrParse,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ref(uri, tc.body, tc.count)
			if tc.mutateHash {
				r.ManifestSHA256 = sha256Hex([]byte("different content"))
			}
			m, err := Load(context.Background(), staticFetcher(map[string][]byte{uri: tc.body}), r, false)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load() = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if m.ScopeBound() {
				t.Fatalf("exact form reported scope-bound")
			}
			for _, w := range tc.wantMembers {
				if !m.Contains(w) {
					t.Errorf("Contains(%q) = false, want true", w)
				}
			}
			for _, w := range tc.wantNot {
				if m.Contains(w) {
					t.Errorf("Contains(%q) = true, want false", w)
				}
			}
		})
	}
}

func TestLoad_ScopeBound(t *testing.T) {
	uri := "blob://tokens/tok_2/scope.json"
	doc := []byte(`{"roe_id":"roe_01J8ZM","roe_version":3,"resolved_at":"2026-07-30T07:00:00Z",` +
		`"scope":{"domains":["acme.com","*.acme.com"],"cidrs":["203.0.113.0/24"],` +
		`"explicit_excludes":["status.acme.com"]}}`)

	m, err := Load(context.Background(), staticFetcher(map[string][]byte{uri: doc}), ref(uri, doc, 0), true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !m.ScopeBound() {
		t.Fatalf("scope-bound form not detected")
	}
	if m.ScopeManifest.ROEID != "roe_01J8ZM" || m.ScopeManifest.ROEVersion != 3 {
		t.Fatalf("scope manifest header = %+v", m.ScopeManifest)
	}
	// The manifest hash IS the scope:sha256 audit value (Ruling A.3).
	wantAudit := "scope:sha256:" + sha256Hex(doc)
	if got := m.ScopeAuditValue(); got != wantAudit {
		t.Fatalf("ScopeAuditValue = %q, want %q", got, wantAudit)
	}
	// Scope evaluation flows through, exclusions win.
	if d := m.EvaluateScope("api.acme.com"); !d.Allowed {
		t.Errorf("api.acme.com denied: %s", d.Reason)
	}
	if d := m.EvaluateScope("status.acme.com"); d.Allowed || !d.Excluded {
		t.Errorf("status.acme.com = %+v, want excluded", d)
	}
	if d := m.EvaluateScope("evil.example.com"); d.Allowed {
		t.Errorf("evil.example.com allowed, want deny")
	}
	// Unknown fields rejected (additionalProperties: false).
	bad := []byte(`{"roe_id":"roe_x","roe_version":1,"scope":{"domains":[],"cidrs":[],"explicit_excludes":[]},"backdoor":true}`)
	if _, err := Load(context.Background(), staticFetcher(map[string][]byte{uri: bad}), ref(uri, bad, 0), true); !errors.Is(err, ErrParse) {
		t.Fatalf("unknown field: err = %v, want ErrParse", err)
	}
}

func TestLoad_FetchFailureFailsClosed(t *testing.T) {
	uri := "blob://tokens/tok_9/targets.json"
	_, err := Load(context.Background(), staticFetcher(nil), ref(uri, []byte("[]"), 0), false)
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("Load() = %v, want ErrFetch (fail-closed)", err)
	}
}
