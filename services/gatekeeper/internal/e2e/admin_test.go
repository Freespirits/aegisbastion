package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/admin"
)

// TestAdminHTTPSurface checks health + JWKS endpoints over httptest.
func TestAdminHTTPSurface(t *testing.T) {
	e := newEnv(t)
	srv := admin.NewServer(admin.Deps{
		Key: e.key, DB: e.db, ROE: e.roe, Approval: e.approval, Revoke: e.revoke,
		RBAC: e.rbac, Audit: e.audit,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// healthz
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}

	// JWKS (doc 11 §3.2 path).
	resp, err = http.Get(ts.URL + "/.well-known/gatekeeper-jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: %d", resp.StatusCode)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0]["kty"] != "OKP" || doc.Keys[0]["kid"] != e.key.KID {
		t.Fatalf("bad JWKS: %+v", doc.Keys)
	}

	// RoE list needs org_id.
	resp, err = http.Get(ts.URL + "/v1/roe")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("roe list without org_id must 400, got %d", resp.StatusCode)
	}
}
