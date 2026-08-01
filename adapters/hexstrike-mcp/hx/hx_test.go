package hx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The mock is the default runtime mode: it must be deterministic and must
// mark its output so a canned result can never pass for a real scan.
func TestMockDeterministic(t *testing.T) {
	m := NewMockClient()
	args := map[string]any{"target": "acme.com", "scan_type": "-sV"}
	a, err := m.CallTool(context.Background(), "api/tools/nmap", args)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	b, err := m.CallTool(context.Background(), "api/tools/nmap", args)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("mock not deterministic:\nA: %s\nB: %s", ja, jb)
	}
	if a["mock"] != true {
		t.Error("mock result must carry mock: true")
	}
	if a["success"] != true {
		t.Error("mock result should succeed")
	}
	if err := m.Health(context.Background()); err != nil {
		t.Errorf("mock health: %v", err)
	}
	if m.Mode() != "mock" {
		t.Errorf("mode = %q", m.Mode())
	}
}

func TestMockEmptyEndpointRefused(t *testing.T) {
	if _, err := NewMockClient().CallTool(context.Background(), "", nil); err == nil {
		t.Error("empty endpoint must be refused")
	}
}

// The HTTP client speaks to hexstrike_server.py: POST {base}/api/tools/<tool>
// with the args as JSON; non-200 is an error carrying the status.
func TestHTTPClientRoundTrip(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"stdout":"scan done"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if c.Mode() != "http" {
		t.Errorf("mode = %q", c.Mode())
	}
	if err := c.Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
	res, err := c.CallTool(context.Background(), "api/tools/nmap", map[string]any{"target": "acme.com"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if gotPath != "/api/tools/nmap" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody != `{"target":"acme.com"}` {
		t.Errorf("body = %q", gotBody)
	}
	if res["success"] != true {
		t.Errorf("result = %v", res)
	}
}

func TestHTTPClientFailureStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"tool exploded"}`))
	}))
	defer srv.Close()

	c, _ := NewHTTPClient(srv.URL)
	if err := c.Health(context.Background()); err == nil {
		t.Error("unhealthy server must fail the health check")
	}
	if _, err := c.CallTool(context.Background(), "api/tools/nmap", nil); err == nil {
		t.Error("non-200 tool response must be an error")
	}
}

func TestHTTPClientURLValidation(t *testing.T) {
	if _, err := NewHTTPClient(""); err == nil {
		t.Error("empty URL must fail")
	}
	if _, err := NewHTTPClient("127.0.0.1:8888"); err == nil {
		t.Error("scheme-less URL must fail")
	}
	if _, err := NewHTTPClient("http://127.0.0.1:8888/"); err != nil {
		t.Errorf("trailing slash should be normalized: %v", err)
	}
}
