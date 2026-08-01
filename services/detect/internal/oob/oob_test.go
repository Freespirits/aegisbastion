package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMintAndLookupInProcess(t *testing.T) {
	svc := New("http://oob.test", time.Hour, nil)
	c := svc.Mint("ssrf:test")
	if c.Token == "" || !strings.Contains(c.URL, "/c/"+c.Token) {
		t.Fatalf("bad canary: %+v", c)
	}
	if got := svc.Lookup(c.Token); len(got) != 0 {
		t.Fatalf("fresh canary should have no interactions, got %d", len(got))
	}
}

func TestHTTPCallbackRoundTrip(t *testing.T) {
	svc := New("http://127.0.0.1:0", time.Hour, nil)
	addr, err := svc.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer svc.Shutdown(context.Background())

	// Mint via API.
	resp, err := http.Post("http://"+addr+"/v1/canaries", "application/json",
		strings.NewReader(`{"purpose":"test-blind-rce"}`))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	var canary Canary
	decodeJSON(t, resp, &canary)

	// Hit the callback URL (blind-vuln simulation).
	cb, err := http.Post("http://"+addr+"/c/"+canary.Token, "text/plain",
		strings.NewReader("blind-rce-marker"))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cb.Body.Close()

	// Lookup via API.
	lr, err := http.Get("http://" + addr + "/v1/interactions?token=" + canary.Token)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	var out struct {
		Interactions []Interaction `json:"interactions"`
	}
	decodeJSON(t, lr, &out)
	if len(out.Interactions) != 1 {
		t.Fatalf("got %d interactions, want 1", len(out.Interactions))
	}
	hit := out.Interactions[0]
	if hit.Method != "POST" || hit.BodySHA256 == "" {
		t.Fatalf("bad interaction: %+v", hit)
	}

	// In-process client sees the same interaction.
	cl := NewClient(svc)
	its, err := cl.Interactions(context.Background(), canary.Token)
	if err != nil || len(its) != 1 {
		t.Fatalf("client interactions: %v %d", err, len(its))
	}
}

func TestUnknownTokenRecordedButFlagged(t *testing.T) {
	svc := New("http://127.0.0.1:0", time.Hour, nil)
	addr, err := svc.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer svc.Shutdown(context.Background())
	resp, err := http.Get("http://" + addr + "/c/s48unknown")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()
	if got := svc.Lookup("s48unknown"); len(got) != 1 {
		t.Fatalf("unknown-token interaction must be recorded, got %d", len(got))
	}
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode >= 300 {
		t.Fatalf("status %d: %s", resp.StatusCode, data)
	}
	if err := jsonUnmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

var _ = fmt.Sprint
