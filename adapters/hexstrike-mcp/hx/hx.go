// Package hx is the client side of an operator-installed HexStrike AI backend
// (0x4m4/hexstrike-ai): hexstrike_server.py exposes POST
// {server}/api/tools/<tool> returning JSON with at least a boolean "success"
// field, and GET {server}/health.
//
// The adapter runs in two modes (HEXSTRIKE_MODE):
//
//   - mock (default): a deterministic in-process client that never touches
//     the network — the adapter is fully exercisable without a HexStrike
//     install. Given identical (endpoint, args) it returns byte-identical
//     results.
//   - http: a real client of the HexStrike server, used when the local
//     installation is present.
package hx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client invokes HexStrike tools. Both implementations are safe for
// concurrent use.
type Client interface {
	// CallTool POSTs args to the tool endpoint (e.g. "api/tools/nmap") and
	// returns the decoded JSON object.
	CallTool(ctx context.Context, endpoint string, args map[string]any) (map[string]any, error)
	// Health checks the HexStrike server (mock: always nil).
	Health(ctx context.Context) error
	// Mode reports "mock" or "http" for logs and health output.
	Mode() string
}

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

// MockClient is the default client. Its responses are deterministic: no
// timestamps, no randomness, map keys sorted on marshal — identical inputs
// yield identical JSON. It clearly marks every result with "mock": true so a
// canned result can never be mistaken for real target contact.
type MockClient struct{}

// NewMockClient returns the deterministic mock.
func NewMockClient() *MockClient { return &MockClient{} }

// Mode implements Client.
func (m *MockClient) Mode() string { return "mock" }

// Health implements Client (the mock is always healthy).
func (m *MockClient) Health(context.Context) error { return nil }

// CallTool implements Client.
func (m *MockClient) CallTool(_ context.Context, endpoint string, args map[string]any) (map[string]any, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("hx mock: empty tool endpoint")
	}
	target, _ := args["target"].(string)
	if target == "" {
		target, _ = args["url"].(string)
	}
	return map[string]any{
		"success":  true,
		"mock":     true,
		"endpoint": endpoint,
		"target":   target,
		"args":     args,
		"stdout":   fmt.Sprintf("MOCK %s completed for %s — no target contact was made", endpoint, target),
	}, nil
}

// ---------------------------------------------------------------------------
// HTTP (live HexStrike server)
// ---------------------------------------------------------------------------

// HTTPClient talks to hexstrike_server.py.
type HTTPClient struct {
	base string // e.g. "http://127.0.0.1:8888"
	hc   *http.Client
}

// NewHTTPClient builds the live client for base (scheme://host:port).
func NewHTTPClient(base string) (*HTTPClient, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("hx http: empty HexStrike server URL")
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("hx http: HexStrike server URL %q must start with http:// or https://", base)
	}
	return &HTTPClient{
		base: base,
		hc:   &http.Client{Timeout: 10 * time.Minute}, // pentest tools run long; the task timeout is the real bound
	}, nil
}

// Mode implements Client.
func (c *HTTPClient) Mode() string { return "http" }

// Health implements Client against GET /health.
func (c *HTTPClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("hx http: health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hx http: health: status %d", resp.StatusCode)
	}
	return nil
}

// CallTool implements Client against POST /api/tools/<tool>.
func (c *HTTPClient) CallTool(ctx context.Context, endpoint string, args map[string]any) (map[string]any, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("hx http: marshal args: %w", err)
	}
	url := c.base + "/" + strings.TrimLeft(endpoint, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hx http: %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("hx http: %s: read body: %w", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hx http: %s: status %d: %s", endpoint, resp.StatusCode, truncate(string(raw), 512))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("hx http: %s: decode response: %w", endpoint, err)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
