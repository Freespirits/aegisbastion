package oob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// HTTPClient is the ave.OOBClient over the service's HTTP lookup API — used
// by EVS sandbox children (separate processes) and remote workers that
// cannot share the in-process service (doc 04 D7).
type HTTPClient struct {
	base string
	hc   *http.Client
}

// NewHTTPClient builds an HTTP-backed OOB client for base ("http://host:port").
func NewHTTPClient(base string, hc *http.Client) *HTTPClient {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTPClient{base: base, hc: hc}
}

// NewCanary implements ave.OOBClient.
func (c *HTTPClient) NewCanary(ctx context.Context, purpose string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{"purpose": purpose})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/canaries", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("oob: mint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("oob: mint status %d", resp.StatusCode)
	}
	var canary Canary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&canary); err != nil {
		return "", "", fmt.Errorf("oob: mint decode: %w", err)
	}
	return canary.Token, canary.URL, nil
}

// Interactions implements ave.OOBClient.
func (c *HTTPClient) Interactions(ctx context.Context, token string) ([]ave.OOBInteraction, error) {
	u := c.base + "/v1/interactions?token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oob: lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oob: lookup status %d", resp.StatusCode)
	}
	var out struct {
		Interactions []Interaction `json:"interactions"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("oob: lookup decode: %w", err)
	}
	res := make([]ave.OOBInteraction, 0, len(out.Interactions))
	for _, h := range out.Interactions {
		res = append(res, ave.OOBInteraction{
			Token: h.Token, At: h.At, Remote: h.Remote,
			Method: h.Method, Path: h.Path, UserAgent: h.UserAgent,
		})
	}
	return res, nil
}
