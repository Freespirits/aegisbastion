// Package inventory implements the R2/R3 verified-asset-inventory check
// (pipeline step 4) against module 09's query API, with a 5-minute cache
// (doc 11 §3.3). Fail-closed: any error denies with TARGET_UNVERIFIED.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HTTPVerifier calls the data platform. Expected contract (documented
// assumption until module 09 lands its endpoint):
//
//	POST {baseURL}/v1/inventory/verify  {"targets": […]}
//	200 {"verified": {"<target>": true, …}}
type HTTPVerifier struct {
	baseURL string
	cli     *http.Client

	mu       sync.Mutex
	cache    map[string]cacheEntry
	cacheTTL time.Duration
}

type cacheEntry struct {
	verified bool
	expires  time.Time
}

// NewHTTPVerifier builds the verifier with a 5-minute result cache.
func NewHTTPVerifier(baseURL string) *HTTPVerifier {
	return &HTTPVerifier{
		baseURL:  baseURL,
		cli:      &http.Client{Timeout: 5 * time.Second},
		cache:    map[string]cacheEntry{},
		cacheTTL: 5 * time.Minute,
	}
}

// VerifyTargets checks each target against verified inventory.
func (v *HTTPVerifier) VerifyTargets(ctx context.Context, targets []string) (map[string]bool, error) {
	out := map[string]bool{}
	var missing []string
	now := time.Now()
	v.mu.Lock()
	for _, t := range targets {
		if e, ok := v.cache[t]; ok && now.Before(e.expires) {
			out[t] = e.verified
		} else {
			missing = append(missing, t)
		}
	}
	v.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	body, _ := json.Marshal(map[string]any{"targets": missing})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+"/v1/inventory/verify", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inventory: status %d", resp.StatusCode)
	}
	var payload struct {
		Verified map[string]bool `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("inventory: decode: %w", err)
	}
	v.mu.Lock()
	for _, t := range missing {
		ok := payload.Verified[t]
		out[t] = ok
		v.cache[t] = cacheEntry{verified: ok, expires: now.Add(v.cacheTTL)}
	}
	v.mu.Unlock()
	return out, nil
}
