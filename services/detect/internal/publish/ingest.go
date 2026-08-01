package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IngestClient pushes findings to the data-platform Ingest API
// (doc 09 §2.2: POST /v1/ingest/batch, TPEL principal headers). Batches are
// idempotent on "detect:<finding_id>".
type IngestClient struct {
	base      string
	principal string
	tenantID  string
	hc        *http.Client
}

// NewIngestClient builds the client. principal is the TPEL identity
// ("svc-detect") holding an ingest grant; tenantID pins the tenant (MVP
// single cohort).
func NewIngestClient(base, principal, tenantID string, timeout time.Duration) *IngestClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &IngestClient{
		base:      base,
		principal: principal,
		tenantID:  tenantID,
		hc:        &http.Client{Timeout: timeout},
	}
}

// FindingIngest is one finding batch item (mirrors doc 09's FindingIn).
type FindingIngest struct {
	FindingID   string         `json:"finding_id,omitempty"`
	AssetType   string         `json:"asset_type,omitempty"`
	AssetValue  string         `json:"asset_value,omitempty"`
	Module      string         `json:"module"`
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	State       string         `json:"state,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Validation  map[string]any `json:"validation,omitempty"`
	Risk        map[string]any `json:"risk,omitempty"`
	EvidenceRef string         `json:"evidence_ref,omitempty"`
	Occurrence  int            `json:"occurrence,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	TaskID      string         `json:"task_id,omitempty"`
	Compliance  map[string]any `json:"compliance,omitempty"`
}

// IngestFindings posts one findings batch. The scope token authorizing the
// underlying scan accompanies the batch (doc 09 §2.2 REST re-verification).
func (c *IngestClient) IngestFindings(ctx context.Context, taskID, scopeToken string, items []FindingIngest) error {
	if len(items) == 0 {
		return nil
	}
	type batch struct {
		IdempotencyKey string          `json:"idempotency_key"`
		TaskID         string          `json:"task_id,omitempty"`
		RiskClass      string          `json:"risk_class,omitempty"`
		ScopeToken     string          `json:"scope_token,omitempty"`
		Findings       []FindingIngest `json:"findings"`
	}
	for _, it := range items {
		b := batch{
			IdempotencyKey: "detect:" + it.FindingID + ":" + it.Fingerprint,
			TaskID:         taskID,
			Findings:       []FindingIngest{it},
		}
		if scopeToken != "" {
			b.RiskClass = "R2"
			b.ScopeToken = scopeToken
		}
		payload, err := json.Marshal(b)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/ingest/batch", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DP-Principal", c.principal)
		if c.tenantID != "" {
			req.Header.Set("X-DP-Tenant", c.tenantID)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("ingest: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("ingest: status %d: %s", resp.StatusCode, truncate(body, 256))
		}
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
