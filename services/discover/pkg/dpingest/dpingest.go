// Package dpingest is the client for the data platform's Ingest API (doc 02
// §2.2 reducer + Ruling C4: every committed asset is additionally upserted
// into doc 09, the system of record, via POST /v1/ingest/batch — never by
// writing dp tables directly). Doc 09's own defense-in-depth scope check on
// ingest is retained server-side.
//
// Identity: the MVP TPEL shim (services/data-platform/internal/tpel) — the
// caller presents X-DP-Principal (a principal holding a service_discover /
// admin grant for the tenant in tenancy.grants) plus X-DP-Tenant. Discover
// is R0, so batches carry no Scope Token (Batch.risk_class empty ⇒ the
// REST-only token re-verification does not apply).
//
// Batches carry deterministic idempotency keys (doc 09 §8: retries are
// no-ops), derived from (order, asset) so a reducer redelivery that replays
// the same write collapses server-side.
package dpingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// Headers of the dp TPEL MVP credential shim.
const (
	PrincipalHeader = "X-DP-Principal"
	TenantHeader    = "X-DP-Tenant"
)

// Client posts ingest batches to the data platform.
type Client struct {
	BaseURL   string       // e.g. "http://data-platform:8082"
	Principal string       // e.g. "svc-discover" (grant role service_discover)
	HTTP      *http.Client // nil ⇒ default with 15 s timeout
}

// batch mirrors services/data-platform/internal/ingest.Batch (the wire
// contract — dp is consumed via its REST API only, never imported).
type batch struct {
	IdempotencyKey string    `json:"idempotency_key"`
	TaskID         string    `json:"task_id,omitempty"`
	Assets         []assetIn `json:"assets,omitempty"`
	Edges          []edgeIn  `json:"edges,omitempty"`
}

type assetIn struct {
	Type        string         `json:"type"`
	Value       string         `json:"value"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Confidence  *float64       `json:"confidence,omitempty"`
	Status      string         `json:"status,omitempty"`
	RoeID       string         `json:"roe_id,omitempty"`
	FirstSeen   *time.Time     `json:"first_seen,omitempty"`
	LastSeen    *time.Time     `json:"last_seen,omitempty"`
	Source      string         `json:"source,omitempty"`
	EvidenceURI string         `json:"evidence_uri,omitempty"`
}

type edgeIn struct {
	SrcType  string `json:"src_type,omitempty"`
	SrcValue string `json:"src_value,omitempty"`
	DstType  string `json:"dst_type,omitempty"`
	DstValue string `json:"dst_value,omitempty"`
	Rel      string `json:"rel"`
}

type result struct {
	IdempotencyKey string `json:"idempotency_key"`
	Replay         bool   `json:"replay"`
	Status         string `json:"status"`
}

// problem is dp's RFC-7807-ish error body (enough to surface the code).
type problem struct {
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// AssetItem is one asset write with its provenance.
type AssetItem struct {
	Record      *model.AssetRecord
	Source      string
	EvidenceURI string
}

// UpsertBatch commits one asset set (plus edges) to the data platform.
// taskID attributes the batch; orderID + the primary asset key form the
// idempotency key so replays of the same reducer write are no-ops.
func (c *Client) UpsertBatch(ctx context.Context, tenantID, orderID, taskID, primaryKey string, assets []AssetItem, edges []model.EdgeRef) error {
	b := batch{
		IdempotencyKey: idemKey(orderID, primaryKey),
		TaskID:         taskID,
	}
	for _, item := range assets {
		a := item.Record
		conf := a.Confidence
		fs, ls := a.FirstSeen.UTC(), a.LastSeen.UTC()
		b.Assets = append(b.Assets, assetIn{
			Type:        string(a.Type),
			Value:       a.Value,
			Attributes:  a.Attributes,
			Confidence:  &conf,
			Status:      a.Status,
			RoeID:       a.ROEID,
			FirstSeen:   &fs,
			LastSeen:    &ls,
			Source:      item.Source,
			EvidenceURI: item.EvidenceURI,
		})
	}
	for _, e := range edges {
		b.Edges = append(b.Edges, edgeIn{
			SrcType:  string(e.Src.Type),
			SrcValue: e.Src.Value,
			DstType:  string(e.Dst.Type),
			DstValue: e.Dst.Value,
			Rel:      e.Rel,
		})
	}
	return c.post(ctx, tenantID, &b)
}

// UpdateStatus commits a status change (e.g. expired) for an existing asset.
func (c *Client) UpdateStatus(ctx context.Context, tenantID string, a *model.AssetRecord) error {
	conf := a.Confidence
	ls := a.LastSeen.UTC()
	fs := a.FirstSeen.UTC()
	b := batch{
		IdempotencyKey: idemKey("status-"+a.Status, string(a.Type), a.Value+ls.Format(time.RFC3339Nano)),
		Assets: []assetIn{{
			Type:       string(a.Type),
			Value:      a.Value,
			Attributes: a.Attributes,
			Confidence: &conf,
			Status:     a.Status,
			RoeID:      a.ROEID,
			FirstSeen:  &fs,
			LastSeen:   &ls,
		}},
	}
	return c.post(ctx, tenantID, &b)
}

func idemKey(parts ...string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%q", parts)))
	return "discover-" + hex.EncodeToString(sum[:16])
}

func (c *Client) post(ctx context.Context, tenantID string, b *batch) error {
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	url := c.BaseURL + "/v1/ingest/batch"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PrincipalHeader, c.Principal)
		req.Header.Set(TenantHeader, tenantID)
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("dp ingest: %w", err)
			continue // transport error — retry
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var r result
			if err := json.Unmarshal(data, &r); err == nil && r.Status == "rejected" {
				return fmt.Errorf("dp ingest: batch rejected (key %s)", r.IdempotencyKey)
			}
			return nil
		}
		var p problem
		_ = json.Unmarshal(data, &p)
		lastErr = fmt.Errorf("dp ingest: status %d: %s %s", resp.StatusCode, p.Code, firstNonEmpty(p.Detail, p.Title, string(data)))
		// 4xx rejections (schema/grant/scope) are terminal — do not retry.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastErr
		}
	}
	return lastErr
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
