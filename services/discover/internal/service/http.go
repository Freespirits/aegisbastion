// REST surface (doc 02 §3.1): service-to-service JSON API over the order
// service layer. Routes:
//
//	POST /v1/discovery/orders                 submit order → 202 {order_id} | 403 gate denial
//	GET  /v1/discovery/orders/{id}            status + progress
//	GET  /v1/discovery/orders/{id}/assets     paginated order assets
//	POST /v1/discovery/orders/{id}/cancel     cooperative cancellation
//	GET  /v1/assets                           tenant-scoped working-store read API
//	POST /v1/admin/tenants/{id}/discover:disable  platform-admin kill (via gatekeeper)
//	GET  /healthz /readyz
//
// Errors are RFC-7807-ish {code, detail} bodies with machine-readable
// gatekeeper reason codes preserved (doc 02 §3.3).
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// HTTP is the REST handler set.
type HTTP struct {
	svc   *Service
	ready func(ctx context.Context) (bool, map[string]string)
	log   func(msg string, args ...any)
}

// NewHTTP builds the REST surface. ready backs /readyz (nil ⇒ always ready).
func NewHTTP(svc *Service, ready func(ctx context.Context) (bool, map[string]string)) *HTTP {
	return &HTTP{svc: svc, ready: ready}
}

// Mount registers the routes.
func (h *HTTP) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/discovery/orders", h.handleSubmitOrder)
	mux.HandleFunc("GET /v1/discovery/orders/{id}", h.handleGetOrder)
	mux.HandleFunc("GET /v1/discovery/orders/{id}/assets", h.handleOrderAssets)
	mux.HandleFunc("POST /v1/discovery/orders/{id}/cancel", h.handleCancelOrder)
	mux.HandleFunc("GET /v1/assets", h.handleListAssets)
	mux.HandleFunc("POST /v1/admin/tenants/{id}/discover:disable", h.handleDisableTenant)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
}

type errorBody struct {
	Code    string   `json:"code"`
	Detail  string   `json:"detail"`
	Reasons []string `json:"reasons,omitempty"`
	Status  any      `json:"status,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func writeErr(w http.ResponseWriter, code int, codeStr, detail string) {
	writeJSON(w, code, errorBody{Code: codeStr, Detail: detail})
}

func (h *HTTP) handleSubmitOrder(w http.ResponseWriter, r *http.Request) {
	var order model.DiscoveryOrder
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&order); err != nil {
		writeErr(w, http.StatusBadRequest, "SCHEMA_INVALID", "body does not decode as a DiscoveryOrder: "+err.Error())
		return
	}
	st, err := h.svc.SubmitOrder(r.Context(), &order)
	if err != nil {
		switch {
		case errors.Is(err, ErrValidation):
			writeErr(w, http.StatusBadRequest, "SCHEMA_INVALID", err.Error())
		case errors.Is(err, ErrDenied):
			// 403 with the gatekeeper denial record (doc 02 §3.1).
			code := http.StatusForbidden
			body := errorBody{Code: "DENIED", Detail: "gatekeeper denied the order"}
			if st != nil && st.Gate != nil {
				body.Reasons = st.Gate.Reasons
			}
			body.Status = st
			writeJSON(w, code, body)
		case errors.Is(err, ErrGatekeeperDown):
			writeErr(w, http.StatusBadGateway, "GATEKEEPER_UNREACHABLE", err.Error())
		case errors.Is(err, ErrIntakePaused):
			writeErr(w, http.StatusServiceUnavailable, "AUDIT_SPOOL_FULL", err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, st)
}

func (h *HTTP) handleGetOrder(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.GetStatus(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "no such order")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *HTTP) handleOrderAssets(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	assets, next, err := h.svc.ListOrderAssets(r.Context(), r.PathValue("id"), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets, "next_cursor": next})
}

func (h *HTTP) handleCancelOrder(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Cancel(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "no such order")
	case errors.Is(err, ErrConflict):
		writeErr(w, http.StatusConflict, "INVALID_STATE", err.Error())
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (h *HTTP) handleListAssets(w http.ResponseWriter, r *http.Request) {
	q := store.AssetQuery{
		TenantID: r.URL.Query().Get("tenant_id"),
		Domain:   r.URL.Query().Get("domain"),
		Type:     r.URL.Query().Get("type"),
		Cursor:   r.URL.Query().Get("cursor"),
	}
	if q.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "SCHEMA_INVALID", "tenant_id is required")
		return
	}
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "SCHEMA_INVALID", "since must be RFC3339")
			return
		}
		q.Since = &t
	}
	q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	assets, next, err := h.svc.ListAssets(r.Context(), q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets, "next_cursor": next})
}

func (h *HTTP) handleDisableTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	actor := r.Header.Get("X-Operator-Id") // platform edge identity shim (MVP)
	if actor == "" {
		actor = "platform-admin"
	}
	issued, err := h.svc.DisableTenant(r.Context(), tenantID, actor)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "REVOCATION_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "roes_revoked": issued})
}

func (h *HTTP) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *HTTP) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if h.ready == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	ok, checks := h.ready(r.Context())
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": map[bool]string{true: "ready", false: "not_ready"}[ok], "checks": checks})
}

// fireCallback POSTs the terminal OrderStatus to the order's callback_url
// (doc 02 §3.1 — optional per-order webhook; best-effort, one attempt).
func (s *Service) fireCallback(ctx context.Context, order *model.DiscoveryOrder, st *model.OrderStatus) {
	if order.Options.CallbackURL == "" || st.FinishedAt == "" {
		return
	}
	body, err := json.Marshal(st)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, order.Options.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.d.Log.Warn("callback webhook failed", "order_id", order.OrderID, "error", err)
		return
	}
	_ = resp.Body.Close()
}
