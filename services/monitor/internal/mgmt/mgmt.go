// Package mgmt serves the doc 03 §13 Module Management API (operator/
// internal REST) plus /healthz, /readyz, and /metrics. No endpoint triggers
// probing directly — POST /v1/assets/{id}/rescan submits a monitor.rescan
// order THROUGH the Orchestrator (PlannerService.SubmitTaskPlan) so the PEP
// path is never bypassed. The MVP ships the exposure ruleset as a fixed
// bundle (doc 03 §14: no ruleset toggle).
package mgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/coordinator"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rules"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
)

// Deps wires the API.
type Deps struct {
	Store       *store.Store
	Coordinator *coordinator.Coordinator
	Streamer    *streamer.Streamer
	// Planner submits rescan orders through the command layer (nil disables
	// POST /v1/assets/{id}/rescan with 503).
	Planner platformv1.PlannerServiceClient
	// Ready reports dependency health (postgres/nats), mirroring
	// platform-core's readiness shape.
	Ready func(ctx context.Context) (bool, map[string]string)
	// AuditHook records mutating operator actions (doc 03 §13).
	AuditHook func(ctx context.Context, action string, detail map[string]any)
}

// Handler returns the root handler.
func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ok, details := d.ready(r)
		status := http.StatusOK
		if !ok {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{"ready": ok, "deps": details})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		d.metrics(w)
	})

	mux.HandleFunc("GET /v1/watches", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"watches": d.Coordinator.Watches()})
	})
	mux.HandleFunc("GET /v1/watches/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		for _, ws := range d.Coordinator.Watches() {
			if ws.WatchID == id || ws.TaskID == id {
				writeJSON(w, http.StatusOK, ws)
				return
			}
		}
		writeErr(w, http.StatusNotFound, "watch not found")
	})
	mux.HandleFunc("GET /v1/assets/{id}/timeline", func(w http.ResponseWriter, r *http.Request) {
		d.timeline(w, r)
	})
	mux.HandleFunc("GET /v1/assets/{id}/snapshots", func(w http.ResponseWriter, r *http.Request) {
		d.snapshots(w, r)
	})
	mux.HandleFunc("POST /v1/assets/{id}/rescan", func(w http.ResponseWriter, r *http.Request) {
		d.rescan(w, r)
	})
	mux.HandleFunc("POST /v1/suppressions", func(w http.ResponseWriter, r *http.Request) {
		d.createSuppression(w, r)
	})
	mux.HandleFunc("DELETE /v1/suppressions/{id}", func(w http.ResponseWriter, r *http.Request) {
		d.deleteSuppression(w, r)
	})
	mux.HandleFunc("GET /v1/exposures", func(w http.ResponseWriter, r *http.Request) {
		d.exposures(w, r)
	})
	mux.HandleFunc("GET /v1/rules/exposures", func(w http.ResponseWriter, _ *http.Request) {
		d.exposureRules(w)
	})
	return mux
}

func (d Deps) ready(r *http.Request) (bool, map[string]string) {
	if d.Ready != nil {
		return d.Ready(r.Context())
	}
	return true, map[string]string{}
}

func (d Deps) timeline(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	from := time.Now().Add(-7 * 24 * time.Hour)
	to := time.Now().Add(time.Hour)
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	evts, err := d.Store.EventTimeline(r.Context(), assetID, from, to, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": assetID, "events": evts})
}

func (d Deps) snapshots(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	probeType := r.URL.Query().Get("probe_type")
	snaps, err := d.Store.SnapshotHistory(r.Context(), assetID, probeType, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": assetID, "snapshots": snaps})
}

// rescan routes the on-demand recheck THROUGH the Orchestrator (doc 03 §13:
// the PEP path is never bypassed).
func (d Deps) rescan(w http.ResponseWriter, r *http.Request) {
	if d.Planner == nil {
		writeErr(w, http.StatusServiceUnavailable, "planner client not configured")
		return
	}
	assetID := r.PathValue("id")
	var body struct {
		MissionID string `json:"mission_id"`
		Reason    string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.MissionID == "" {
		writeErr(w, http.StatusBadRequest, "mission_id is required")
		return
	}
	identifier, err := d.lookupIdentifier(r.Context(), body.MissionID, assetID)
	if err != nil || identifier == "" {
		writeErr(w, http.StatusNotFound, "asset not found in watch set")
		return
	}
	params, err := structpb.NewStruct(map[string]any{
		"targets":       []any{identifier},
		"probe_types":   []any{"dns", "tls", "http"},
		"reason":        "operator rescan via mgmt API: " + body.Reason,
		"report_events": true,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := d.Planner.SubmitTaskPlan(r.Context(), &platformv1.SubmitTaskPlanRequest{
		Plan: &platformv1.TaskPlan{
			MissionId:      body.MissionID,
			IdempotencyKey: fmt.Sprintf("monitor-mgmt:rescan:%s:%d", assetID, time.Now().Unix()),
			Tasks: []*platformv1.TaskSpec{{
				TaskKey:    "rescan-" + assetID,
				Capability: "monitor.rescan",
				RiskClass:  platformv1.RiskClass_RISK_CLASS_R1,
				Targets:    []string{identifier},
				Params:     params,
				TimeoutS:   600,
			}},
		},
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "orchestrator: "+err.Error())
		return
	}
	d.audit(r, "monitor.mgmt_rescan", map[string]any{
		"asset_id": assetID, "identifier": identifier, "mission_id": body.MissionID,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"decision": resp.GetDecision().String(), "identifier": identifier,
	})
}

func (d Deps) lookupIdentifier(ctx context.Context, missionID, assetID string) (string, error) {
	assets, err := d.Store.ListWatchAssets(ctx, missionID, "")
	if err != nil {
		return "", err
	}
	for _, a := range assets {
		if a.AssetID == assetID || a.Identifier == assetID {
			return a.Identifier, nil
		}
	}
	return "", nil
}

func (d Deps) createSuppression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Selector  map[string]string `json:"selector"`
		Reason    string            `json:"reason"`
		CreatedBy string            `json:"created_by"`
		ExpiresIn string            `json:"expires_in"` // e.g. "720h"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if body.Reason == "" || body.CreatedBy == "" {
		writeErr(w, http.StatusBadRequest, "reason and created_by are required")
		return
	}
	dur := 30 * 24 * time.Hour
	if body.ExpiresIn != "" {
		if v, err := time.ParseDuration(body.ExpiresIn); err == nil {
			dur = v
		}
	}
	id, err := d.Store.InsertSuppression(r.Context(), body.Selector, body.Reason,
		body.CreatedBy, time.Now().Add(dur))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.audit(r, "monitor.mgmt_suppression_create", map[string]any{
		"suppression_id": id, "selector": fmt.Sprint(body.Selector), "created_by": body.CreatedBy,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"suppression_id": id})
}

func (d Deps) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.Store.DeleteSuppression(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.audit(r, "monitor.mgmt_suppression_delete", map[string]any{"suppression_id": id})
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (d Deps) exposures(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	states, assets, err := d.Store.ListExposures(r.Context(), state, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		AssetID  string     `json:"asset_id"`
		RuleID   string     `json:"rule_id"`
		State    string     `json:"state"`
		OpenedAt time.Time  `json:"opened_at"`
		ClosedAt *time.Time `json:"closed_at,omitempty"`
	}
	out := make([]row, 0, len(states))
	for i, st := range states {
		out = append(out, row{assets[i], st.RuleID, st.State, st.OpenedAt, st.ClosedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"exposures": out})
}

// exposureRules lists the shipped ruleset bundle (doc 03 §13/§14: read-only
// at MVP — the ruleset is a shipped bundle, no toggle).
func (d Deps) exposureRules(w http.ResponseWriter) {
	type rule struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Enabled  bool   `json:"enabled"`
	}
	out := make([]rule, 0, len(rules.ExposureV1))
	for _, r := range rules.ExposureV1 {
		out = append(out, rule{r.ID, r.Severity, r.Title, true})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ruleset": rules.RuleSetVersion, "rules": out,
	})
}

func (d Deps) metrics(w http.ResponseWriter) {
	c := d.Streamer.Counters()
	watches := d.Coordinator.Watches()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "monitor_events_emitted_total %d\n", c.Emitted)
	fmt.Fprintf(w, "monitor_events_suppressed_total{reason=\"dedup\"} %d\n", c.Deduped)
	fmt.Fprintf(w, "monitor_events_suppressed_total{reason=\"suppression\"} %d\n", c.Suppressed)
	fmt.Fprintf(w, "monitor_events_suppressed_total{reason=\"cap\"} %d\n", c.Capped)
	fmt.Fprintf(w, "monitor_change_bursts_total %d\n", c.Bursts)
	fmt.Fprintf(w, "monitor_outbox_relayed_total %d\n", c.Relayed)
	fmt.Fprintf(w, "monitor_outbox_relay_errors_total %d\n", c.RelayErrs)
	fmt.Fprintf(w, "monitor_active_watches %d\n", len(watches))
	for _, ws := range watches {
		fmt.Fprintf(w, "monitor_watch_assets{watch_id=%q,mission_id=%q} %d\n",
			ws.WatchID, ws.MissionID, ws.AssetsWatched)
	}
}

func (d Deps) audit(r *http.Request, action string, detail map[string]any) {
	if d.AuditHook != nil {
		d.AuditHook(r.Context(), action, detail)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
