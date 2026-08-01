package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/aegisbastion/aegisbastion/adapters/internal/taskspec"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// rpcTimeout bounds PlannerService calls from REST handlers.
const rpcTimeout = 30 * time.Second

// Server is the CAI adapter's REST surface (doc 01 §7.1: a REST/JSON tool
// endpoint the commander calls). Health routes are mounted on the same
// listener by the caller.
type Server struct {
	planner Planner
	pc      platformv1.PlannerServiceClient
	mux     *http.ServeMux
}

// NewServer builds the REST handler. pc is the client side of the platform
// PlannerService; planner is the (stub, at MVP-A) mission planner.
func NewServer(pl Planner, pc platformv1.PlannerServiceClient) *Server {
	s := &Server{planner: pl, pc: pc, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /v1/intents", s.handleIntent)
	s.mux.HandleFunc("POST /v1/plans", s.handleSubmitPlan)
	s.mux.HandleFunc("GET /v1/missions/{id}", s.handleGetMission)
	s.mux.HandleFunc("GET /v1/capabilities", s.handleListCapabilities)
	return s
}

// Handler exposes the mux so main can mount health routes alongside.
func (s *Server) Handler() http.Handler { return s.mux }

// Mount registers an additional handler (used for the health surface).
func (s *Server) Mount(pattern string, h http.Handler) {
	s.mux.Handle(pattern, h)
}

// ---------------------------------------------------------------------------
// POST /v1/intents — the MVP-A stub entry point. Accepts a mission intent,
// plans it with the configured Planner (deterministic Discover passive order
// in stub mode), submits the plan to the Orchestrator, and returns both.
// ---------------------------------------------------------------------------

type intentResponse struct {
	Plan       any             `json:"plan"`
	Submission *submissionView `json:"submission,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type submissionView struct {
	Decision     string           `json:"decision"`
	TaskVerdicts []taskVerdictOut `json:"task_verdicts"`
}

type taskVerdictOut struct {
	TaskKey  string `json:"task_key"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

func (s *Server) handleIntent(w http.ResponseWriter, r *http.Request) {
	var in Intent
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid intent JSON: %v", err)
		return
	}
	plan, err := s.planner.PlanMission(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	planJSON, err := toJSON(plan)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), rpcTimeout)
	defer cancel()
	resp, err := s.pc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		// The plan is still returned so callers can inspect it; the flow is
		// exercisable even while the Orchestrator is down.
		writeJSON(w, http.StatusBadGateway, intentResponse{
			Plan:  planJSON,
			Error: fmt.Sprintf("planner SubmitTaskPlan: %v", err),
		})
		return
	}
	writeJSON(w, http.StatusOK, intentResponse{
		Plan:       planJSON,
		Submission: verdictView(resp),
	})
}

// ---------------------------------------------------------------------------
// POST /v1/plans — the doc 01 §7.1 surface the real CAI calls with an
// already-formed plan. Kept live in stub mode so the production integration
// path is exercised end-to-end.
// ---------------------------------------------------------------------------

func (s *Server) handleSubmitPlan(w http.ResponseWriter, r *http.Request) {
	var body taskspec.PlanJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid plan JSON: %v", err)
		return
	}
	plan, err := taskspec.BuildPlan(platformv1.Commander_COMMANDER_CAI, "", &body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), rpcTimeout)
	defer cancel()
	resp, err := s.pc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		writeError(w, http.StatusBadGateway, "planner SubmitTaskPlan: %v", err)
		return
	}
	out := struct {
		PlanID string `json:"plan_id"`
		*submissionView
	}{PlanID: plan.GetPlanId(), submissionView: verdictView(resp)}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// GET /v1/missions/{id}, GET /v1/capabilities — read proxies to the
// PlannerService (doc 01 §7.1).
// ---------------------------------------------------------------------------

func (s *Server) handleGetMission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "mission id is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), rpcTimeout)
	defer cancel()
	resp, err := s.pc.GetMissionStatus(ctx, &platformv1.GetMissionStatusRequest{
		Mission: &platformv1.MissionRef{MissionId: id},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "planner GetMissionStatus: %v", err)
		return
	}
	writeProto(w, resp)
}

func (s *Server) handleListCapabilities(w http.ResponseWriter, r *http.Request) {
	query := &platformv1.CapabilityQuery{
		NamePrefix: r.URL.Query().Get("name_prefix"),
	}
	if rc := r.URL.Query().Get("max_risk_class"); rc != "" {
		parsed, err := taskspec.ParseRiskClass(rc)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		query.MaxRiskClass = parsed
	}
	ctx, cancel := context.WithTimeout(r.Context(), rpcTimeout)
	defer cancel()
	resp, err := s.pc.ListCapabilities(ctx, &platformv1.ListCapabilitiesRequest{Query: query})
	if err != nil {
		writeError(w, http.StatusBadGateway, "planner ListCapabilities: %v", err)
		return
	}
	writeProto(w, resp)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func verdictView(resp *platformv1.SubmitTaskPlanResponse) *submissionView {
	view := &submissionView{Decision: taskspec.FormatDecision(resp.GetDecision())}
	for _, v := range resp.GetTaskVerdicts() {
		view.TaskVerdicts = append(view.TaskVerdicts, taskVerdictOut{
			TaskKey:  v.GetTaskKey(),
			Accepted: v.GetAccepted(),
			Reason:   v.GetReason(),
		})
	}
	return view
}

// toJSON renders a proto message as generic JSON via protojson (snake_case
// fields, enum names — the doc 01 wire shapes).
func toJSON(m proto.Message) (any, error) {
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode response: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("encode response: %v", err)
	}
	return out, nil
}

func writeProto(w http.ResponseWriter, m proto.Message) {
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, map[string]string{"error": fmt.Sprintf(format, args...)})
}
