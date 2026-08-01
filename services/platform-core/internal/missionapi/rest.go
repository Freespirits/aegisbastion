package missionapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// RESTGateway is the doc 01 §7.3 REST/JSON surface over the MissionService
// (the MVP ships "REST gateway only", doc 01 §14). Operator identity comes
// from the X-Operator-Id header and is injected into the gRPC context so the
// same RBAC shim covers both transports.
type RESTGateway struct {
	svc     *Service
	ready   func(context.Context) (bool, map[string]string)
	marsh   protojson.MarshalOptions
	unmarsh protojson.UnmarshalOptions
}

// NewRESTGateway builds the gateway. ready reports readiness details for
// /readyz (nil → always ready).
func NewRESTGateway(svc *Service, ready func(context.Context) (bool, map[string]string)) *RESTGateway {
	return &RESTGateway{
		svc:     svc,
		ready:   ready,
		marsh:   protojson.MarshalOptions{EmitUnpopulated: true},
		unmarsh: protojson.UnmarshalOptions{DiscardUnknown: true},
	}
}

// Handler returns the http.Handler with all routes mounted.
func (g *RESTGateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/missions", g.createMission)
	mux.HandleFunc("GET /v1/missions/{id}", g.getMission)
	mux.HandleFunc("POST /v1/missions/{id}/pause", g.pauseMission)
	mux.HandleFunc("POST /v1/missions/{id}/resume", g.resumeMission)
	mux.HandleFunc("POST /v1/missions/{id}/kill", g.killMission)
	mux.HandleFunc("GET /v1/missions/{id}/audit", g.getAuditTrail)
	mux.HandleFunc("POST /v1/roe/approve", g.approveRoE)
	mux.HandleFunc("POST /v1/roe/revoke", g.revokeRoE)
	mux.HandleFunc("GET /healthz", g.healthz)
	mux.HandleFunc("GET /readyz", g.readyz)
	return mux
}

func (g *RESTGateway) ctx(r *http.Request) context.Context {
	operator := r.Header.Get("X-Operator-Id")
	md := metadata.New(map[string]string{OperatorHeader: operator})
	return metadata.NewIncomingContext(r.Context(), md)
}

func (g *RESTGateway) writeProto(w http.ResponseWriter, code int, m proto.Message) {
	data, err := g.marsh.Marshal(m)
	if err != nil {
		g.writeErr(w, status.Errorf(codes.Internal, "marshal: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(data)
}

func (g *RESTGateway) writeErr(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		st = status.New(codes.Internal, err.Error())
	}
	httpCode := http.StatusInternalServerError
	switch st.Code() {
	case codes.InvalidArgument:
		httpCode = http.StatusBadRequest
	case codes.Unauthenticated:
		httpCode = http.StatusUnauthorized
	case codes.PermissionDenied:
		httpCode = http.StatusForbidden
	case codes.NotFound:
		httpCode = http.StatusNotFound
	case codes.FailedPrecondition:
		httpCode = http.StatusConflict
	case codes.Unavailable:
		httpCode = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    st.Code().String(),
			"message": st.Message(),
		},
	})
}

func (g *RESTGateway) decode(r *http.Request, m proto.Message) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("request body too large")
	}
	if len(body) == 0 {
		return nil
	}
	return g.unmarsh.Unmarshal(body, m)
}

func (g *RESTGateway) createMission(w http.ResponseWriter, r *http.Request) {
	req := &platformv1CreateMissionRequest{}
	if err := g.decode(r, req); err != nil {
		g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad body: %v", err))
		return
	}
	// created_by falls back to the operator header.
	if req.GetCreatedBy() == "" {
		req.CreatedBy = r.Header.Get("X-Operator-Id")
	}
	resp, err := g.svc.CreateMission(g.ctx(r), req)
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusCreated, resp)
}

func (g *RESTGateway) getMission(w http.ResponseWriter, r *http.Request) {
	resp, err := g.svc.GetMission(g.ctx(r), &platformv1GetMissionRequest{MissionId: r.PathValue("id")})
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) pauseMission(w http.ResponseWriter, r *http.Request) {
	resp, err := g.svc.PauseMission(g.ctx(r), &platformv1PauseMissionRequest{MissionId: r.PathValue("id")})
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) resumeMission(w http.ResponseWriter, r *http.Request) {
	resp, err := g.svc.ResumeMission(g.ctx(r), &platformv1ResumeMissionRequest{MissionId: r.PathValue("id")})
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) killMission(w http.ResponseWriter, r *http.Request) {
	req := &platformv1KillMissionRequest{MissionId: r.PathValue("id")}
	if err := g.decode(r, req); err != nil {
		g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad body: %v", err))
		return
	}
	resp, err := g.svc.KillMission(g.ctx(r), req)
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) getAuditTrail(w http.ResponseWriter, r *http.Request) {
	req := &platformv1GetAuditTrailRequest{MissionId: r.PathValue("id")}
	if v := r.URL.Query().Get("after_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad after_seq: %v", err))
			return
		}
		req.AfterSeq = n
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad limit: %v", err))
			return
		}
		req.Limit = uint32(n)
	}
	resp, err := g.svc.GetAuditTrail(g.ctx(r), req)
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) approveRoE(w http.ResponseWriter, r *http.Request) {
	req := &platformv1ApproveRoERequest{}
	if err := g.decode(r, req); err != nil {
		g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad body: %v", err))
		return
	}
	if req.GetApprover() == "" {
		req.Approver = r.Header.Get("X-Operator-Id")
	}
	resp, err := g.svc.ApproveRoE(g.ctx(r), req)
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) revokeRoE(w http.ResponseWriter, r *http.Request) {
	req := &platformv1RevokeRoERequest{}
	if err := g.decode(r, req); err != nil {
		g.writeErr(w, status.Errorf(codes.InvalidArgument, "bad body: %v", err))
		return
	}
	resp, err := g.svc.RevokeRoE(g.ctx(r), req)
	if err != nil {
		g.writeErr(w, err)
		return
	}
	g.writeProto(w, http.StatusOK, resp)
}

func (g *RESTGateway) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (g *RESTGateway) readyz(w http.ResponseWriter, r *http.Request) {
	ok := true
	details := map[string]string{}
	if g.ready != nil {
		ok, details = g.ready(r.Context())
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":   ok,
		"details": details,
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// Convenience aliases keep the REST handlers readable.
type (
	platformv1CreateMissionRequest = platformv1.CreateMissionRequest
	platformv1GetMissionRequest    = platformv1.GetMissionRequest
	platformv1PauseMissionRequest  = platformv1.PauseMissionRequest
	platformv1ResumeMissionRequest = platformv1.ResumeMissionRequest
	platformv1KillMissionRequest   = platformv1.KillMissionRequest
	platformv1GetAuditTrailRequest = platformv1.GetAuditTrailRequest
	platformv1ApproveRoERequest    = platformv1.ApproveRoERequest
	platformv1RevokeRoERequest     = platformv1.RevokeRoERequest
)
