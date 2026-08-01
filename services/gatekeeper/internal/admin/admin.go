// Package admin exposes gatekeeper's HTTP surface: the JWKS endpoint
// (doc 11 §3.2: /.well-known/gatekeeper-jwks.json), health probes, and the
// admin-api REST façade (doc 11 §2.1.10) over the internal services for the
// dashboard (doc 10) and CLI automation.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/approval"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/revocation"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/roe"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// Deps wires the facade.
type Deps struct {
	Key      *keys.Keypair
	DB       *store.DB
	ROE      *roe.Service
	Approval *approval.Service
	Revoke   *revocation.Service
	RBAC     *rbac.Service
	Audit    *audit.Service
	// Ready checks external dependencies for /readyz (NATS, MinIO).
	ReadyChecks map[string]func(ctx context.Context) error
}

// Server is the admin HTTP server.
type Server struct {
	deps Deps
	mux  *http.ServeMux
}

// NewServer builds the mux.
func NewServer(deps Deps) *Server {
	s := &Server{deps: deps, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /readyz", s.readyz)
	s.mux.HandleFunc("GET /.well-known/gatekeeper-jwks.json", s.jwks)

	s.mux.HandleFunc("POST /v1/roe", s.roeCreate)
	s.mux.HandleFunc("GET /v1/roe", s.roeList)
	s.mux.HandleFunc("GET /v1/roe/{id}", s.roeGet)
	s.mux.HandleFunc("POST /v1/roe/{id}/activate", s.roeActivate)
	s.mux.HandleFunc("POST /v1/roe/{id}/suspend", s.roeSuspend)
	s.mux.HandleFunc("POST /v1/roe/{id}/revoke", s.roeRevoke)

	s.mux.HandleFunc("POST /v1/approvals", s.approvalRequest)
	s.mux.HandleFunc("GET /v1/approvals", s.approvalList)
	s.mux.HandleFunc("GET /v1/approvals/{id}", s.approvalGet)
	s.mux.HandleFunc("POST /v1/approvals/{id}/decide", s.approvalDecide)

	s.mux.HandleFunc("POST /v1/revocations", s.revocationIssue)
	s.mux.HandleFunc("GET /v1/revocations", s.revocationList)

	s.mux.HandleFunc("POST /v1/rbac/grants", s.rbacGrant)
	s.mux.HandleFunc("GET /v1/rbac/grants", s.rbacList)
	s.mux.HandleFunc("DELETE /v1/rbac/grants", s.rbacRevoke)

	s.mux.HandleFunc("GET /v1/audit/verify", s.auditVerify)
}

// ---------------------------------------------------------------------------
// health + JWKS
// ---------------------------------------------------------------------------

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	ok := true
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.deps.DB.Ping(ctx); err != nil {
		checks["postgres"] = err.Error()
		ok = false
	} else {
		checks["postgres"] = "ok"
	}
	for name, check := range s.deps.ReadyChecks {
		if err := check(ctx); err != nil {
			checks[name] = err.Error()
			ok = false
		} else {
			checks[name] = "ok"
		}
	}
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ready": ok, "checks": checks})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{s.deps.Key.JWK()}})
}

// ---------------------------------------------------------------------------
// RoE
// ---------------------------------------------------------------------------

var protoJSON = protojson.MarshalOptions{UseProtoNames: true}

func (s *Server) roeCreate(w http.ResponseWriter, r *http.Request) {
	var roeMsg gatekeeperv1.RulesOfEngagement
	if err := unmarshalProto(r, &roeMsg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.deps.ROE.CreateROE(r.Context(), &gatekeeperv1.CreateROERequest{Roe: &roeMsg})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusCreated, resp)
}

func (s *Server) roeList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := &gatekeeperv1.ListROEsRequest{
		OrgId:     q.Get("org_id"),
		PageToken: q.Get("page_token"),
	}
	if ps, _ := strconv.Atoi(q.Get("page_size")); ps > 0 {
		req.PageSize = uint32(ps)
	}
	if st := q.Get("status"); st != "" {
		if v, ok := gatekeeperv1.ROEStatus_value["ROE_STATUS_"+strings.ToUpper(st)]; ok {
			req.Status = gatekeeperv1.ROEStatus(v)
		}
	}
	resp, err := s.deps.ROE.ListROEs(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) roeGet(w http.ResponseWriter, r *http.Request) {
	req := &gatekeeperv1.GetROERequest{RoeId: r.PathValue("id")}
	if v, _ := strconv.ParseUint(r.URL.Query().Get("version"), 10, 64); v > 0 {
		req.Version = v
	}
	resp, err := s.deps.ROE.GetROE(r.Context(), req)
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) roeActivate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version uint64 `json:"version"`
	}
	_ = decodeBody(r, &body)
	resp, err := s.deps.ROE.ActivateROE(r.Context(), &gatekeeperv1.ActivateROERequest{
		RoeId: r.PathValue("id"), Version: body.Version,
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) roeSuspend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeBody(r, &body)
	resp, err := s.deps.ROE.SuspendROE(r.Context(), &gatekeeperv1.SuspendROERequest{
		RoeId: r.PathValue("id"), Reason: body.Reason,
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) roeRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeBody(r, &body)
	resp, err := s.deps.ROE.RevokeROE(r.Context(), &gatekeeperv1.RevokeROERequest{
		RoeId: r.PathValue("id"), Reason: body.Reason,
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

func (s *Server) approvalRequest(w http.ResponseWriter, r *http.Request) {
	var req gatekeeperv1.RequestApprovalRequest
	if err := unmarshalProto(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.deps.Approval.RequestApproval(r.Context(), &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusCreated, resp)
}

func (s *Server) approvalList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := &gatekeeperv1.ListApprovalsRequest{RoeId: q.Get("roe_id"), PageToken: q.Get("page_token")}
	if st := q.Get("state"); st != "" {
		if v, ok := gatekeeperv1.ApprovalState_value["APPROVAL_STATE_"+strings.ToUpper(st)]; ok {
			req.State = gatekeeperv1.ApprovalState(v)
		}
	}
	if ps, _ := strconv.Atoi(q.Get("page_size")); ps > 0 {
		req.PageSize = uint32(ps)
	}
	resp, err := s.deps.Approval.ListApprovals(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) approvalGet(w http.ResponseWriter, r *http.Request) {
	resp, err := s.deps.Approval.GetApproval(r.Context(), &gatekeeperv1.GetApprovalRequest{
		ApprovalId: r.PathValue("id"),
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

func (s *Server) approvalDecide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Approver string `json:"approver"`
		Approved bool   `json:"approved"`
		Note     string `json:"note"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.deps.Approval.RecordApprovalDecision(r.Context(), &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: r.PathValue("id"),
		Decision: &gatekeeperv1.ApproverDecision{
			Approver: body.Approver, Approved: body.Approved, Note: body.Note,
		},
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// revocations
// ---------------------------------------------------------------------------

func (s *Server) revocationIssue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope     string `json:"scope"`
		Key       string `json:"key"`
		IssuedBy  string `json:"issued_by"`
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req := &gatekeeperv1.RevokeRequest{
		Key: body.Key, IssuedBy: body.IssuedBy, Reason: body.Reason,
	}
	if v, ok := gatekeeperv1.RevocationScope_value["REVOCATION_SCOPE_"+strings.ToUpper(body.Scope)]; ok {
		req.Scope = gatekeeperv1.RevocationScope(v)
	}
	if body.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("expires_at must be RFC3339"))
			return
		}
		req.ExpiresAt = timestamppb.New(t)
	}
	resp, err := s.deps.Revoke.Revoke(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusCreated, resp)
}

func (s *Server) revocationList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := &gatekeeperv1.ListRevocationsRequest{Key: q.Get("key")}
	if sc := q.Get("scope"); sc != "" {
		if v, ok := gatekeeperv1.RevocationScope_value["REVOCATION_SCOPE_"+strings.ToUpper(sc)]; ok {
			req.Scope = gatekeeperv1.RevocationScope(v)
		}
	}
	resp, err := s.deps.Revoke.ListRevocations(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// RBAC grants
// ---------------------------------------------------------------------------

func (s *Server) rbacGrant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrgID         string `json:"org_id"`
		Principal     string `json:"principal"`
		PrincipalKind string `json:"principal_kind"`
		Role          string `json:"role"`
		GrantedBy     string `json:"granted_by"`
		TTLHours      int    `json:"ttl_hours"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b := rbac.Binding{
		OrgID: body.OrgID, Principal: body.Principal, PrincipalKind: body.PrincipalKind,
		Role: body.Role, GrantedBy: body.GrantedBy,
	}
	if body.TTLHours > 0 {
		b.ExpiresAt = time.Now().UTC().Add(time.Duration(body.TTLHours) * time.Hour)
	}
	out, err := s.deps.RBAC.Grant(r.Context(), b)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordRBACAudit(r, "rbac.grant", out)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) rbacList(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("org_id")
	if org == "" {
		writeErr(w, http.StatusBadRequest, errors.New("org_id is required"))
		return
	}
	all := r.URL.Query().Get("include_revoked") == "true"
	out, err := s.deps.RBAC.List(r.Context(), org, all)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": out})
}

func (s *Server) rbacRevoke(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := s.deps.RBAC.Revoke(r.Context(), q.Get("org_id"), q.Get("principal"), q.Get("role")); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	s.recordRBACAudit(r, "rbac.revoke", map[string]string{
		"org_id": q.Get("org_id"), "principal": q.Get("principal"), "role": q.Get("role"),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) recordRBACAudit(r *http.Request, action string, payload any) {
	m, _ := payloadToMap(payload)
	m["action"] = action
	// RBAC grants are R0-audited (doc 11 §3.5) — best-effort.
	if _, err := s.deps.Audit.Record(r.Context(), audit.Input{
		Kind:    audit.KindRBACChanged,
		Actor:   map[string]any{"kind": "service", "id": "gatekeeper.admin-api"},
		Payload: m,
	}); err != nil {
		// Logged by audit caller; nothing else to do on the admin path.
		_ = err
	}
}

func payloadToMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// audit verification
// ---------------------------------------------------------------------------

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.ParseUint(q.Get("from_seq"), 10, 64)
	to, _ := strconv.ParseUint(q.Get("to_seq"), 10, 64)
	if from == 0 || to == 0 || to < from {
		writeErr(w, http.StatusBadRequest, errors.New("from_seq and to_seq (>= from_seq) are required"))
		return
	}
	resp, err := s.deps.Audit.VerifyChain(r.Context(), &gatekeeperv1.VerifyChainRequest{
		OrgId: q.Get("org_id"), FromSeq: from, ToSeq: to,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeProto(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProto(w http.ResponseWriter, status int, m proto.Message) {
	raw, err := protoJSON.Marshal(m)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func unmarshalProto(r *http.Request, m proto.Message) error {
	defer r.Body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return err
	}
	return protojson.Unmarshal(raw, m)
}

// statusFor maps not-found-ish errors to 404.
func statusFor(err error) int {
	if strings.Contains(err.Error(), "no rows") || strings.Contains(err.Error(), "not found") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}
