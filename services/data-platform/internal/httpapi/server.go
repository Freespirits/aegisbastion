// Package httpapi serves the data platform's REST surface (doc 09 §3.1):
//
//	POST /v1/ingest/batch                    idempotent asset/finding writes
//	GET  /v1/tasks/{id}/rollup               ingest-side task attribution rollup
//	POST /v1/findings/{id}/transitions       lifecycle state transitions
//	POST /v1/inventory/verify                gatekeeper's R2/R3 verified-inventory
//	                                         check (doc 11 §3.3 step 4)
//	POST /v1/admin/tenants                   tenancy bootstrap (MVP admin shim)
//	GET  /v1/admin/tenants
//	POST /v1/admin/tenants/{id}/grants
//	POST /v1/admin/tenants/{id}/workspaces
//	GET  /healthz, /readyz
//
// plus the GraphQL Query API mounted at /v1/query (doc 09 §5).
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/config"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/ingest"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/lifecycle"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/problem"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/tpel"
)

// Deps bundles the server dependencies.
type Deps struct {
	Cfg     *config.Config
	Store   *store.Store
	Engine  *ingest.Engine
	TPEL    *tpel.Resolver
	ReadyFn func(ctx context.Context) (bool, map[string]string)
	Log     *slog.Logger
}

// Server is the REST handler set.
type Server struct {
	d *Deps
}

// NewServer builds the REST server.
func NewServer(d *Deps) *Server { return &Server{d: d} }

// Mount registers the REST routes on mux. graphqlHandler (may be nil) is
// mounted at /v1/query behind the TPEL middleware.
func (s *Server) Mount(mux *http.ServeMux, graphqlHandler http.Handler) {
	resolve := s.d.TPEL.Middleware

	mux.Handle("POST /v1/ingest/batch", resolve(http.HandlerFunc(s.handleIngestBatch)))
	mux.Handle("GET /v1/tasks/{id}/rollup", resolve(http.HandlerFunc(s.handleTaskRollup)))
	mux.Handle("POST /v1/findings/{id}/transitions", resolve(http.HandlerFunc(s.handleFindingTransition)))

	// Platform-internal contract for gatekeeper's policy pipeline (doc 11
	// §3.3 step 4): the caller sends no principal (see gatekeeper
	// internal/inventory) — network-internal, boolean existence answers only.
	mux.HandleFunc("POST /v1/inventory/verify", s.handleInventoryVerify)

	mux.Handle("POST /v1/admin/tenants", http.HandlerFunc(s.handleAdminCreateTenant))
	mux.Handle("GET /v1/admin/tenants", http.HandlerFunc(s.handleAdminListTenants))
	mux.Handle("POST /v1/admin/tenants/{id}/grants", http.HandlerFunc(s.handleAdminCreateGrant))
	mux.Handle("POST /v1/admin/tenants/{id}/workspaces", http.HandlerFunc(s.handleAdminCreateWorkspace))

	if graphqlHandler != nil {
		mux.Handle("/v1/query", resolve(graphqlHandler))
	}

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
}

// ---------------------------------------------------------------------------
// Ingest (doc 09 §2.2)
// ---------------------------------------------------------------------------

func (s *Server) handleIngestBatch(w http.ResponseWriter, r *http.Request) {
	id, _ := tpel.FromContext(r.Context())
	if !store.IngestRoles[id.Role] {
		problem.Write(w, problem.NoGrant("role "+id.Role+" may not ingest"))
		return
	}
	var b ingest.Batch
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		problem.Write(w, problem.Invalid("body does not decode as an ingest batch: "+err.Error()))
		return
	}
	res, prob := s.d.Engine.Apply(r.Context(), id.Actor(), id.TenantID, &b)
	if prob != nil {
		problem.Write(w, prob)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// Task rollup (doc 09 §3.1/§3.2)
// ---------------------------------------------------------------------------

func (s *Server) handleTaskRollup(w http.ResponseWriter, r *http.Request) {
	id, _ := tpel.FromContext(r.Context())
	taskID := r.PathValue("id")
	if taskID == "" {
		problem.Write(w, problem.Invalid("task id required"))
		return
	}
	rollup, err := s.d.Store.Rollup(r.Context(), id.TenantID, taskID)
	if err != nil {
		problem.Write(w, problem.Internal("rollup: "+err.Error()))
		return
	}
	if rollup == nil {
		problem.Write(w, problem.NotFoundProblem("no ingested data attributed to task "+taskID))
		return
	}
	writeJSON(w, http.StatusOK, rollup)
}

// ---------------------------------------------------------------------------
// Findings lifecycle transitions (doc 04 §7.3 persisted by 09)
// ---------------------------------------------------------------------------

type transitionRequest struct {
	ToState string `json:"to_state"`
	Note    string `json:"note,omitempty"`
	TaskID  string `json:"task_id,omitempty"`
}

func (s *Server) handleFindingTransition(w http.ResponseWriter, r *http.Request) {
	id, _ := tpel.FromContext(r.Context())
	if !store.TransitionRoles[id.Role] {
		problem.Write(w, problem.NoGrant("role "+id.Role+" may not transition findings"))
		return
	}
	findingID := r.PathValue("id")
	if len(findingID) != 36 {
		problem.Write(w, problem.Invalid("finding id must be a UUID"))
		return
	}
	var req transitionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		problem.Write(w, problem.Invalid("body does not decode: "+err.Error()))
		return
	}
	to, err := lifecycle.Parse(req.ToState)
	if err != nil {
		problem.Write(w, problem.Invalid(err.Error()))
		return
	}
	tx, err := s.d.Store.Pool.Begin(r.Context())
	if err != nil {
		problem.Write(w, problem.Internal("begin tx: "+err.Error()))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	from, changed, ok, err := store.ApplyTransitionTx(r.Context(), tx, id.TenantID, findingID,
		string(to), id.Actor(), req.TaskID, req.Note)
	if err != nil {
		problem.Write(w, problem.Internal("transition: "+err.Error()))
		return
	}
	if from == "" && !ok {
		problem.Write(w, problem.NotFoundProblem("finding "+findingID+" not found in this tenant"))
		return
	}
	if !ok {
		problem.Write(w, problem.TransitionInvalid(from+" → "+req.ToState+" is not a doc 04 §7.3 edge"))
		return
	}
	if err := store.AuditOutboxTx(r.Context(), tx, store.AuditRecord{
		TenantID: id.TenantID, Actor: id.Actor(), Action: "admin.action",
		ObjectRef: "finding/" + findingID + "/transition/" + req.ToState,
	}); err != nil {
		problem.Write(w, problem.Internal("audit record: "+err.Error()))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		problem.Write(w, problem.Internal("commit: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"finding_id": findingID, "from_state": from, "to_state": req.ToState, "changed": changed,
	})
}

// ---------------------------------------------------------------------------
// Verified-inventory check for gatekeeper (doc 11 §3.3 step 4)
// ---------------------------------------------------------------------------

type verifyRequest struct {
	Targets []string `json:"targets"`
}

func (s *Server) handleInventoryVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		problem.Write(w, problem.Invalid("body does not decode: "+err.Error()))
		return
	}
	if len(req.Targets) == 0 {
		problem.Write(w, problem.Invalid("targets must be a non-empty array"))
		return
	}
	if len(req.Targets) > 500 {
		problem.Write(w, problem.Invalid("targets exceeds 500 entries"))
		return
	}
	out := map[string]bool{}
	for _, t := range req.Targets {
		cv, err := canonicalizeTarget(t)
		if err != nil {
			out[t] = false // unparseable targets are never verified (fail-closed)
			continue
		}
		ok, err := s.d.Store.VerifiedTarget(r.Context(), cv)
		if err != nil {
			// Fail-closed: gatekeeper's client treats non-200 as an error and
			// denies with TARGET_UNVERIFIED (doc 11 §3.3).
			problem.Write(w, problem.Internal("inventory lookup: "+err.Error()))
			return
		}
		out[t] = ok
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": out})
}

// canonicalizeTarget reduces a target to the asset-value comparison form
// (host or IP, doc 01 §10.1 canonicalization).
func canonicalizeTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", errEmpty
	}
	// URL form: keep host only.
	if i := strings.Index(t, "://"); i >= 0 {
		rest := t[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if k := strings.LastIndex(rest, "@"); k >= 0 {
			rest = rest[k+1:]
		}
		t = rest
	}
	// Strip port (host:port and [v6]:port).
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.TrimPrefix(strings.TrimSuffix(t, "]"), "[")
	t = strings.TrimSuffix(strings.ToLower(t), ".")
	if t == "" {
		return "", errEmpty
	}
	return t, nil
}

var errEmpty = errString("empty target")

type errString string

func (e errString) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Admin bootstrap (MVP admin shim; audit admin.action, doc 09 §4.4)
// ---------------------------------------------------------------------------

func (s *Server) adminIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal := r.Header.Get(tpel.PrincipalHeader)
	if !s.d.Cfg.AdminAllowed(principal) {
		problem.Write(w, problem.NoGrant("principal is not a dp admin (DP_ADMIN_PRINCIPALS)"))
		return "", false
	}
	return principal, true
}

func (s *Server) handleAdminCreateTenant(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.adminIdentity(w, r)
	if !ok {
		return
	}
	var req struct {
		Name       string `json:"name"`
		Tier       string `json:"tier,omitempty"`
		DataRegion string `json:"data_region,omitempty"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		problem.Write(w, problem.Invalid("name is required"))
		return
	}
	t, err := s.d.Store.CreateTenant(r.Context(), req.Name, req.Tier, req.DataRegion)
	if err != nil {
		problem.Write(w, problem.Internal("create tenant: "+err.Error()))
		return
	}
	s.auditAdmin(r, principal, "tenant/"+t.TenantID, req)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleAdminListTenants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminIdentity(w, r); !ok {
		return
	}
	ts, err := s.d.Store.ListTenants(r.Context())
	if err != nil {
		problem.Write(w, problem.Internal("list tenants: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": ts})
}

func (s *Server) handleAdminCreateGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.adminIdentity(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	var req struct {
		Principal string `json:"principal"`
		Role      string `json:"role"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Principal == "" || req.Role == "" {
		problem.Write(w, problem.Invalid("principal and role are required"))
		return
	}
	valid := false
	for _, role := range store.GrantRoles {
		if req.Role == role {
			valid = true
			break
		}
	}
	if !valid {
		problem.Write(w, problem.Invalid("role must be one of "+strings.Join(store.GrantRoles, "|")))
		return
	}
	exists, err := s.d.Store.TenantExists(r.Context(), tenantID)
	if err != nil {
		problem.Write(w, problem.Internal("tenant lookup: "+err.Error()))
		return
	}
	if !exists {
		problem.Write(w, problem.NotFoundProblem("tenant "+tenantID+" not found or not active"))
		return
	}
	g, err := s.d.Store.CreateGrant(r.Context(), tenantID, req.Principal, req.Role)
	if err != nil {
		problem.Write(w, problem.Internal("create grant: "+err.Error()))
		return
	}
	s.auditAdmin(r, principal, "tenant/"+tenantID+"/grant/"+g.GrantID, req)
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleAdminCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.adminIdentity(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		problem.Write(w, problem.Invalid("name is required"))
		return
	}
	id, err := s.d.Store.CreateWorkspace(r.Context(), tenantID, req.Name)
	if err != nil {
		problem.Write(w, problem.Internal("create workspace: "+err.Error()))
		return
	}
	s.auditAdmin(r, principal, "tenant/"+tenantID+"/workspace/"+id, req)
	writeJSON(w, http.StatusCreated, map[string]any{"workspace_id": id, "tenant_id": tenantID, "name": req.Name})
}

// auditAdmin records an admin.action data-access audit row. The outbox lives
// in the same Postgres the action just used, so a write failure means the
// store is degraded — surfaced in logs for the operator (the forwarder
// retries delivery to gatekeeper independently, doc 09 §8).
func (s *Server) auditAdmin(r *http.Request, principal, objectRef string, params any) {
	b, _ := json.Marshal(params)
	sum := sha256.Sum256(b)
	err := s.d.Store.AuditOutbox(r.Context(), store.AuditRecord{
		Actor:      store.Actor{Type: "human", ID: principal},
		Action:     "admin.action",
		ObjectRef:  objectRef,
		ParamsHash: "sha256:" + hex.EncodeToString(sum[:]),
	})
	if err != nil && s.d.Log != nil {
		s.d.Log.Error("admin audit record failed", "object", objectRef, "err", err)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ready := true
	details := map[string]string{}
	if s.d.ReadyFn != nil {
		ready, details = s.d.ReadyFn(r.Context())
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ready": ready, "checks": details})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
