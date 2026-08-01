// Package queryapi is the governed GraphQL Query API (doc 09 §5). Read-only;
// every resolver runs under a TPEL-resolved tenant identity (doc 09 §2.3) and
// the store layer rewrites every query with the tenant predicate — cross-
// tenant reads are impossible by construction (doc 09 §9.6).
//
// This file holds the dependency injection root (gqlgen regenerates
// everything else except this file).
package queryapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/tpel"
)

// Resolver is the gqlgen DI root.
type Resolver struct {
	st       *store.Store
	maxPage  int
	maxDepth int
	log      *slog.Logger
}

// NewResolver builds the resolver root.
func NewResolver(st *store.Store, maxPage, maxDepth int, log *slog.Logger) *Resolver {
	if maxPage <= 0 {
		maxPage = 500 // doc 09 §2.3
	}
	if maxDepth <= 0 {
		maxDepth = 4 // doc 09 §2.3
	}
	return &Resolver{st: st, maxPage: maxPage, maxDepth: maxDepth, log: log}
}

// NewHandler builds the /v1/query handler with a bounded query complexity
// (doc 09 §5: cost analysis rejects over-broad traversals). Tenant scoping is
// enforced by the TPEL middleware mounted in front of this handler; resolvers
// additionally fail closed when no identity is present.
func NewHandler(r *Resolver) http.Handler {
	srv := handler.NewDefaultServer(NewExecutableSchema(Config{Resolvers: r}))
	srv.Use(extension.FixedComplexityLimit(2000))
	return srv
}

// tenantID extracts the TPEL identity (fail-closed below the middleware).
func (r *Resolver) tenantID(ctx context.Context) (tpel.Identity, error) {
	return tpel.MustIdentity(ctx)
}

// pageLimit applies the doc 09 §2.3 page cap.
func (r *Resolver) pageLimit(first *int) int {
	limit := 100
	if first != nil {
		limit = *first
	}
	if limit <= 0 {
		limit = 1
	}
	if limit > r.maxPage {
		limit = r.maxPage
	}
	return limit
}

// auditQuery writes one metadata-level data-access audit record
// (doc 09 §2.3: who, tenant, query hash, row count). Best-effort: a failing
// outbox write degrades to a log line (the forwarder keeps retrying delivery
// to gatekeeper independently, doc 09 §8).
func (r *Resolver) auditQuery(ctx context.Context, id tpel.Identity, op string, args any, rows int) {
	h := sha256.New()
	_ = json.NewEncoder(h).Encode(map[string]any{"op": op, "args": args, "rows": rows})
	err := r.st.AuditOutbox(ctx, store.AuditRecord{
		TenantID:   id.TenantID,
		Actor:      id.Actor(),
		Action:     "query.metadata",
		ObjectRef:  "query/" + op,
		ParamsHash: "sha256:" + hex.EncodeToString(h.Sum(nil)),
	})
	if err != nil && r.log != nil {
		r.log.Error("query audit record failed", "op", op, "err", err)
	}
}

// auditEvidenceAccess records a query.evidence_access event (doc 09 §9.5:
// sensitive findings are access-audited on every read).
func (r *Resolver) auditEvidenceAccess(ctx context.Context, id tpel.Identity, findingID string) {
	err := r.st.AuditOutbox(ctx, store.AuditRecord{
		TenantID:  id.TenantID,
		Actor:     id.Actor(),
		Action:    "query.evidence_access",
		ObjectRef: "finding/" + findingID + "/evidence",
	})
	if err != nil && r.log != nil {
		r.log.Error("evidence access audit record failed", "finding", findingID, "err", err)
	}
}

// --- cursors ----------------------------------------------------------------

// assetCursor is the keyset cursor for the assets connection
// (ORDER BY value, asset_id).
type assetCursor struct {
	V string `json:"v"`
	I string `json:"i"`
}

// findingCursor is the keyset cursor for the findings connection
// (ORDER BY created_at DESC, finding_id DESC).
type findingCursor struct {
	C time.Time `json:"c"`
	I string    `json:"i"`
}

func encodeCursor(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor[T any](s string) (*T, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var c T
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// --- model mapping ----------------------------------------------------------

func assetModel(a *store.Asset) *Asset {
	return &Asset{
		UID:        a.AssetID,
		Type:       a.Type,
		Value:      a.Value,
		Attributes: a.Attributes,
		Confidence: a.Confidence,
		Status:     a.Status,
		FirstSeen:  a.FirstSeen,
		LastSeen:   a.LastSeen,
		RoeID:      a.RoeID,
	}
}

func edgeModel(e *store.Edge) *Edge {
	return &Edge{
		EdgeID:     e.EdgeID,
		Src:        e.Src,
		Dst:        e.Dst,
		Rel:        e.Rel,
		Attributes: e.Attributes,
		FirstSeen:  e.FirstSeen,
		LastSeen:   e.LastSeen,
	}
}

// findingModel maps a store finding, applying the field mask for viewer-role
// callers on sensitive findings (doc 09 §9.5) and recording evidence access.
// The lifecycle history (doc 04 §7.3) is loaded with the finding.
func (r *Resolver) findingModel(ctx context.Context, id tpel.Identity, f *store.Finding) (*Finding, error) {
	out := &Finding{
		FindingID:   f.FindingID,
		AssetUID:    f.AssetUID,
		Module:      f.Module,
		CheckID:     f.CheckID,
		Title:       f.Title,
		Severity:    f.Severity,
		State:       f.State,
		Fingerprint: f.Fingerprint,
		Validation:  f.Validation,
		Risk:        f.Risk,
		EvidenceRef: f.EvidenceRef,
		Occurrence:  f.Occurrence,
		FirstSeen:   f.FirstSeen,
		LastSeen:    f.LastSeen,
		TaskID:      f.TaskID,
		Compliance:  f.Compliance,
		LegalHold:   f.LegalHold,
		Sensitive:   f.Sensitive,
		CreatedAt:   f.CreatedAt,
		UpdatedAt:   f.UpdatedAt,
	}
	if f.Sensitive && f.EvidenceRef != nil {
		if id.Role == "viewer" {
			masked := "masked:sensitive (viewer role)"
			out.EvidenceRef = &masked
		} else {
			r.auditEvidenceAccess(ctx, id, f.FindingID)
		}
	}
	trs, err := r.st.ListTransitions(ctx, id.TenantID, f.FindingID)
	if err != nil {
		return nil, err
	}
	out.Transitions = make([]*StateTransition, 0, len(trs))
	for _, t := range trs {
		out.Transitions = append(out.Transitions, transitionModel(t))
	}
	return out, nil
}

func transitionModel(t *store.StateTransition) *StateTransition {
	return &StateTransition{
		FromState: t.FromState,
		ToState:   t.ToState,
		Actor:     t.Actor,
		TaskID:    t.TaskID,
		Note:      t.Note,
		Ts:        t.TS,
	}
}
