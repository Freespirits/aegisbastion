package queryapi

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// Asset is the resolver for the asset field.
func (r *queryResolver) Asset(ctx context.Context, uid string) (*Asset, error) {
	id, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	a, err := r.st.GetAsset(ctx, id.TenantID, uid)
	if err != nil {
		return nil, fmt.Errorf("asset lookup: %w", err)
	}
	r.auditQuery(ctx, id, "asset", map[string]any{"uid": uid}, boolRows(a != nil))
	if a == nil {
		return nil, nil
	}
	return assetModel(a), nil
}

// Assets is the resolver for the assets field.
func (r *queryResolver) Assets(ctx context.Context, filter *AssetFilter, first *int, after *string) (*AssetConnection, error) {
	id, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	var f store.AssetFilter
	if filter != nil {
		f.Types = filter.Types
		f.Statuses = filter.Statuses
		if filter.ValuePrefix != nil {
			f.ValuePrefix = *filter.ValuePrefix
		}
		f.Since = filter.SeenSince
	}
	var afterValue, afterID string
	if after != nil && *after != "" {
		c, err := decodeCursor[assetCursor](*after)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor")
		}
		afterValue, afterID = c.V, c.I
	}
	limit := r.pageLimit(first)
	// Fetch one extra row to compute hasNextPage.
	assets, total, err := r.st.ListAssets(ctx, id.TenantID, f, limit+1, afterValue, afterID)
	if err != nil {
		return nil, fmt.Errorf("assets query: %w", err)
	}
	r.auditQuery(ctx, id, "assets", filter, len(assets))
	conn := &AssetConnection{Nodes: []*Asset{}, PageInfo: &PageInfo{TotalCount: total}}
	for i, a := range assets {
		if i == limit {
			conn.PageInfo.HasNextPage = true
			break
		}
		conn.Nodes = append(conn.Nodes, assetModel(a))
		cur := encodeCursor(assetCursor{V: a.Value, I: a.AssetID})
		conn.PageInfo.EndCursor = &cur
	}
	return conn, nil
}

// AssetNeighborhood is the resolver for the assetNeighborhood field.
func (r *queryResolver) AssetNeighborhood(ctx context.Context, uid string, depth *int) (*AssetNeighborhood, error) {
	id, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	d := 1
	if depth != nil {
		d = *depth
	}
	if d < 0 || d > r.maxDepth {
		// Query cost control (doc 09 §5): over-broad traversals are rejected.
		return nil, fmt.Errorf("depth must be in [0,%d]", r.maxDepth)
	}
	nb, err := r.st.Neighborhood(ctx, id.TenantID, uid, d)
	if err != nil {
		return nil, fmt.Errorf("neighborhood: %w", err)
	}
	if nb == nil {
		return nil, fmt.Errorf("asset %s not found in this tenant", uid)
	}
	r.auditQuery(ctx, id, "assetNeighborhood", map[string]any{"uid": uid, "depth": d}, len(nb.Assets))
	out := &AssetNeighborhood{Root: assetModel(nb.Root), Assets: []*Asset{}, Edges: []*Edge{}}
	for _, a := range nb.Assets {
		out.Assets = append(out.Assets, assetModel(a))
	}
	for _, e := range nb.Edges {
		out.Edges = append(out.Edges, edgeModel(e))
	}
	return out, nil
}

// Finding is the resolver for the finding field.
func (r *queryResolver) Finding(ctx context.Context, id string) (*Finding, error) {
	tid, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	f, err := r.st.GetFinding(ctx, tid.TenantID, id)
	if err != nil {
		return nil, fmt.Errorf("finding lookup: %w", err)
	}
	r.auditQuery(ctx, tid, "finding", map[string]any{"id": id}, boolRows(f != nil))
	if f == nil {
		return nil, nil
	}
	out, err := r.findingModel(ctx, tid, f)
	if err != nil {
		return nil, fmt.Errorf("transitions: %w", err)
	}
	return out, nil
}

// Findings is the resolver for the findings field.
func (r *queryResolver) Findings(ctx context.Context, filter *FindingFilter, first *int, after *string) (*FindingConnection, error) {
	id, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	var f store.FindingFilter
	if filter != nil {
		f.Modules = filter.Modules
		f.Severities = filter.Severities
		f.States = filter.States
		if filter.AssetUID != nil {
			f.AssetUID = *filter.AssetUID
		}
		if filter.TaskID != nil {
			f.TaskID = *filter.TaskID
		}
		if filter.CheckIDPrefix != nil {
			f.CheckIDPrefix = *filter.CheckIDPrefix
		}
		f.Since = filter.SeenSince
	}
	var afterCreated time.Time
	var afterID string
	if after != nil && *after != "" {
		c, err := decodeCursor[findingCursor](*after)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor")
		}
		afterCreated, afterID = c.C, c.I
	}
	limit := r.pageLimit(first)
	findings, total, err := r.st.ListFindings(ctx, id.TenantID, f, limit+1, afterCreated, afterID)
	if err != nil {
		return nil, fmt.Errorf("findings query: %w", err)
	}
	r.auditQuery(ctx, id, "findings", filter, len(findings))
	conn := &FindingConnection{Nodes: []*Finding{}, PageInfo: &PageInfo{TotalCount: total}}
	for i, fnd := range findings {
		if i == limit {
			conn.PageInfo.HasNextPage = true
			break
		}
		fm, err := r.findingModel(ctx, id, fnd)
		if err != nil {
			return nil, fmt.Errorf("transitions: %w", err)
		}
		conn.Nodes = append(conn.Nodes, fm)
		cur := encodeCursor(findingCursor{C: fnd.CreatedAt, I: fnd.FindingID})
		conn.PageInfo.EndCursor = &cur
	}
	return conn, nil
}

// TaskRollup is the resolver for the taskRollup field.
func (r *queryResolver) TaskRollup(ctx context.Context, taskID string) (*TaskRollup, error) {
	id, err := r.tenantID(ctx)
	if err != nil {
		return nil, err
	}
	ru, err := r.st.Rollup(ctx, id.TenantID, taskID)
	if err != nil {
		return nil, fmt.Errorf("rollup: %w", err)
	}
	r.auditQuery(ctx, id, "taskRollup", map[string]any{"taskId": taskID}, boolRows(ru != nil))
	if ru == nil {
		return nil, nil
	}
	bySev := map[string]any{}
	for k, v := range ru.FindingsBySeverity {
		bySev[k] = v
	}
	return &TaskRollup{
		TaskID:             ru.TaskID,
		TenantID:           ru.TenantID,
		Batches:            ru.Batches,
		RejectedBatches:    ru.RejectedBatches,
		AssetsTouched:      ru.AssetsTouched,
		FindingsProduced:   ru.FindingsProduced,
		FindingsBySeverity: bySev,
		FirstActivity:      ru.FirstActivity,
		LastActivity:       ru.LastActivity,
	}, nil
}

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }

func boolRows(b bool) int {
	if b {
		return 1
	}
	return 0
}
