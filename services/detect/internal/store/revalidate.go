package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/coordinator"
)

// RevalidateAdapter adapts the fallback store to the coordinator's
// RevalidateStore contract (doc 04 §4.1 detect.revalidate over the local
// fallback table at MVP; 09's query API post-MVP).
type RevalidateAdapter struct {
	St *Store
}

// NewRevalidateAdapter builds the adapter.
func NewRevalidateAdapter(st *Store) *RevalidateAdapter {
	return &RevalidateAdapter{St: st}
}

// FindingByFingerprint implements coordinator.RevalidateStore: it re-aims
// validators from the stored validation payload (target/matched_at/
// vuln_class are carried there by the fallback sink).
func (a *RevalidateAdapter) FindingByFingerprint(ctx context.Context, tenantID, fingerprint string) (*coordinator.RevalidateTarget, error) {
	row, err := a.St.FindingByFingerprint(ctx, tenantID, fingerprint)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	get := func(k string) string {
		if row.Validation == nil {
			return ""
		}
		if v, ok := row.Validation[k].(string); ok {
			return v
		}
		return ""
	}
	target := get("target")
	matchedAt := get("matched_at")
	if matchedAt == "" {
		matchedAt = target
	}
	return &coordinator.RevalidateTarget{
		FindingID: row.FindingID,
		Target:    target,
		MatchedAt: matchedAt,
		CheckID:   row.CheckID,
		VulnClass: get("vuln_class"),
		State:     row.State,
	}, nil
}

// TransitionState implements coordinator.RevalidateStore.
func (a *RevalidateAdapter) TransitionState(ctx context.Context, tenantID, findingID, toState string) error {
	return a.St.TransitionState(ctx, tenantID, findingID, toState)
}
