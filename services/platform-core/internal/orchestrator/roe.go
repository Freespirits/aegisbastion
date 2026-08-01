package orchestrator

import (
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
	"github.com/aegisbastion/aegisbastion/services/platform-core/pkg/scope"
)

// roeRecord is the Orchestrator's working view of a gatekeeper RoE (the RoE
// store of record is gatekeeper roe-service; the command layer keeps no RoE
// tables, doc 01 §5.4 / Ruling B).
type roeRecord struct {
	RoeID         string
	Version       int
	Status        string
	MaxRiskClass  string
	AllowedCaps   []string
	Scope         *scope.Scope
	MaxConcurrent int // max_concurrent_intrusive (0 = use platform default)
	DefaultMaxRPS int // strongest declared rps cap (0 = use platform default)
	ValidFrom     time.Time
	ValidUntil    time.Time
}

func roeFromProto(r *gatekeeperv1.RulesOfEngagement) *roeRecord {
	rec := &roeRecord{
		RoeID:   r.GetRoeId(),
		Version: int(r.GetVersion()),
		Status:  r.GetStatus().String(),
		Scope:   &scope.Scope{},
	}
	if r.GetValidFrom() != nil {
		rec.ValidFrom = r.GetValidFrom().AsTime()
	}
	if r.GetValidUntil() != nil {
		rec.ValidUntil = r.GetValidUntil().AsTime()
	}
	if c := r.GetConstraints(); c != nil {
		rec.MaxRiskClass = pep_RiskFromProto(c.GetMaxRiskClass())
		rec.AllowedCaps = c.GetAllowedCapabilities()
		for _, rc := range c.GetRateCaps() {
			if int(rc.GetMaxConcurrent()) > rec.MaxConcurrent {
				rec.MaxConcurrent = int(rc.GetMaxConcurrent())
			}
			if int(rc.GetRps()) > rec.DefaultMaxRPS {
				rec.DefaultMaxRPS = int(rc.GetRps())
			}
		}
	}
	if sc := r.GetScope(); sc != nil {
		rec.Scope.Domains = sc.GetDomains()
		rec.Scope.CIDRs = sc.GetCidrs()
		rec.Scope.Excludes = sc.GetExplicitExcludes()
	}
	return rec
}

// Active reports whether the RoE authorizes work right now (mission
// admission + plan validation, doc 01 §6.1 step 2).
func (r *roeRecord) Active(now time.Time) bool {
	if r.Status != gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE.String() {
		return false
	}
	if !r.ValidFrom.IsZero() && now.Before(r.ValidFrom) {
		return false
	}
	if !r.ValidUntil.IsZero() && now.After(r.ValidUntil) {
		return false
	}
	return true
}

// AllowsCapability checks the capability against allowed_capabilities
// (pattern form "stress.*" supported, doc 11 §3.1).
func (r *roeRecord) AllowsCapability(capability string) bool {
	for _, p := range r.AllowedCaps {
		if scope.MatchCapabilityPattern(p, capability) {
			return true
		}
	}
	return false
}

// pep_RiskFromProto avoids an import cycle (pep imports store; this file
// needs the same mapping without importing pep).
func pep_RiskFromProto(r interface{ String() string }) string {
	switch r.String() {
	case "RISK_CLASS_R0":
		return store.RiskR0
	case "RISK_CLASS_R1":
		return store.RiskR1
	case "RISK_CLASS_R2":
		return store.RiskR2
	case "RISK_CLASS_R3":
		return store.RiskR3
	}
	return ""
}
