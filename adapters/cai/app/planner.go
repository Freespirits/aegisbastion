// Package app is the CAI commander adapter (doc 01 §4.1, §7.1) — a
// bring-your-own-license (BYO) integration.
//
// LICENSING: CAI (Alias Robotics S.L.) is licensed
// RESEARCH-USE ONLY. Commercial or production use of this adapter with a real
// CAI backend requires the operator to hold a valid Alias Robotics commercial
// license. AegisBastion vendors NO CAI code: this module contains only a
// deterministic demo planner (CAI_MODE=stub, the default) plus the
// REST/PlannerService plumbing around it.
//
// In stub mode the adapter accepts mission intents over REST and returns a
// fixed, clearly-marked STUB plan — a deterministic Discover passive order —
// so the end-to-end flow (mission → plan → verdict → replan) is exercisable
// without any CAI installation.
//
// The seam for a real integration is the Planner interface: a customer with
// a valid CAI license plugs their integration in as another Planner
// implementation that calls their licensed CAI deployment and maps its
// output to a TaskPlan — no other adapter code changes (doc 01 §14 Later
// item 1: "CAI adapter productionized").
package app

import (
	"encoding/json"
	"fmt"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aegisbastion/aegisbastion/adapters/internal/ids"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// StubGenerator identifies stub-generated plans in every task's params, so a
// stub plan can never be mistaken for real CAI output.
const StubGenerator = "cai-stub-v1"

// Intent is a mission intent as POSTed to /v1/intents. In the real
// integration this is what CAI would produce from its strategic reasoning;
// here it is the operator/test harness speaking intent directly.
type Intent struct {
	// MissionID is the mission this intent plans for (required).
	MissionID string `json:"mission_id"`
	// Objective is the free-text mission objective (carried into the plan
	// for audit readability).
	Objective string `json:"objective"`
	// Targets are the seed targets (required, ≥1). Sorted before planning so
	// target ordering in the request cannot change the generated plan.
	Targets []string `json:"targets"`
}

// Planner turns a mission intent into a TaskPlan. THIS IS THE INTEGRATION
// SEAM: a customer's licensed CAI integration plugs in here as another
// implementation — the REST surface and PlannerService submission path stay
// unchanged.
//
// LICENSE REQUIREMENT: any implementation that talks to a real CAI backend
// (Alias Robotics S.L. — research-use only) may be used
// commercially or in production ONLY by operators holding a valid Alias
// Robotics commercial license. That integration is bring-your-own: it is
// installed and licensed by the customer, never vendored into AegisBastion.
type Planner interface {
	PlanMission(in Intent) (*platformv1.TaskPlan, error)
}

// NewPlanner selects the planner for the configured CAI_MODE. "stub" (the
// default) is the built-in demo planner — pure deterministic AegisBastion
// code, no CAI involved. Any other mode is a hard config error: the adapter
// fails fast instead of silently running the wrong brain, and a licensed
// customer CAI backend is wired in as a Planner implementation (see the
// Planner interface above), not as a CAI_MODE string shipped here.
func NewPlanner(mode string) (Planner, error) {
	switch mode {
	case "stub":
		return StubPlanner{}, nil
	default:
		return nil, fmt.Errorf("CAI_MODE=%q is not supported (supported: stub); "+
			"a real CAI backend requires a valid Alias Robotics commercial license "+
			"and plugs in behind the app.Planner interface (BYO — no CAI code is vendored)", mode)
	}
}

// StubPlanner is the default demo planner. Its output is fully deterministic: the
// same intent always yields the same plan, including plan_id and
// idempotency_key (both derived from a hash of the canonical intent), so
// replays are idempotent and the end-to-end flow is testable.
type StubPlanner struct{}

// stubTask is one stage of the fixed Discover passive order.
type stubTask struct {
	key        string
	capability string
	technique  string
	dependsOn  []string
}

// discoverPassiveOrder is the fixed stub DAG: the passive-only Discover
// techniques (doc 02 §2.3 technique set, all R0 — no target contact), in
// their natural dependency order. Capability names follow the platform
// registry style; the Discover agent registers the authoritative set and the
// Orchestrator rejects anything unregistered — exactly the flow the stub
// exists to exercise.
var discoverPassiveOrder = []stubTask{
	{key: "discover-passive-dns", capability: "recon.passive_dns", technique: "passive_dns"},
	{key: "discover-ct", capability: "recon.ct", technique: "ct", dependsOn: []string{"discover-passive-dns"}},
	{key: "discover-subdomain-passive", capability: "recon.subdomain_passive", technique: "subdomain_passive", dependsOn: []string{"discover-passive-dns"}},
	{key: "discover-ip-netblock", capability: "recon.ip_netblock", technique: "ip_netblock", dependsOn: []string{"discover-passive-dns"}},
	{key: "discover-cloud-credentialed", capability: "recon.cloud_credentialed", technique: "cloud_credentialed", dependsOn: []string{"discover-ip-netblock"}},
}

// PlanMission implements Planner.
func (StubPlanner) PlanMission(in Intent) (*platformv1.TaskPlan, error) {
	if in.MissionID == "" {
		return nil, fmt.Errorf("intent: mission_id is required")
	}
	if len(in.Targets) == 0 {
		return nil, fmt.Errorf("intent: targets must contain at least one seed target")
	}
	targets := make([]string, len(in.Targets))
	copy(targets, in.Targets)
	sort.Strings(targets)

	// Deterministic identity: hash the canonical intent (sorted targets) so
	// identical intents produce identical plans.
	seed, err := json.Marshal(map[string]any{
		"mission_id": in.MissionID,
		"objective":  in.Objective,
		"targets":    targets,
		"generator":  StubGenerator,
	})
	if err != nil {
		return nil, fmt.Errorf("intent: canonicalize: %v", err)
	}
	planID := ids.Deterministic("pln_caistub", seed)
	idem := fmt.Sprintf("cai:%s:plan:%s", in.MissionID, ids.Hash12(seed))

	tasks := make([]*platformv1.TaskSpec, 0, len(discoverPassiveOrder))
	for i, st := range discoverPassiveOrder {
		params, err := structpb.NewStruct(map[string]any{
			// STUB MARKER: these fields make the plan's provenance explicit
			// in every audit record and dashboard view.
			"stub":      true,
			"generator": StubGenerator,
			"plan_note": "STUB PLAN — deterministic Discover passive order; demo planner only, no real CAI backend is integrated (BYO)",
			"technique": st.technique,
			"order":     i + 1,
			"objective": in.Objective,
		})
		if err != nil {
			return nil, fmt.Errorf("intent: task %s params: %v", st.key, err)
		}
		tasks = append(tasks, &platformv1.TaskSpec{
			TaskKey:    st.key,
			Capability: st.capability,
			RiskClass:  platformv1.RiskClass_RISK_CLASS_R0,
			Targets:    targets,
			Params:     params,
			DependsOn:  st.dependsOn,
			TimeoutS:   900,
			MaxRetries: 2,
		})
	}

	return &platformv1.TaskPlan{
		PlanId:         planID,
		MissionId:      in.MissionID,
		SubmittedBy:    platformv1.Commander_COMMANDER_CAI,
		IdempotencyKey: idem,
		Tasks:          tasks,
	}, nil
}
