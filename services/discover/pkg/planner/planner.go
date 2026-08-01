// Package planner expands DiscoveryOrder seeds into the task DAG (doc 02
// §2.2 planner + §2.4 recursion/budgets). Each task is the smallest
// idempotent unit: (technique, source, seed, depth). The planner rejects
// out-of-scope seeds against the gatekeeper-resolved scope (doc 02 §6.1),
// drops active techniques with ACTIVE_NOT_ALLOWED (MVP, doc 02 §8), and
// enforces max_depth / max_tasks / max_assets / time budgets.
package planner

import (
	"fmt"
	"sort"
	"time"

	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"

	"github.com/google/uuid"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// Plan is the planner output for one order.
type Plan struct {
	Tasks []model.Task
	// DroppedActive lists requested active techniques dropped per MVP
	// (recorded as ACTIVE_NOT_ALLOWED in gate reasons, doc 02 §8).
	DroppedActive []model.Technique
	// RejectedSeeds maps seed → reason (out-of-scope seeds are rejected at
	// the planner, doc 02 §6.1; exclusions always win).
	RejectedSeeds map[string]string
	// UnsupportedSeeds maps seed → reason for seed types with no MVP source
	// mapping (e.g. org).
	UnsupportedSeeds map[string]string
	// Reasons accumulates machine-readable planner notes (doc 02 §3.3).
	Reasons []string
}

// Sources maps a technique to the enabled connector names serving it (from
// the connector registry/manifest).
type Sources map[model.Technique][]string

// Planner expands orders and discovered assets.
type Planner struct {
	Sources Sources
	// TaskTimeout — per-task deadline (default 120 s, doc 02 §7.2).
	TaskTimeout time.Duration
	// Now — clock injection (tests).
	Now func() time.Time
}

// New builds a Planner.
func New(sources Sources) *Planner {
	return &Planner{Sources: sources, TaskTimeout: 120 * time.Second, Now: time.Now}
}

// seedScopeCheck validates one seed against the gatekeeper-resolved scope
// (doc 02 §6.1). Returns "" when allowed, else the rejection reason code.
func seedScopeCheck(seed model.Seed, sc *sdkscope.Scope) string {
	switch seed.Type {
	case model.SeedDomain:
		dec := sc.Evaluate(seed.Value)
		if dec.Allowed {
			return ""
		}
		if dec.Excluded {
			return "TARGET_EXCLUDED"
		}
		return "TARGET_NOT_IN_SCOPE"
	case model.SeedCIDR:
		dec := sc.Evaluate(seed.Value)
		if dec.Allowed {
			return ""
		}
		if dec.Excluded {
			return "TARGET_EXCLUDED"
		}
		return "TARGET_NOT_IN_SCOPE"
	case model.SeedCloudAccount:
		for _, ex := range sc.ExplicitExcludes {
			if ex == seed.Value {
				return "TARGET_EXCLUDED"
			}
		}
		for _, acct := range sc.CloudAccounts {
			if acct == seed.Value {
				return ""
			}
		}
		return "TARGET_NOT_IN_SCOPE"
	case model.SeedASN, model.SeedOrg:
		// Not syntactically evaluable against domains/CIDRs/cloud_accounts —
		// the produced netblocks/domains are scope-checked (and quarantined
		// when out of scope) at the reducer, which owns finding-level scope
		// enforcement (doc 02 §2.3 step 3). Explicit exclusions of the
		// literal seed value still win here.
		for _, ex := range sc.ExplicitExcludes {
			if ex == seed.Value {
				return "TARGET_EXCLUDED"
			}
		}
		return ""
	}
	return "TARGET_NOT_IN_SCOPE"
}

// techniquesForSeed maps a seed type to its applicable techniques.
func techniquesForSeed(t model.SeedType) []model.Technique {
	switch t {
	case model.SeedDomain:
		return []model.Technique{
			model.TechniquePassiveDNS, model.TechniqueCT, model.TechniqueSubdomainPassive, model.TechniqueIPNetblock,
		}
	case model.SeedASN, model.SeedCIDR:
		return []model.Technique{model.TechniqueIPNetblock}
	case model.SeedCloudAccount:
		return []model.Technique{model.TechniqueCloudCredentialed}
	case model.SeedOrg:
		return nil // no MVP source mapping — recorded as unsupported
	}
	return nil
}

// sourcesFor narrows the enabled sources for (seed, technique).
func (p *Planner) sourcesFor(seed model.Seed, t model.Technique) []string {
	enabled := p.Sources[t]
	if len(enabled) == 0 {
		return nil
	}
	var out []string
	for _, s := range enabled {
		switch seed.Type {
		case model.SeedDomain:
			if t == model.TechniqueIPNetblock && s != "rdap" {
				continue // domain RDAP only
			}
			out = append(out, s)
		case model.SeedASN:
			if s == "bgpview" || s == "ripestat" {
				out = append(out, s)
			}
		case model.SeedCIDR:
			if s == "rdap" {
				out = append(out, s)
			}
		case model.SeedCloudAccount:
			// Provider connector is chosen by the seed prefix
			// (aws:/azure:/gcp:).
			want := map[string]string{
				"aws":   "aws_resource_explorer",
				"azure": "azure_resource_graph",
				"gcp":   "gcp_cloud_asset_inventory",
			}
			provider, _, err := parseProviderPrefix(seed.Value)
			if err == nil && want[provider] == s {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseProviderPrefix(v string) (string, string, error) {
	for _, p := range []string{"aws", "azure", "gcp"} {
		if len(v) > len(p)+1 && v[:len(p)+1] == p+":" {
			return p, v[len(p)+1:], nil
		}
	}
	return "", "", fmt.Errorf("no provider prefix in %q", v)
}

// Plan expands an order. riskClass is the gatekeeper-evaluated class of the
// order's capabilities ("R0" at MVP-A); it rides on every task so workers
// enforce the token rules for that class.
func (p *Planner) Plan(order *model.DiscoveryOrder, sc *sdkscope.Scope, riskClass string) *Plan {
	plan := &Plan{
		RejectedSeeds:    map[string]string{},
		UnsupportedSeeds: map[string]string{},
	}
	deadline := p.Now().UTC().Add(p.TaskTimeout)

	// Active techniques are accepted in the schema but not implemented at
	// MVP — dropped with ACTIVE_NOT_ALLOWED (doc 02 §8).
	active := map[model.Technique]bool{}
	for _, t := range order.Techniques {
		if t.Active() {
			if !active[t] {
				active[t] = true
				plan.DroppedActive = append(plan.DroppedActive, t)
			}
		}
	}
	sort.Slice(plan.DroppedActive, func(i, j int) bool { return plan.DroppedActive[i] < plan.DroppedActive[j] })
	if len(plan.DroppedActive) > 0 {
		plan.Reasons = append(plan.Reasons, model.ReasonActiveNotAllowed)
	}

	requested := map[model.Technique]bool{}
	for _, t := range order.Techniques {
		requested[t] = true
	}

	for _, seed := range order.Seeds {
		if reason := seedScopeCheck(seed, sc); reason != "" {
			plan.RejectedSeeds[seed.Value] = reason
			continue
		}
		applicable := techniquesForSeed(seed.Type)
		if len(applicable) == 0 {
			plan.UnsupportedSeeds[seed.Value] = "SEED_TYPE_UNSUPPORTED"
			continue
		}
		for _, t := range applicable {
			if !requested[t] {
				continue
			}
			for _, src := range p.sourcesFor(seed, t) {
				plan.Tasks = append(plan.Tasks, p.newTask(order, t, src, seed, 0, deadline, riskClass))
			}
		}
	}
	return plan
}

func (p *Planner) newTask(order *model.DiscoveryOrder, t model.Technique, source string, seed model.Seed, depth int, deadline time.Time, riskClass string) model.Task {
	return model.Task{
		TaskID:    uuid.NewString(),
		OrderID:   order.OrderID,
		TenantID:  order.TenantID,
		Technique: t,
		Source:    source,
		Seed:      seed,
		Depth:     depth,
		Attempt:   1,
		Deadline:  deadline,
		ROEID:     order.Authorization.ROEID,
		RiskClass: riskClass,
	}
}

// ExpandDiscovered derives depth+1 tasks for a newly discovered in-scope
// domain asset (doc 02 §2.4 recursion), respecting max_depth. Wildcard bases
// stop recursion (doc 02 §2.4 wildcard guard). Budget checks
// (max_tasks/max_assets/time) are the caller's — it holds the order counters.
func (p *Planner) ExpandDiscovered(order *model.DiscoveryOrder, host string, depth int, sc *sdkscope.Scope, riskClass string) []model.Task {
	if depth >= order.Options.MaxDepth {
		return nil
	}
	// Wildcard guard: never expand under a wildcard base (doc 02 §2.4).
	if dec := sc.Evaluate(host); !dec.Allowed {
		return nil // reducer already quarantines; defense in depth here too
	}
	seed := model.Seed{Type: model.SeedDomain, Value: host}
	deadline := p.Now().UTC().Add(p.TaskTimeout)
	requested := map[model.Technique]bool{}
	for _, t := range order.Techniques {
		if !t.Active() {
			requested[t] = true
		}
	}
	var tasks []model.Task
	for _, t := range techniquesForSeed(model.SeedDomain) {
		if !requested[t] {
			continue
		}
		for _, src := range p.sourcesFor(seed, t) {
			tasks = append(tasks, p.newTask(order, t, src, seed, depth+1, deadline, riskClass))
		}
	}
	return tasks
}
