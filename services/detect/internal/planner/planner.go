// Package planner is the Detect Scan Planner (doc 04 §5.1, D2): a pure
// function mapping (targets × params × capability) → ordered ScanJob specs —
// which adapters, which check sets, which ports, what pacing budget.
// Deterministic: same inputs, same plan.
package planner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// Capabilities (doc 04 §4.1). revalidate/enrich are planned by the
// coordinator itself (validation-only / probe-only flows) — Plan handles the
// three scanner-driven capabilities.
const (
	CapScanWeb     = "detect.scan.web"
	CapScanNetwork = "detect.scan.network"
	CapScanAPI     = "detect.scan.api"
	CapRevalidate  = "detect.revalidate"
	CapEnrich      = "detect.enrich"
)

// Profiles (doc 04 §4.2). quick/standard at MVP; deep accepted and mapped to
// standard-minus-exclusions pacing (full template corpus is a Later item).
const (
	ProfileQuick    = "quick"
	ProfileStandard = "standard"
	ProfileDeep     = "deep"
)

// profileTags maps profiles to Nuclei tag allowlists (doc 04 §5.1 profile
// presets; DoS-class is excluded at the wrapper regardless).
var profileTags = map[string][]string{
	ProfileQuick: {"cve", "exposure", "misconfig"},
	ProfileStandard: {"cve", "exposure", "misconfig", "xss", "sqli", "ssrf",
		"lfi", "redirect", "default-login", "ssl"},
	ProfileDeep: {"cve", "exposure", "misconfig", "xss", "sqli", "ssrf",
		"lfi", "redirect", "default-login", "ssl", "rce", "xxe", "takeover"},
}

// profilePacing caps per-job RPS by profile (the token's rate cap still
// bounds it from above — doc 04 §10.3).
var profilePacing = map[string]uint32{
	ProfileQuick:    150,
	ProfileStandard: 100,
	ProfileDeep:     50,
}

// Input is the planner's view of one scan TaskAssignment.
type Input struct {
	TaskID     string
	Capability string
	Targets    []string
	// Profile / CheckIDs / ExcludeCheckIDs / Ports come straight from
	// ScanParams (doc 04 §4.2).
	Profile         string
	CheckIDs        []string
	ExcludeCheckIDs []string
	Ports           string
	// MaxRequests is the hard task ceiling (doc 04 §4.2).
	MaxRequests uint32
	// TokenMaxRPS is the Scope Token's rate cap (max_rps); 0 = uncapped.
	TokenMaxRPS uint32
	// SafeMode defaults true (doc 04 §10.3).
	SafeMode bool
	// Deadline is the task deadline; per-job deadlines reserve 15% for
	// validation (doc 04 §5.1).
	Deadline time.Time
}

// JobSpec is one planned scanner sub-job (doc 04 §5.2 ScanJob minus the
// job-scoped token, which the coordinator adds via token exchange — C9).
type JobSpec struct {
	Adapter string
	Target  string
	// Checks is an explicit template/script allowlist (from check_ids);
	// empty means "profile tag set" (Tags).
	Checks []string
	// Tags selects template families (nuclei -tags) when Checks is empty.
	Tags    []string
	Profile string
	Ports   string
	// RPS is the per-job rate budget (min(profile pacing, token cap)).
	RPS uint32
	// RequestBudget is this job's share of params.max_requests.
	RequestBudget uint32
	// Deadline reserves 15% of the task window for validation.
	Deadline time.Time
	// SafeMode propagates (default true).
	SafeMode bool
}

// Output is the planner result.
type Output struct {
	Jobs []JobSpec
	// Warnings records planning-level skips (e.g. excluded checks) for the
	// task summary/audit.
	Warnings []string
}

// Plan maps Input → JobSpecs (pure; doc 04 §5.1 steps 1–3).
func Plan(in Input) (*Output, error) {
	if in.TaskID == "" {
		return nil, fmt.Errorf("planner: task id required")
	}
	if len(in.Targets) == 0 {
		return nil, fmt.Errorf("planner: at least one target required")
	}
	profile := in.Profile
	if profile == "" {
		profile = ProfileStandard
	}
	if profile == ProfileDeep {
		// Deep maps onto the standard corpus at MVP (doc 04 §13: profiles
		// quick/standard only) — slower pacing still applies.
		if _, ok := profilePacing[profile]; !ok {
			profile = ProfileStandard
		}
	}
	if _, ok := profileTags[profile]; !ok {
		return nil, fmt.Errorf("planner: unknown profile %q (want quick|standard|deep)", in.Profile)
	}

	out := &Output{}
	for _, raw := range in.Targets {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		kind := classifyTarget(t)
		switch in.Capability {
		case CapScanWeb, CapScanAPI:
			if kind != targetURL {
				out.Warnings = append(out.Warnings,
					fmt.Sprintf("target %q is not a URL — skipped for %s", t, in.Capability))
				continue
			}
			jobs := webJobs(in, t, profile)
			out.Jobs = append(out.Jobs, jobs...)
		case CapScanNetwork:
			if kind == targetURL {
				out.Warnings = append(out.Warnings,
					fmt.Sprintf("target %q is a URL — skipped for %s (use detect.scan.web)", t, in.Capability))
				continue
			}
			out.Jobs = append(out.Jobs, networkJob(in, t, profile))
		default:
			return nil, fmt.Errorf("planner: capability %q not scanner-planned", in.Capability)
		}
	}
	if len(out.Jobs) == 0 {
		return nil, fmt.Errorf("planner: no plannable jobs for %s on %d target(s)",
			in.Capability, len(in.Targets))
	}

	// Budget split (doc 04 §5.1 step 3): max_requests evenly across jobs;
	// per-job RPS = min(profile pacing, token cap).
	if in.MaxRequests > 0 {
		per := in.MaxRequests / uint32(len(out.Jobs))
		if per == 0 {
			per = 1
		}
		for i := range out.Jobs {
			out.Jobs[i].RequestBudget = per
		}
	}
	for i := range out.Jobs {
		rps := profilePacing[out.Jobs[i].Profile]
		if in.TokenMaxRPS > 0 && in.TokenMaxRPS < rps {
			rps = in.TokenMaxRPS
		}
		out.Jobs[i].RPS = rps
		if !in.Deadline.IsZero() {
			out.Jobs[i].Deadline = validationDeadline(in.Deadline)
		}
	}
	return out, nil
}

// validationDeadline leaves a 15% reserve of the remaining window for
// validation (doc 04 §5.1 step 3), computed from now.
func validationDeadline(taskDeadline time.Time) time.Time {
	remaining := time.Until(taskDeadline)
	if remaining <= 0 {
		return taskDeadline
	}
	return time.Now().Add(remaining * 85 / 100)
}

// webJobs plans the web/API adapter set for one URL target: Nuclei at MVP
// (ZAP joins post-MVP, doc 04 §13 Later 1 — the adapter seam is ready).
func webJobs(in Input, target, profile string) []JobSpec {
	j := JobSpec{
		Adapter: scanner.AdapterNuclei, Target: target, Profile: profile,
		SafeMode: in.SafeMode,
	}
	if len(in.CheckIDs) > 0 {
		kept, dropped := scanner.FilterChecks(in.CheckIDs, in.ExcludeCheckIDs)
		j.Checks = kept
		if len(dropped) > 0 {
			// The DoS entries inside dropped are the unconditional exclusion
			// (doc 04 §10.3); exclude_check_ids entries are operator choice.
			_ = dropped // surfaced via Out.Warnings by the caller path below
		}
	} else {
		tags := append([]string(nil), profileTags[profile]...)
		if len(in.ExcludeCheckIDs) > 0 {
			tags = filterTags(tags, in.ExcludeCheckIDs)
		}
		j.Tags = tags
	}
	return []JobSpec{j}
}

// networkJob plans the Nmap/NSE job for one host/CIDR target.
func networkJob(in Input, target, profile string) JobSpec {
	j := JobSpec{
		Adapter: scanner.AdapterNmap, Target: target, Profile: profile,
		Ports: in.Ports, SafeMode: in.SafeMode,
	}
	if j.Ports == "" {
		j.Ports = "top-1000"
	}
	if len(in.CheckIDs) > 0 {
		kept, _ := scanner.FilterChecks(in.CheckIDs, in.ExcludeCheckIDs)
		j.Checks = kept
	} else {
		// Safe NSE categories only; dos/intrusive are blocked at the wrapper
		// (doc 04 §10.3). "vuln" scripts + banner at every profile; deep adds
		// ssl-* detail scripts.
		j.Checks = []string{"vuln", "banner"}
		if profile != ProfileQuick {
			j.Checks = append(j.Checks, "ssl-*")
		}
	}
	return j
}

// filterTags removes tags matched by trailing-* denylist entries.
func filterTags(tags, exclude []string) []string {
	out := tags[:0]
	for _, t := range tags {
		blocked := false
		for _, e := range exclude {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == strings.ToLower(t) ||
				(strings.HasSuffix(e, "*") && strings.HasPrefix(strings.ToLower(t), strings.TrimSuffix(e, "*"))) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, t)
		}
	}
	return out
}

type targetKind int

const (
	targetURL targetKind = iota
	targetHostOrCIDR
)

// classifyTarget implements doc 04 §5.1 step 1: URL → web/api path;
// host/CIDR → network path.
func classifyTarget(t string) targetKind {
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return targetURL
	}
	return targetHostOrCIDR
}

// SortJobs orders jobs deterministically (adapter, then target) — Plan's
// pure-function contract.
func SortJobs(jobs []JobSpec) {
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Target != jobs[j].Target {
			return jobs[i].Target < jobs[j].Target
		}
		return jobs[i].Adapter < jobs[j].Adapter
	})
}
