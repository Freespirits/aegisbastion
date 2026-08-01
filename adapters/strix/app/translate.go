package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aegisbastion/aegisbastion/adapters/strix/strixcli"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// ExecutorID is reported as TaskResult.agent_id for adapter-side executions.
// It is not a registered platform agent id — it identifies the commander
// adapter as the executor of record for these scans.
const ExecutorID = "strix-adapter"

// ScanMapping binds one platform capability to one Strix scan profile. The
// mapping is static and explicit on purpose: the adapter may only request
// capabilities, and only the capabilities listed here can be translated into
// Strix invocations. Anything else is refused.
type ScanMapping struct {
	// Instruction is the strix --instruction steering text: what class of
	// hunt the autonomous agents should perform for this capability.
	Instruction string
	// ScanMode is the strix --scan-mode value (quick | standard | deep).
	ScanMode string
	// ParamKeys are the TaskSpec params this mapping honours ("instruction"
	// overrides/extends Instruction, "scan_mode" overrides ScanMode). Only
	// these keys may leak from a TaskSpec into a Strix invocation.
	ParamKeys []string
}

// capabilityScans is the static capability → Strix scan table. Strix's
// strengths are autonomous web/API vulnerability hunting with
// proof-of-exploit validation, so it fills R2 detect-class scans and R1
// recon. Capability names follow the platform registry style
// (registry.proto / detect.proto).
//
// CAPABILITY MAP (marker for the audit — keep in sync with README.md):
//
//	recon.port_scan   R1 → quick recon-only scan
//	recon.web_surface R1 → quick web-surface enumeration
//	detect.scan.web   R2 → standard autonomous web pentest, PoC-validated
//	detect.scan.api   R2 → standard autonomous API pentest, PoC-validated
//	detect.scan.full  R2 → deep full-surface pentest, PoC-validated
var capabilityScans = map[string]ScanMapping{
	"recon.port_scan": {
		Instruction: "Reconnaissance only: enumerate open ports, services and web technologies on the target. " +
			"Do not attempt exploitation; report findings as informational.",
		ScanMode:  "quick",
		ParamKeys: []string{"instruction", "scan_mode"},
	},
	"recon.web_surface": {
		Instruction: "Reconnaissance only: enumerate the target's web attack surface (hosts, endpoints, " +
			"technologies, entry points). Do not attempt exploitation; report findings as informational.",
		ScanMode:  "quick",
		ParamKeys: []string{"instruction", "scan_mode"},
	},
	"detect.scan.web": {
		Instruction: "Autonomous web application penetration test: hunt for OWASP-class vulnerabilities " +
			"(XSS, SQLi, SSRF, auth bypass, IDOR, file upload). Validate every finding with a working " +
			"proof-of-exploit before reporting it.",
		ScanMode:  "standard",
		ParamKeys: []string{"instruction", "scan_mode"},
	},
	"detect.scan.api": {
		Instruction: "Autonomous API security assessment: enumerate endpoints, test authentication and " +
			"authorization, injection, and data exposure. Validate every finding with a working " +
			"proof-of-exploit before reporting it.",
		ScanMode:  "standard",
		ParamKeys: []string{"instruction", "scan_mode"},
	},
	"detect.scan.full": {
		Instruction: "Deep full-surface penetration test: reconnaissance, vulnerability hunting and " +
			"exploitation across the whole target. Validate every finding with a working " +
			"proof-of-exploit before reporting it.",
		ScanMode:  "deep",
		ParamKeys: []string{"instruction", "scan_mode"},
	},
}

// TranslateTask converts an accepted TaskSpec into one ScanRequest per
// target. It fails for capabilities outside the static mapping — the adapter
// can only request capabilities; it cannot invent executions for ones it
// does not understand.
func TranslateTask(spec *platformv1.TaskSpec) ([]strixcli.ScanRequest, error) {
	if spec == nil {
		return nil, fmt.Errorf("translate: nil task spec")
	}
	m, ok := capabilityScans[spec.GetCapability()]
	if !ok {
		known := make([]string, 0, len(capabilityScans))
		for k := range capabilityScans {
			known = append(known, k)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("translate: no Strix scan mapping for capability %q (mapped: %s)",
			spec.GetCapability(), strings.Join(known, ", "))
	}
	if len(spec.GetTargets()) == 0 {
		return nil, fmt.Errorf("translate: task %q has no targets", spec.GetTaskKey())
	}

	// Param overrides: only string params, and only keys the mapping actually
	// honours — a commander cannot smuggle arbitrary arguments into a Strix
	// invocation by adding unknown params.
	instruction := m.Instruction
	scanMode := m.ScanMode
	params := spec.GetParams().GetFields()
	for _, k := range m.ParamKeys {
		pv, ok := params[k]
		if !ok {
			continue
		}
		s := pv.GetStringValue()
		if s == "" {
			continue
		}
		switch k {
		case "instruction":
			instruction = s
		case "scan_mode":
			switch s {
			case "quick", "standard", "deep":
				scanMode = s
			default:
				return nil, fmt.Errorf("translate: task %q: invalid scan_mode param %q (want quick|standard|deep)",
					spec.GetTaskKey(), s)
			}
		}
	}

	calls := make([]strixcli.ScanRequest, 0, len(spec.GetTargets()))
	for _, target := range spec.GetTargets() {
		calls = append(calls, strixcli.ScanRequest{
			TaskKey:     spec.GetTaskKey(),
			Target:      target,
			Instruction: instruction,
			ScanMode:    scanMode,
		})
	}
	return calls, nil
}

// MapResult folds per-target Strix scan results into a platform TaskResult
// (doc 01 §5.7). SUCCEEDED requires every per-target scan to have run to
// completion; any failure makes the task FAILED with the first error in the
// error field. Findings are carried in the summary per target, severity
// counts included. targets_touched is the honest list of targets the scans
// were issued for — in mock mode no target contact happened, and every
// finding's "mock" marker says so.
func MapResult(spec *platformv1.TaskSpec, calls []strixcli.ScanRequest, results []*strixcli.ScanResult, callErrs []error, started, finished time.Time) *platformv1.TaskResult {
	status := platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED
	firstErr := ""
	// structpb only accepts map[string]any, so counts accumulate as any-values.
	severityCounts := map[string]any{}
	findingTotal := 0

	perTarget := make([]any, 0, len(calls))
	for i, call := range calls {
		entry := map[string]any{"target": call.Target, "scan_mode": call.ScanMode}
		switch {
		case callErrs[i] != nil:
			status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
			entry["success"] = false
			entry["error"] = callErrs[i].Error()
			if firstErr == "" {
				firstErr = fmt.Sprintf("%s: %v", call.Target, callErrs[i])
			}
		default:
			entry["success"] = results[i].Success
			entry["mock"] = results[i].Mock
			entry["note"] = results[i].Note
			if results[i].RunDir != "" {
				entry["run_dir"] = results[i].RunDir
			}
			findings := make([]any, 0, len(results[i].Findings))
			for _, f := range results[i].Findings {
				findings = append(findings, map[string]any{
					"id":              f.ID,
					"title":           f.Title,
					"severity":        f.Severity,
					"target":          f.Target,
					"description":     f.Description,
					"poc_description": f.POCDescription,
					"remediation":     f.Remediation,
					"cve":             f.CVE,
					"cwe":             f.CWE,
					"cvss_score":      f.CVSSScore,
					"mock":            results[i].Mock,
				})
				sev := strings.ToLower(f.Severity)
				n, _ := severityCounts[sev].(int)
				severityCounts[sev] = n + 1
				findingTotal++
			}
			entry["findings"] = findings
			if !results[i].Success {
				status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
				if firstErr == "" {
					firstErr = fmt.Sprintf("%s: strix scan reported failure", call.Target)
				}
			}
		}
		perTarget = append(perTarget, entry)
	}

	summary, err := structpb.NewStruct(map[string]any{
		"task_key":        spec.GetTaskKey(),
		"capability":      spec.GetCapability(),
		"results":         perTarget,
		"finding_count":   findingTotal,
		"severity_counts": severityCounts,
	})
	if err != nil {
		// structpb.NewStruct only fails on unrepresentable values; perTarget
		// is plain JSON-shaped data. Fall back to a minimal summary rather
		// than dropping the result.
		summary, _ = structpb.NewStruct(map[string]any{
			"task_key":   spec.GetTaskKey(),
			"capability": spec.GetCapability(),
			"error":      "summary encoding failed",
		})
	}

	return &platformv1.TaskResult{
		TaskId:     spec.GetTaskKey(), // commander-local correlation id; the Orchestrator owns tsk_ ids
		AgentId:    ExecutorID,
		Status:     status,
		StartedAt:  timestamppb.New(started),
		FinishedAt: timestamppb.New(finished),
		Summary:    summary,
		Metrics: &platformv1.TaskResultMetrics{
			RequestsSent:   uint64(len(calls)),
			TargetsTouched: spec.GetTargets(),
		},
		Error: firstErr,
	}
}
