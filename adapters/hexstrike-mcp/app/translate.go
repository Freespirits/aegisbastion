package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// ExecutorID is reported as TaskResult.agent_id for adapter-side executions.
// It is not a registered platform agent id — it identifies the commander
// adapter as the executor of record for these calls.
const ExecutorID = "hexstrike-mcp-adapter"

// ToolMapping binds one platform capability to one HexStrike MCP tool. The
// mapping is static and explicit on purpose: the adapter may only request
// capabilities, and only the capabilities listed here can be translated into
// local HexStrike tool calls. Anything else is refused.
type ToolMapping struct {
	// Tool is the HexStrike MCP tool name (hexstrike_mcp.py).
	Tool string
	// Endpoint is the hexstrike_server.py API path.
	Endpoint string
	// TargetKey is the argument name that carries the target ("target" or "url").
	TargetKey string
	// Defaults are the tool's default arguments; string-valued keys in the
	// TaskSpec params override them.
	Defaults map[string]string
}

// capabilityTools is the static capability → HexStrike tool table. Capability
// names follow the platform registry style (registry.proto / detect.proto).
var capabilityTools = map[string]ToolMapping{
	"recon.port_scan": {
		Tool: "nmap_scan", Endpoint: "api/tools/nmap", TargetKey: "target",
		Defaults: map[string]string{"scan_type": "-sV", "ports": "", "additional_args": ""},
	},
	"detect.scan.network": {
		Tool: "nmap_scan", Endpoint: "api/tools/nmap", TargetKey: "target",
		Defaults: map[string]string{"scan_type": "-sV", "ports": "", "additional_args": ""},
	},
	"detect.scan.web": {
		Tool: "nuclei_scan", Endpoint: "api/tools/nuclei", TargetKey: "target",
		Defaults: map[string]string{"severity": "", "tags": "", "template": "", "additional_args": ""},
	},
	"web.dirbust": {
		Tool: "gobuster_scan", Endpoint: "api/tools/gobuster", TargetKey: "url",
		Defaults: map[string]string{"mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": ""},
	},
	"web.nikto": {
		Tool: "nikto_scan", Endpoint: "api/tools/nikto", TargetKey: "target",
		Defaults: map[string]string{"additional_args": ""},
	},
	"web.sqlmap": {
		Tool: "sqlmap_scan", Endpoint: "api/tools/sqlmap", TargetKey: "url",
		Defaults: map[string]string{"data": "", "additional_args": ""},
	},
}

// ToolCall is one concrete HexStrike invocation derived from a TaskSpec.
type ToolCall struct {
	Tool     string
	Endpoint string
	Target   string
	Args     map[string]any
}

// TranslateTask converts an accepted TaskSpec into one ToolCall per target.
// It fails for capabilities outside the static mapping — the adapter can
// only request capabilities; it cannot invent executions for ones it does
// not understand.
func TranslateTask(spec *platformv1.TaskSpec) ([]ToolCall, error) {
	if spec == nil {
		return nil, fmt.Errorf("translate: nil task spec")
	}
	m, ok := capabilityTools[spec.GetCapability()]
	if !ok {
		known := make([]string, 0, len(capabilityTools))
		for k := range capabilityTools {
			known = append(known, k)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("translate: no HexStrike tool mapping for capability %q (mapped: %s)",
			spec.GetCapability(), strings.Join(known, ", "))
	}
	if len(spec.GetTargets()) == 0 {
		return nil, fmt.Errorf("translate: task %q has no targets", spec.GetTaskKey())
	}

	calls := make([]ToolCall, 0, len(spec.GetTargets()))
	for _, target := range spec.GetTargets() {
		args := map[string]any{}
		for k, v := range m.Defaults {
			args[k] = v
		}
		// Param overrides: only string params override, and only keys the tool
		// actually takes — a commander cannot smuggle arbitrary arguments into
		// a tool call by adding unknown params.
		params := spec.GetParams().GetFields()
		for k := range m.Defaults {
			if pv, ok := params[k]; ok {
				if s := pv.GetStringValue(); s != "" {
					args[k] = s
				}
			}
		}
		args[m.TargetKey] = target
		calls = append(calls, ToolCall{Tool: m.Tool, Endpoint: m.Endpoint, Target: target, Args: args})
	}
	return calls, nil
}

// MapResult folds per-target HexStrike tool results into a platform
// TaskResult (doc 01 §5.7). SUCCEEDED requires every per-target call to
// report success; any failure makes the task FAILED with the first error in
// the error field. targets_touched is the honest list of targets the calls
// were issued for — in mock mode no network contact happened, and the
// summary's "mock" flag says so.
func MapResult(spec *platformv1.TaskSpec, calls []ToolCall, results []map[string]any, callErrs []error, started, finished time.Time) *platformv1.TaskResult {
	status := platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED
	firstErr := ""

	perTarget := make([]any, 0, len(calls))
	for i, call := range calls {
		entry := map[string]any{"target": call.Target, "tool": call.Tool}
		switch {
		case callErrs[i] != nil:
			status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
			entry["success"] = false
			entry["error"] = callErrs[i].Error()
			if firstErr == "" {
				firstErr = fmt.Sprintf("%s: %v", call.Target, callErrs[i])
			}
		default:
			ok, _ := results[i]["success"].(bool)
			entry["success"] = ok
			entry["result"] = results[i]
			if !ok {
				status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
				if firstErr == "" {
					firstErr = fmt.Sprintf("%s: tool %s reported failure", call.Target, call.Tool)
				}
			}
		}
		perTarget = append(perTarget, entry)
	}

	summary, err := structpb.NewStruct(map[string]any{
		"task_key":   spec.GetTaskKey(),
		"capability": spec.GetCapability(),
		"results":    perTarget,
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
