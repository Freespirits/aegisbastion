package planner

import (
	"strings"
	"testing"
	"time"
)

func TestPlanWebTargets(t *testing.T) {
	out, err := Plan(Input{
		TaskID: "tsk_1", Capability: CapScanWeb,
		Targets: []string{"https://a.example/app", "https://b.example"},
		Profile: ProfileQuick, MaxRequests: 1000, TokenMaxRPS: 80,
		SafeMode: true, Deadline: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(out.Jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(out.Jobs))
	}
	for _, j := range out.Jobs {
		if j.Adapter != "nuclei" {
			t.Errorf("adapter = %q, want nuclei", j.Adapter)
		}
		if j.RPS != 80 { // min(quick pacing 150, token cap 80)
			t.Errorf("rps = %d, want 80 (token cap binds)", j.RPS)
		}
		if j.RequestBudget != 500 {
			t.Errorf("budget = %d, want 500 (even split)", j.RequestBudget)
		}
		if j.Deadline.After(time.Now().Add(10 * time.Minute)) {
			t.Error("job deadline must not exceed task deadline")
		}
		if j.Profile != ProfileQuick {
			t.Errorf("profile = %q", j.Profile)
		}
	}
}

func TestPlanNetworkSplitsURLAndHosts(t *testing.T) {
	out, err := Plan(Input{
		TaskID: "tsk_2", Capability: CapScanNetwork,
		Targets: []string{"192.0.2.10", "10.0.0.0/24", "https://web.example"},
		Profile: ProfileStandard, SafeMode: true,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(out.Jobs) != 2 {
		t.Fatalf("jobs = %d, want 2 (URL skipped): %+v", len(out.Jobs), out.Jobs)
	}
	if len(out.Warnings) != 1 {
		t.Errorf("warnings = %v, want 1 for the skipped URL", out.Warnings)
	}
	for _, j := range out.Jobs {
		if j.Adapter != "nmap" || j.Ports != "top-1000" {
			t.Errorf("bad network job: %+v", j)
		}
		// standard profile → ssl-* detail scripts included
		found := false
		for _, c := range j.Checks {
			if c == "ssl-*" {
				found = true
			}
		}
		if !found {
			t.Errorf("standard profile must include ssl-* scripts: %v", j.Checks)
		}
	}
}

func TestPlanRejectsDoSChecks(t *testing.T) {
	out, err := Plan(Input{
		TaskID: "tsk_3", Capability: CapScanWeb,
		Targets:  []string{"https://a.example"},
		CheckIDs: []string{"cve-2024-3400", "dos-slowloris", "flood-udp"},
		Profile:  ProfileStandard, SafeMode: true,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(out.Jobs) != 1 {
		t.Fatalf("jobs = %d", len(out.Jobs))
	}
	for _, c := range out.Jobs[0].Checks {
		if strings.Contains(c, "dos") || strings.Contains(c, "flood") {
			t.Fatalf("DoS-class check survived planning: %v", out.Jobs[0].Checks)
		}
	}
}

func TestPlanRespectsExcludeGlobs(t *testing.T) {
	out, err := Plan(Input{
		TaskID: "tsk_4", Capability: CapScanWeb,
		Targets: []string{"https://a.example"},
		Profile: ProfileStandard, ExcludeCheckIDs: []string{"xss*"},
		SafeMode: true,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, tag := range out.Jobs[0].Tags {
		if tag == "xss" {
			t.Fatalf("excluded tag survived: %v", out.Jobs[0].Tags)
		}
	}
}

func TestPlanErrors(t *testing.T) {
	if _, err := Plan(Input{TaskID: "t", Capability: CapScanWeb}); err == nil {
		t.Error("want error for empty targets")
	}
	if _, err := Plan(Input{TaskID: "t", Capability: CapScanWeb, Targets: []string{"https://a"}, Profile: "weird"}); err == nil {
		t.Error("want error for unknown profile")
	}
	if _, err := Plan(Input{TaskID: "t", Capability: CapScanWeb, Targets: []string{"192.0.2.1"}}); err == nil {
		t.Error("want error when nothing is plannable (host target for web scan)")
	}
	if _, err := Plan(Input{TaskID: "t", Capability: CapRevalidate, Targets: []string{"x"}}); err == nil {
		t.Error("revalidate is not scanner-planned")
	}
}
