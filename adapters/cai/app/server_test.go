package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisbastion/aegisbastion/adapters/internal/health"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerfake"
)

func testServer(t *testing.T) (*httptest.Server, *plannerfake.Server) {
	t.Helper()
	fake := plannerfake.New()
	client, cleanup := fake.Client()
	t.Cleanup(cleanup)
	s := NewServer(StubPlanner{}, client)
	s.Mount("/", health.Handler("aegisbastion-cai-adapter", nil))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, fake
}

// The MVP-A acceptance loop: intent in → clearly-marked deterministic stub
// plan out → submitted to the PlannerService → verdict returned.
func TestIntentFlow(t *testing.T) {
	ts, fake := testServer(t)

	body := `{"mission_id":"msn_1","objective":"map acme.com","targets":["acme.com"]}`
	resp, err := http.Post(ts.URL+"/v1/intents", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/intents: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var out intentResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	plan := out.Plan.(map[string]any)
	if !strings.HasPrefix(plan["planId"].(string), "pln_caistub_") {
		t.Errorf("planId = %v, want stub-marked", plan["planId"])
	}
	if out.Submission == nil || out.Submission.Decision != "ACCEPTED" {
		t.Errorf("submission = %+v, want ACCEPTED (fake registry covers the stub capabilities)", out.Submission)
	}
	if len(out.Submission.TaskVerdicts) != 5 {
		t.Errorf("verdicts = %d, want 5", len(out.Submission.TaskVerdicts))
	}
	// The Orchestrator side received a CAI-tagged plan.
	if len(fake.Plans()) != 1 || fake.Plans()[0].GetSubmittedBy().String() != "COMMANDER_CAI" {
		t.Fatalf("plan not submitted as CAI: %+v", fake.Plans())
	}

	// Determinism over the wire: the identical intent yields the identical
	// plan id.
	resp2, err := http.Post(ts.URL+"/v1/intents", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/intents (replay): %v", err)
	}
	defer resp2.Body.Close()
	var out2 intentResponse
	if err := json.NewDecoder(resp2.Body).Decode(&out2); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if out2.Plan.(map[string]any)["planId"] != plan["planId"] {
		t.Errorf("replay produced a different plan id: %v vs %v",
			out2.Plan.(map[string]any)["planId"], plan["planId"])
	}
}

func TestIntentValidation(t *testing.T) {
	ts, _ := testServer(t)
	resp, err := http.Post(ts.URL+"/v1/intents", "application/json", strings.NewReader(`{"mission_id":"msn_1"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("target-less intent: status = %d, want 400", resp.StatusCode)
	}
}

// POST /v1/plans is the surface the real CAI will call with its own plans;
// it must already work in stub mode.
func TestSubmitPlanEndpoint(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"mission_id":"msn_1","tasks":[{"task_key":"ct","capability":"recon.ct","risk_class":"R0","targets":["acme.com"]}]}`
	resp, err := http.Post(ts.URL+"/v1/plans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/plans: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		PlanID   string `json:"plan_id"`
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Decision != "ACCEPTED" || !strings.HasPrefix(out.PlanID, "pln_") {
		t.Errorf("out = %+v", out)
	}
}

func TestReadEndpoints(t *testing.T) {
	ts, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/v1/missions/msn_1")
	if err != nil {
		t.Fatalf("GET mission: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mission status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "msn_1") {
		t.Errorf("mission response = %s", raw)
	}

	resp2, err := http.Get(ts.URL + "/v1/capabilities?name_prefix=recon.")
	if err != nil {
		t.Fatalf("GET capabilities: %v", err)
	}
	defer resp2.Body.Close()
	raw2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(raw2), "recon.passive_dns") {
		t.Errorf("capabilities response = %s", raw2)
	}

	resp3, err := http.Get(ts.URL + "/v1/capabilities?max_risk_class=R9")
	if err != nil {
		t.Fatalf("GET capabilities bad risk: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("bad risk filter: status = %d, want 400", resp3.StatusCode)
	}
}

func TestHealthEndpoints(t *testing.T) {
	ts, _ := testServer(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, resp.StatusCode)
		}
	}
}
