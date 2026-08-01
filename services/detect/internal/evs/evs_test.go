package evs

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// devPrivateKeyHex signs test packs (the local-dev keypair; never production).
const devPrivateKeyHex = "799cc5710b7024c340897171c24443777717787af148488ac3af16c5f49bbbbf0d684b856e2cc0e3540cd58f11383cc2384b4b9695feea353770ea176ae2a259"

func devKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	privRaw, err := hex.DecodeString(devPrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.PrivateKey(privRaw)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func TestAllowlist(t *testing.T) {
	a := NewAllowlist([]string{
		"https://api.acme.com/login",
		"10.0.0.0/24",
		"192.168.1.10",
		"host.example:8443",
	})
	cases := []struct {
		hostPort string
		want     bool
	}{
		{"api.acme.com:443", true},
		{"api.acme.com", true},
		{"deep.api.acme.com:443", true}, // subdomain of an allowed host
		{"acme.com:443", false},         // parent of allowed host NOT covered
		{"evil.com:443", false},
		{"10.0.0.7:80", true},
		{"10.0.1.7:80", false},
		{"192.168.1.10:22", true},
		{"192.168.1.11:22", false},
		{"host.example:8443", true},
		{"host.example:9443", true}, // host allowed; pin is an additional allow
		{"", false},
	}
	for _, tc := range cases {
		if got := a.Allows(tc.hostPort); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.hostPort, got, tc.want)
		}
	}
}

func TestAllowlistDenyAllDefault(t *testing.T) {
	a := NewAllowlist(nil)
	if a.Allows("anything.example:443") {
		t.Fatal("empty allowlist must deny everything")
	}
}

func TestProxyRefusesOutOfScope(t *testing.T) {
	var denies []DenyEvent
	p := NewProxy(NewAllowlist([]string{"127.0.0.1"}), nil)
	p.OnDeny = func(e DenyEvent) { denies = append(denies, e) }
	proxyURL, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())

	// Out-of-scope host → 403 + deny event (doc 04 §14 acceptance test 2).
	client := HTTPClient(proxyURL, 5*time.Second)
	req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if len(denies) != 1 || !strings.Contains(denies[0].HostPort, "169.254.169.254") {
		t.Fatalf("deny event missing: %+v", denies)
	}
	_, deniedN := p.Stats()
	if deniedN != 1 {
		t.Fatalf("deny count = %d, want 1", deniedN)
	}
}

func TestProxyForwardsInScope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello-in-scope")
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")

	p := NewProxy(NewAllowlist([]string{hostPort}), nil)
	proxyURL, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())

	resp, err := HTTPClient(proxyURL, 5*time.Second).Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "hello-in-scope") {
		t.Fatalf("unexpected body: %s", body)
	}
	allowed, _ := p.Stats()
	if allowed != 1 {
		t.Fatalf("allowed = %d, want 1", allowed)
	}
}

func TestPackSignVerifyRoundTrip(t *testing.T) {
	pub, priv := devKeys(t)
	p := &Pack{
		ID: "test-pack", Version: "1.0.0", Safety: SafetyNonDestructive,
		TargetClasses: []string{"ssrf"},
		Program: Program{
			Steps:   []Step{{Name: "s", HTTP: &HTTPStep{Method: "GET", URL: "{{target}}"}}},
			Confirm: []Condition{{Var: "s.status", StatusEquals: 200}},
		},
	}
	signed, err := SignPack(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadPack(signed, pub)
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	if got.ID != "test-pack" || got.Program.Steps[0].Name != "s" {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	// Tampered pack → hard refusal (doc 04 §12 pack signature re-verification).
	tampered := strings.Replace(string(signed), `"test-pack"`, `"evil-pack"`, 1)
	if _, err := LoadPack([]byte(tampered), pub); err == nil {
		t.Fatal("tampered pack must fail signature verification")
	}

	// Wrong key → refusal.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := LoadPack(signed, otherPub); err == nil {
		t.Fatal("pack signed by another key must fail verification")
	}
}

func TestBuiltinPacksVerify(t *testing.T) {
	packs, err := BuiltinPacks("")
	if err != nil {
		t.Fatalf("BuiltinPacks: %v", err)
	}
	if len(packs) != 3 {
		t.Fatalf("got %d builtin packs, want 3", len(packs))
	}
	for _, p := range packs {
		if p.Safety != SafetyNonDestructive {
			t.Errorf("pack %s safety = %s, want non_destructive", p.ID, p.Safety)
		}
	}
	if ForClass(packs, "ssrf") == nil || ForClass(packs, "version_cve") == nil || ForClass(packs, "default_creds") == nil {
		t.Fatal("expected pack coverage for ssrf/version_cve/default_creds")
	}
}

func TestCheckSafetyRefusesStateChanging(t *testing.T) {
	p := &Pack{Safety: SafetyStateChanging}
	if err := CheckSafety(p, false); err == nil {
		t.Fatal("state_changing must be refused at MVP even with safe_mode=false")
	}
}

type fakeOOB struct {
	hits map[string][]ave.OOBInteraction
}

func (f *fakeOOB) NewCanary(_ context.Context, purpose string) (string, string, error) {
	return "tok123", "http://oob.test/c/tok123", nil
}
func (f *fakeOOB) Interactions(_ context.Context, token string) ([]ave.OOBInteraction, error) {
	return f.hits[token], nil
}

func TestRunProgramRCEEchoConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Vulnerable behavior: "cmd=echo+TOKEN" executes and echoes TOKEN.
		if strings.HasPrefix(string(body), "cmd=echo+") {
			fmt.Fprint(w, strings.TrimPrefix(string(body), "cmd=echo+"))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()

	pack := ForClass(mustBuiltin(t), "version_cve")
	out, err := RunProgram(context.Background(), pack.Program, &ProgramEnv{
		Target: srv.URL, MatchedAt: srv.URL, EchoToken: "s48echoTEST123",
		HTTP: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Confirmed {
		t.Fatalf("expected CONFIRMED, proof: %s", out.Proof)
	}
	if len(out.Transcript) != 1 || out.Transcript[0].Status != 200 {
		t.Fatalf("bad transcript: %+v", out.Transcript)
	}
}

func TestRunProgramRCEEchoNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "safe response, no echo")
	}))
	defer srv.Close()
	pack := ForClass(mustBuiltin(t), "version_cve")
	out, err := RunProgram(context.Background(), pack.Program, &ProgramEnv{
		Target: srv.URL, MatchedAt: srv.URL, EchoToken: "s48echoTEST123",
		HTTP: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Confirmed {
		t.Fatal("patched target must not confirm")
	}
}

func TestRunProgramSSRFViaOOB(t *testing.T) {
	oobSvc := &fakeOOB{hits: map[string][]ave.OOBInteraction{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Blind behavior: server-side fetch happens asynchronously; simulate
		// by recording the OOB hit from the handler itself.
		oobSvc.hits["tok123"] = append(oobSvc.hits["tok123"], ave.OOBInteraction{Token: "tok123", At: time.Now()})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pack := ForClass(mustBuiltin(t), "ssrf")
	out, err := RunProgram(context.Background(), pack.Program, &ProgramEnv{
		Target: srv.URL, MatchedAt: srv.URL, CanaryToken: "tok123",
		CanaryURL: "http://oob.test/c/tok123",
		HTTP:      &http.Client{Timeout: 5 * time.Second},
		OOB:       oobSvc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Confirmed {
		t.Fatalf("expected CONFIRMED via OOB, proof: %s", out.Proof)
	}
}

func TestRunProgramNoHTTPClientFails(t *testing.T) {
	pack := ForClass(mustBuiltin(t), "version_cve")
	if _, err := RunProgram(context.Background(), pack.Program, &ProgramEnv{}); err == nil {
		t.Fatal("program without a proxy-forced HTTP client must fail closed")
	}
}

func mustBuiltin(t *testing.T) []*Pack {
	t.Helper()
	packs, err := BuiltinPacks("")
	if err != nil {
		t.Fatal(err)
	}
	return packs
}

// --- Local runner round trip via the test binary as the sandbox child ------

// TestEvsChildHelper runs ONLY as the LocalRunner's sandbox child: it
// executes the real ChildMain against stdin/stdout (standard Go helper-
// process pattern).
func TestEvsChildHelper(t *testing.T) {
	if os.Getenv("S48_EVS_TEST_CHILD") != "1" {
		t.Skip("helper process")
	}
	os.Exit(ChildMain(context.Background(), os.Stdin, os.Stdout))
}

func TestLocalRunnerRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(body), "cmd=echo+") {
			fmt.Fprint(w, strings.TrimPrefix(string(body), "cmd=echo+"))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()

	pack := ForClass(mustBuiltin(t), "version_cve")
	r := &LocalRunner{
		Bin:      os.Args[0],
		Args:     []string{"-test.run=^TestEvsChildHelper$"},
		ExtraEnv: []string{"S48_EVS_TEST_CHILD=1"},
	}
	res, err := r.Run(context.Background(), RunRequest{
		JobID: "evs-test",
		Pack:  pack,
		Env: EnvSpec{
			Target: srv.URL, MatchedAt: srv.URL, EchoToken: "s48echoCHILD",
			ProxyURL: "", // test runs the child without a proxy
		},
		TimeoutMS: 30000,
	})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if res.Outcome == nil || !res.Outcome.Confirmed {
		b, _ := json.Marshal(res)
		t.Fatalf("child did not confirm: %s", b)
	}
	if res.Runner != "local" {
		t.Fatalf("runner = %s, want local", res.Runner)
	}
}

func TestEngineTriggerAndSkip(t *testing.T) {
	if !ShouldVerify("high", ave.VerdictInconclusive, false) {
		t.Error("high+INCONCLUSIVE must trigger EVS")
	}
	if !ShouldVerify("critical", ave.VerdictNotValidatable, false) {
		t.Error("critical+NOT_VALIDATABLE must trigger EVS")
	}
	if ShouldVerify("high", ave.VerdictConfirmed, false) {
		t.Error("CONFIRMED must not re-trigger EVS")
	}
	if ShouldVerify("low", ave.VerdictInconclusive, false) {
		t.Error("low severity must not trigger EVS")
	}
	if !ShouldVerify("low", ave.VerdictConfirmed, true) {
		t.Error("exploit_verify param forces EVS")
	}
}

func TestEngineVerifyWithFakeRunner(t *testing.T) {
	e := NewEngine(EngineConfig{
		Runner: &fakeRunner{out: &Outcome{Confirmed: true, Proof: "canary observed"}},
		Packs:  mustBuiltin(t),
	})
	res, bundle, err := e.Verify(context.Background(), ave.Candidate{
		Target: "https://t", MatchedAt: "https://t/x", VulnClass: "version_cve", CheckID: "cve-x",
	}, "http://127.0.0.1:1", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != ave.VerdictConfirmed || res.Method != "evs.poc" {
		t.Fatalf("bad result: %+v", res)
	}
	if len(bundle) == 0 {
		t.Fatal("evidence bundle required for CONFIRMED")
	}
}

func TestEngineNoPackSkips(t *testing.T) {
	e := NewEngine(EngineConfig{Runner: &fakeRunner{}, Packs: mustBuiltin(t)})
	res, bundle, err := e.Verify(context.Background(), ave.Candidate{VulnClass: "open_redirect"}, "", true)
	if err != nil || res != nil || bundle != nil {
		t.Fatalf("no-pack class must skip cleanly: %v %v %v", res, bundle, err)
	}
}

type fakeRunner struct{ out *Outcome }

func (f *fakeRunner) Kind() string { return "fake" }
func (f *fakeRunner) Run(_ context.Context, _ RunRequest) (*RunResult, error) {
	return &RunResult{Outcome: f.out, Runner: "fake"}, nil
}
