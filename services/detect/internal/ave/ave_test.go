package ave

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func toolsFor(srv *httptest.Server) *Tools {
	return &Tools{HTTP: srv.Client(), Now: time.Now}
}

func TestEngineNotValidatableWithoutValidator(t *testing.T) {
	e := NewEngine() // none registered
	res, err := e.Validate(context.Background(), Candidate{VulnClass: "open_redirect"}, &Tools{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictNotValidatable {
		t.Fatalf("verdict = %q, want NOT_VALIDATABLE", res.Verdict)
	}
	if res.Confidence > 0.5 {
		t.Fatalf("NOT_VALIDATABLE must carry reduced confidence, got %v", res.Confidence)
	}
}

func TestXSSConfirmedOnExecutableReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	e := NewEngine(XSSValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, MatchedAt: srv.URL + "/search?q=test",
		VulnClass: "reflected_xss", CheckID: "reflected-xss-search",
		Evidence: map[string]any{"param": "q"},
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %q, want CONFIRMED (%s)", res.Verdict, res.Detail)
	}
	if res.Transcript == nil || res.Transcript.Canary == "" {
		t.Fatal("transcript with canary required for CONFIRMED")
	}
	if len(res.Transcript.Exchanges) == 0 {
		t.Fatal("CONFIRMED requires captured exchanges")
	}
}

func TestXSSNotReproducibleWhenEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		q = strings.ReplaceAll(q, "<", "&lt;")
		q = strings.ReplaceAll(q, ">", "&gt;")
		q = strings.ReplaceAll(q, `"`, "&quot;")
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer srv.Close()

	e := NewEngine(XSSValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, VulnClass: "reflected_xss", CheckID: "xss",
		Evidence: map[string]any{"param": "q"},
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict == VerdictConfirmed {
		t.Fatalf("escaped reflection must never be CONFIRMED: %s", res.Detail)
	}
	if res.Verdict != VerdictNotReproducible && res.Verdict != VerdictInconclusive {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestSQLiConfirmedOnErrorDifferential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch {
		case strings.HasSuffix(id, `'`) && !strings.HasSuffix(id, `''`):
			w.WriteHeader(500)
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
		case strings.Contains(id, "AND 1=2"):
			fmt.Fprint(w, "no rows")
		default:
			fmt.Fprint(w, "<html>product page for id</html>")
		}
	}))
	defer srv.Close()

	e := NewEngine(SQLiValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL + "/item?id=1", MatchedAt: srv.URL + "/item?id=1",
		VulnClass: "sqli", CheckID: "sqli-error",
		Evidence: map[string]any{"param": "id"},
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %q, want CONFIRMED (%s)", res.Verdict, res.Detail)
	}
}

func TestSQLiNotReproducibleOnParameterizedApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>stable page</html>")
	}))
	defer srv.Close()

	e := NewEngine(SQLiValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL + "/item?id=1", VulnClass: "sqli", CheckID: "sqli",
		Evidence: map[string]any{"param": "id"},
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict == VerdictConfirmed {
		t.Fatalf("parameterized endpoint must not confirm: %s", res.Detail)
	}
}

func TestSSRFNotValidatableWithoutOOB(t *testing.T) {
	e := NewEngine(SSRFValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: "https://x.example/fetch", VulnClass: "ssrf", CheckID: "ssrf",
	}, &Tools{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictNotValidatable {
		t.Fatalf("verdict = %q, want NOT_VALIDATABLE when OOB is down (doc 04 §12)", res.Verdict)
	}
}

type fakeOOB struct {
	mu     sync.Mutex
	tokens map[string][]OOBInteraction
	hits   map[string]int
}

func newFakeOOB() *fakeOOB {
	return &fakeOOB{tokens: map[string][]OOBInteraction{}, hits: map[string]int{}}
}

func (f *fakeOOB) NewCanary(_ context.Context, purpose string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok := "canary-" + fmt.Sprint(len(f.tokens)+1)
	f.tokens[tok] = nil
	return tok, "http://oob.example/c/" + tok, nil
}

func (f *fakeOOB) Interactions(_ context.Context, token string) ([]OOBInteraction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[token], nil
}

func (f *fakeOOB) record(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token] = append(f.tokens[token], OOBInteraction{
		Token: tok(token), At: time.Now(), Method: "GET", Path: "/c/" + token, Remote: "203.0.113.9:51000",
	})
}

func tok(t string) string { return t }

func TestSSRFConfirmedOnCallback(t *testing.T) {
	oob := newFakeOOB()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			// vulnerable app would fetch u; we simulate the callback below
			for tok := range oob.tokens {
				if strings.Contains(u, tok) {
					oob.record(tok)
				}
			}
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	tls2 := toolsFor(srv)
	tls2.OOB = oob
	e := NewEngine(SSRFValidator{WaitWindow: 2 * time.Second, PollInterval: 50 * time.Millisecond})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL + "/fetch?url=x", MatchedAt: srv.URL + "/fetch?url=x",
		VulnClass: "ssrf", CheckID: "ssrf-param",
		Evidence: map[string]any{"param": "url"},
	}, tls2)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %q, want CONFIRMED (%s)", res.Verdict, res.Detail)
	}
	if res.Confidence < 0.9 {
		t.Fatalf("OOB-confirmed confidence too low: %v", res.Confidence)
	}
}

func TestSSRFNotReproducibleWithoutCallback(t *testing.T) {
	oob := newFakeOOB()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	tls2 := toolsFor(srv)
	tls2.OOB = oob
	e := NewEngine(SSRFValidator{WaitWindow: 300 * time.Millisecond, PollInterval: 50 * time.Millisecond})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL + "/fetch?url=x", VulnClass: "ssrf", CheckID: "ssrf",
		Evidence: map[string]any{"param": "url"},
	}, tls2)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictNotReproducible {
		t.Fatalf("verdict = %q, want NOT_REPRODUCIBLE", res.Verdict)
	}
}

func TestTraversalConfirmedOnRobotsHash(t *testing.T) {
	robots := "User-agent: *\nDisallow: /admin\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		switch {
		case r.URL.Path == "/robots.txt":
			fmt.Fprint(w, robots)
		case f != "":
			// vulnerable: naive "file read" that resolves traversal
			if strings.Contains(f, "robots.txt") {
				fmt.Fprint(w, robots)
			} else {
				fmt.Fprint(w, "template not found")
			}
		default:
			fmt.Fprint(w, "<html>app</html>")
		}
	}))
	defer srv.Close()

	e := NewEngine(TraversalValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL + "/view?file=home", MatchedAt: srv.URL + "/view?file=home",
		VulnClass: "path_traversal", CheckID: "lfi-generic",
		Evidence: map[string]any{"param": "file"},
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %q, want CONFIRMED (%s)", res.Verdict, res.Detail)
	}
}

func TestHeadersConfirmedWhenMissingTwice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// no security headers at all
		fmt.Fprint(w, "<html>plain</html>")
	}))
	defer srv.Close()

	e := NewEngine(HeadersValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, VulnClass: "security_header", CheckID: "missing-security-headers",
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %q, want CONFIRMED (%s)", res.Verdict, res.Detail)
	}
}

func TestHeadersNotReproducibleWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fmt.Fprint(w, "<html>hardened</html>")
	}))
	defer srv.Close()

	e := NewEngine(HeadersValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, VulnClass: "security_header", CheckID: "missing-security-headers",
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictNotReproducible {
		t.Fatalf("verdict = %q, want NOT_REPRODUCIBLE", res.Verdict)
	}
}

func TestVersionCVEBannerOnlyIsInconclusive(t *testing.T) {
	// Server advertises the banner but answers OPTIONS plainly with no
	// feature differential → contractual INCONCLUSIVE (doc 04 §6 row 1).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Server", "PAN-OS 10.2.3")
		fmt.Fprint(w, "<PAN-OS login>")
	}))
	defer srv.Close()

	e := NewEngine(VersionCVEValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, VulnClass: "version_cve", CheckID: "cve-2024-3400",
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictInconclusive {
		t.Fatalf("banner-only must be INCONCLUSIVE, got %q (%s)", res.Verdict, res.Detail)
	}
}

func TestVersionCVEConfirmedOnDualSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, PUT, DELETE")
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Server", "PAN-OS 10.2.3")
		fmt.Fprint(w, "<PAN-OS login>")
	}))
	defer srv.Close()

	e := NewEngine(VersionCVEValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: srv.URL, VulnClass: "version_cve", CheckID: "cve-2024-3400",
	}, toolsFor(srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("dual signal must CONFIRM, got %q (%s)", res.Verdict, res.Detail)
	}
}

func TestTLSValidatorWithStubProber(t *testing.T) {
	e := NewEngine(TLSValidator{})
	res, err := e.Validate(context.Background(), Candidate{
		Target: "tls.example:443", MatchedAt: "tls.example:443",
		VulnClass: "tls_misconfig", CheckID: "ssl-weak-version",
	}, &Tools{TLS: stubProber{profile: &TLSProfile{
		MinVersionOffered: 0x0301, // TLS 1.0
		ServerName:        "tls.example:443",
	}}})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("weak version must CONFIRM, got %q", res.Verdict)
	}

	res2, _ := e.Validate(context.Background(), Candidate{
		Target: "tls.example:443", MatchedAt: "tls.example:443",
		VulnClass: "tls_misconfig", CheckID: "ssl-weak-version",
	}, &Tools{TLS: stubProber{profile: &TLSProfile{
		MinVersionOffered: 0x0303, // TLS 1.2
		ServerName:        "tls.example:443",
	}}})
	if res2.Verdict != VerdictNotReproducible {
		t.Fatalf("modern TLS must NOT_REPRODUCE, got %q", res2.Verdict)
	}
}

type stubProber struct {
	profile *TLSProfile
	err     error
}

func (s stubProber) ProbeVersions(_ context.Context, _ string) (*TLSProfile, error) {
	return s.profile, s.err
}
