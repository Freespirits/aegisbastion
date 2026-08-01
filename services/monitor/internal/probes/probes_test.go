package probes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

var testNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func reqFor(target string) Request {
	return Request{Target: target, AssetID: "asset_1", MissionID: "msn_1",
		ROEID: "roe_1", ROEVersion: 1, TokenJTI: "tok_1", WorkerID: "mon-w-test", Now: testNow}
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

// fakeQuerier scripts answers per (name, qtype).
type fakeQuerier struct {
	answers map[string]*dns.Msg // "name|type" → msg
}

func (f fakeQuerier) Query(_ context.Context, _, name string, qtype uint16) (*dns.Msg, error) {
	key := strings.TrimSuffix(strings.ToLower(name), ".") + "|" + dns.TypeToString[qtype]
	if m, ok := f.answers[key]; ok {
		return m, nil
	}
	m := new(dns.Msg)
	m.Rcode = dns.RcodeSuccess // NODATA
	return m, nil
}

func aMsg(name, ip string) *dns.Msg {
	m := new(dns.Msg)
	rr, _ := dns.NewRR(fmt.Sprintf("%s. 300 IN A %s", name, ip))
	m.Answer = []dns.RR{rr}
	m.Rcode = dns.RcodeSuccess
	return m
}

func cnameMsg(name, target string) *dns.Msg {
	m := new(dns.Msg)
	rr, _ := dns.NewRR(fmt.Sprintf("%s. 300 IN CNAME %s.", name, target))
	m.Answer = []dns.RR{rr}
	m.Rcode = dns.RcodeSuccess
	return m
}

func nsMsg(name string, servers ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, s := range servers {
		rr, _ := dns.NewRR(fmt.Sprintf("%s. 300 IN NS %s.", name, s))
		m.Answer = append(m.Answer, rr)
	}
	m.Rcode = dns.RcodeSuccess
	return m
}

func nxMsg() *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	return m
}

func TestDNSProbe_QuorumAgreement(t *testing.T) {
	q := fakeQuerier{answers: map[string]*dns.Msg{
		"api.acme.com|A":  aMsg("api.acme.com", "203.0.113.10"),
		"api.acme.com|NS": nsMsg("api.acme.com", "ns1.acme.com", "ns2.acme.com"),
	}}
	p := &DNSProbe{Resolvers: []string{"r1", "r2", "r3"}, Querier: q}
	res, err := p.Probe(context.Background(), reqFor("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Doc
	if doc.Status != snapshot.StatusOK {
		t.Fatalf("status = %s", doc.Status)
	}
	if doc.Data.DNS.Records["A"][0] != "203.0.113.10" {
		t.Fatalf("A records = %v", doc.Data.DNS.Records["A"])
	}
	if doc.Data.DNS.TTLs["A"] != 300 {
		t.Fatalf("TTL = %d", doc.Data.DNS.TTLs["A"])
	}
	if doc.Data.DNS.Quorum.Agreeing != 3 {
		t.Fatalf("quorum = %+v", doc.Data.DNS.Quorum)
	}
	if doc.Authorization.TokenJTI != "tok_1" {
		t.Fatalf("authorization not stamped: %+v", doc.Authorization)
	}
}

// splitQuerier returns different answers per resolver server.
type splitQuerier struct{ per map[string]fakeQuerier }

func (s splitQuerier) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return s.per[server].Query(ctx, server, name, qtype)
}

func TestDNSProbe_SplitHorizonInconclusive(t *testing.T) {
	mk := func(ip string) fakeQuerier {
		return fakeQuerier{answers: map[string]*dns.Msg{"api.acme.com|A": aMsg("api.acme.com", ip)}}
	}
	q := splitQuerier{per: map[string]fakeQuerier{
		"r1": mk("203.0.113.1"), "r2": mk("203.0.113.2"), "r3": mk("203.0.113.3"),
	}}
	p := &DNSProbe{Resolvers: []string{"r1", "r2", "r3"}, Querier: q}
	res, err := p.Probe(context.Background(), reqFor("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Doc.Status != snapshot.StatusInconclusive {
		// doc 03 §12: resolver poisoning/split horizon → no state transition
		t.Fatalf("status = %s, want inconclusive", res.Doc.Status)
	}
}

func TestDNSProbe_NXDOMAIN(t *testing.T) {
	q := fakeQuerier{answers: map[string]*dns.Msg{
		"gone.acme.com|A":     nxMsg(),
		"gone.acme.com|AAAA":  nxMsg(),
		"gone.acme.com|CNAME": nxMsg(),
		"gone.acme.com|MX":    nxMsg(),
		"gone.acme.com|TXT":   nxMsg(),
		"gone.acme.com|NS":    nxMsg(),
	}}
	p := &DNSProbe{Resolvers: []string{"r1", "r2", "r3"}, Querier: q}
	res, err := p.Probe(context.Background(), reqFor("gone.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Doc.Status != snapshot.StatusDNSNXDomain {
		t.Fatalf("status = %s, want dns_nxdomain", res.Doc.Status)
	}
}

func TestDNSProbe_DanglingCNAMETakeable(t *testing.T) {
	q := fakeQuerier{answers: map[string]*dns.Msg{
		"app.acme.com|A":               cnameMsg("app.acme.com", "gone.azurewebsites.net"),
		"app.acme.com|CNAME":           cnameMsg("app.acme.com", "gone.azurewebsites.net"),
		"gone.azurewebsites.net|A":     nxMsg(),
		"gone.azurewebsites.net|AAAA":  nxMsg(),
		"gone.azurewebsites.net|CNAME": {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}},
	}}
	p := &DNSProbe{Resolvers: []string{"r1", "r2", "r3"}, Querier: q}
	res, err := p.Probe(context.Background(), reqFor("app.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	d := res.Doc.Data.DNS.Dangling
	if d == nil {
		t.Fatalf("dangling not detected: %+v", res.Doc.Data.DNS)
	}
	if d.TakeableService != "azurewebsites.net" {
		t.Fatalf("takeable service = %q", d.TakeableService)
	}
}

// ---------------------------------------------------------------------------
// TLS (loopback)
// ---------------------------------------------------------------------------

func TestTLSProbe_Loopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(strings.Split(srv.URL, ":")[2])

	p := &TLSProbe{Dialer: NetTLSDialer{ServerName: "example.com", Addr: "127.0.0.1:" + strconv.Itoa(port)}, Port: port}
	res, err := p.Probe(context.Background(), reqFor("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Doc
	if doc.Status != snapshot.StatusOK {
		t.Fatalf("status = %s", doc.Status)
	}
	td := doc.Data.TLS
	if td.Leaf.FingerprintSHA256 == "" || td.Leaf.Issuer == "" {
		t.Fatalf("leaf not captured: %+v", td.Leaf)
	}
	if td.Negotiated.Version == "" || td.Negotiated.Cipher == "" {
		t.Fatalf("negotiated not captured: %+v", td.Negotiated)
	}
	if td.DaysToExpiry < 0 {
		t.Fatalf("test cert should not be expired: %d", td.DaysToExpiry)
	}
}

func TestTLSProbe_Refused(t *testing.T) {
	// Bind and close to get a definitely-closed port.
	srv := httptest.NewTLSServer(nil)
	port, _ := strconv.Atoi(strings.Split(srv.URL, ":")[2])
	srv.Close()

	p := &TLSProbe{Dialer: NetTLSDialer{Addr: "127.0.0.1:" + strconv.Itoa(port)}, Port: port}
	res, err := p.Probe(context.Background(), reqFor("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Doc.Status != snapshot.StatusRefused && res.Doc.Status != snapshot.StatusTLSError {
		t.Fatalf("status = %s, want refused/tls_error", res.Doc.Status)
	}
}

// ---------------------------------------------------------------------------
// HTTP (loopback)
// ---------------------------------------------------------------------------

func TestHTTPProbe_Loopback(t *testing.T) {
	var gotUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Set-Cookie", "session=secret")
		fmt.Fprint(w, `<html><head><title>Acme Home</title></head><body><div data-reactroot=""></div></body></html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	probe := &HTTPProbe{
		Client:     srv.Client(),
		ResolveURL: func(_, scheme string) string { return srv.URL + "/" },
	}
	res, err := probe.Probe(context.Background(), reqFor("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Doc
	if doc.Status != snapshot.StatusOK {
		t.Fatalf("status = %s", doc.Status)
	}
	hd := doc.Data.HTTP
	if hd.Status != 200 || hd.Title != "Acme Home" {
		t.Fatalf("status/title = %d/%q", hd.Status, hd.Title)
	}
	if hd.HeadersCanonical["server"] != "nginx" {
		t.Fatalf("server header = %q", hd.HeadersCanonical["server"])
	}
	if _, ok := hd.HeadersCanonical["set-cookie"]; ok {
		t.Fatal("set-cookie must never be stored (doc 03 §9.5)")
	}
	if hd.BodySimHash == "" || hd.BodySize == 0 {
		t.Fatal("body hash/size missing")
	}
	if hd.RobotsStatus != 200 {
		t.Fatalf("robots status = %d", hd.RobotsStatus)
	}
	foundReact := false
	for _, te := range hd.Tech {
		if te.Name == "react" {
			foundReact = true
		}
		if te.Name == "nginx" && te.Confidence != "sure" {
			t.Fatal("nginx header rule must be sure")
		}
	}
	if !foundReact {
		t.Fatal("react fingerprint missing")
	}
	// Fixed identifiable UA with the RoE id (doc 03 §6.1/§9.6).
	if gotUA != "AegisBastion-Monitor/0.1 (+roe:roe_1)" {
		t.Fatalf("UA = %q", gotUA)
	}
	if len(res.RawBody) == 0 {
		t.Fatal("raw body not captured")
	}
}

func TestHTTPProbe_RedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landing", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<html><head><title>Landing</title></head></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	probe := &HTTPProbe{Client: srv.Client(),
		ResolveURL: func(_, _ string) string { return srv.URL + "/" }}
	res, err := probe.Probe(context.Background(), reqFor("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	hd := res.Doc.Data.HTTP
	if len(hd.RedirectChain) != 1 || !strings.HasSuffix(hd.FinalURL, "/landing") {
		t.Fatalf("chain=%v final=%s", hd.RedirectChain, hd.FinalURL)
	}
}

func TestHTTPProbe_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	probe := &HTTPProbe{Client: srv.Client(),
		ResolveURL: func(_, _ string) string { return srv.URL + "/" }}
	res, err := probe.Probe(context.Background(), reqFor("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Doc.Status != snapshot.StatusOK || res.Doc.Data.HTTP.Status != 404 {
		t.Fatalf("404 is an observation, not a transport failure: %+v", res.Doc)
	}
}

func TestFixtureProbe_Scripting(t *testing.T) {
	f := NewFixtureProbe("dns")
	f.SetFrames("a.acme.com",
		&snapshot.Document{Status: snapshot.StatusOK},
		&snapshot.Document{Status: snapshot.StatusTimeout},
	)
	r1, _ := f.Probe(context.Background(), reqFor("a.acme.com"))
	r2, _ := f.Probe(context.Background(), reqFor("a.acme.com"))
	r3, _ := f.Probe(context.Background(), reqFor("a.acme.com"))
	if r1.Doc.Status != snapshot.StatusOK || r2.Doc.Status != snapshot.StatusTimeout ||
		r3.Doc.Status != snapshot.StatusTimeout {
		t.Fatal("fixture frames not advancing")
	}
	if f.Calls("a.acme.com") != 3 || f.TotalCalls() != 3 {
		t.Fatal("call counters wrong")
	}
	if _, err := f.Probe(context.Background(), reqFor("unknown")); err == nil {
		t.Fatal("unknown target must error")
	}
}
