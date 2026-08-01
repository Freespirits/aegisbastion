package connectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// fixtureBody loads a recorded source response from testdata/fixtures.
func fixtureBody(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return body
}

// runConnector executes one connector against its fixture and returns the
// emitted findings (+ edges).
func runConnector(t *testing.T, c Connector, seed model.Seed) ([]model.RawFinding, [][]model.EdgeRef) {
	t.Helper()
	task := model.Task{
		TaskID:   "task-test",
		OrderID:  "order-test",
		TenantID: "tenant-test",
		Source:   c.Name(),
		Seed:     seed,
	}
	var findings []model.RawFinding
	var edges [][]model.EdgeRef
	emit := func(f model.RawFinding, e []model.EdgeRef) error {
		findings = append(findings, f)
		edges = append(edges, e)
		return nil
	}
	keys := KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "test-key", nil
	})
	_ = keys
	err := c.Run(context.Background(), RunInput{
		Task:       task,
		ObservedAt: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}, emit)
	if err != nil {
		t.Fatalf("%s run: %v", c.Name(), err)
	}
	return findings, edges
}

func fetcherFor(t *testing.T, fixture string) Fetcher {
	t.Helper()
	body := fixtureBody(t, fixture)
	return FetcherFunc(func(context.Context, *Request) ([]byte, error) { return body, nil })
}

func values(findings []model.RawFinding, typ model.AssetType) map[string]model.RawFinding {
	out := map[string]model.RawFinding{}
	for _, f := range findings {
		if f.Asset.Type == typ {
			out[f.Asset.Value] = f
		}
	}
	return out
}

func TestCrtSHFixture(t *testing.T) {
	c := NewCrtSH(fetcherFor(t, "crt.sh"))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})

	subs := values(findings, model.AssetSubdomain)
	for _, want := range []string{"www.example.com", "mail.example.com"} {
		if _, ok := subs[want]; !ok {
			t.Errorf("missing subdomain finding %s (got %v)", want, subs)
		}
	}
	// The apex classifies as domain.
	doms := values(findings, model.AssetDomain)
	if _, ok := doms["example.com"]; !ok {
		t.Errorf("missing apex domain finding (got %v)", doms)
	}
	// Wildcard: attribute on the base, not an asset (doc 02 §4.2).
	wc, ok := doms["api.example.com"]
	if !ok || wc.Asset.Attributes["wildcard"] != true {
		t.Errorf("wildcard base api.example.com missing/misattributed: %+v", doms)
	}
	if _, ok := subs["*.api.example.com"]; ok {
		t.Error("wildcard must never be an asset value")
	}
	// Out-of-scope SANs are still emitted — the REDUCER owns quarantine.
	if _, ok := subs["shared-hosting-neighbor.org"]; !ok {
		t.Error("out-of-scope SAN must be emitted for the reducer to quarantine")
	}
	// Dedup: www.example.com appears in two cert entries, one finding.
	count := 0
	for _, f := range findings {
		if f.Asset.Value == "www.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("www.example.com dedup: %d findings, want 1", count)
	}
}

func TestCensysCTFixture(t *testing.T) {
	c := NewCensysCT(fetcherFor(t, "censys_ct"), KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "id:secret", nil
	}))
	findings, edges := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})

	certs := values(findings, model.AssetCert)
	if len(certs) != 2 {
		t.Fatalf("want 2 cert assets keyed by sha256 fingerprint, got %v", certs)
	}
	for fp, f := range certs {
		if len(fp) != 64 {
			t.Errorf("cert key %q is not lowercase sha256 hex", fp)
		}
		cert, _ := f.Asset.Attributes["cert"].(map[string]any)
		if cert == nil || cert["not_after"] == "" {
			t.Errorf("cert %s missing not_after attribute", fp)
		}
	}
	// san_of edges host → cert.
	sanOf := 0
	for _, es := range edges {
		for _, e := range es {
			if e.Rel == model.RelSANOf && e.Dst.Type == model.AssetCert {
				sanOf++
			}
		}
	}
	if sanOf == 0 {
		t.Error("expected san_of edges host → cert")
	}
	if !c.RequiresCredentials() {
		t.Error("censys_ct must require credentials")
	}
}

func TestSecurityTrailsFixture(t *testing.T) {
	c := NewSecurityTrails(fetcherFor(t, "securitytrails"), KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "k", nil
	}))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})
	subs := values(findings, model.AssetSubdomain)
	for _, want := range []string{"www.example.com", "api.example.com", "dev.api.example.com"} {
		if _, ok := subs[want]; !ok {
			t.Errorf("missing %s (relative labels must join the apex; got %v)", want, subs)
		}
	}
	// "WWW" dedups against "www" after canonicalization.
	if len(findings) != 3 {
		t.Errorf("case-insensitive dedup: %d findings, want 3", len(findings))
	}
}

func TestVirusTotalFixture(t *testing.T) {
	c := NewVirusTotal(fetcherFor(t, "virustotal"), KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "k", nil
	}))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})
	subs := values(findings, model.AssetSubdomain)
	if len(subs) != 2 {
		t.Errorf("vt dedup: got %v, want 2 subdomains", subs)
	}
}

func TestShodanFixture(t *testing.T) {
	c := NewShodan(fetcherFor(t, "shodan_dns"), KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "k", nil
	}))
	findings, edges := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})

	ips := values(findings, model.AssetIP)
	for _, want := range []string{"203.0.113.10", "203.0.113.11", "2001:db8::10"} {
		if _, ok := ips[want]; !ok {
			t.Errorf("missing IP %s (got %v)", want, ips)
		}
	}
	subs := values(findings, model.AssetSubdomain)
	www, ok := subs["www.example.com"]
	if !ok {
		t.Fatalf("missing www.example.com (got %v)", subs)
	}
	dns, _ := www.Asset.Attributes["dns"].([]string)
	if len(dns) != 2 {
		t.Errorf("www dns attribute = %v, want 2 records (v4 never merged with v6)", dns)
	}
	// resolves_to edges www → both IPs.
	resolves := 0
	for _, es := range edges {
		for _, e := range es {
			if e.Rel == model.RelResolvesTo && e.Src.Value == "www.example.com" {
				resolves++
			}
		}
	}
	if resolves != 2 {
		t.Errorf("www resolves_to edges = %d, want 2", resolves)
	}
}

func TestRapidDNSFixture(t *testing.T) {
	c := NewRapidDNS(fetcherFor(t, "rapiddns"))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})
	subs := values(findings, model.AssetSubdomain)
	if _, ok := subs["www.example.com"]; !ok {
		t.Errorf("missing www.example.com (got %v)", subs)
	}
	if _, ok := subs["shop.example.com"]; !ok {
		t.Errorf("missing shop.example.com (got %v)", subs)
	}
	ips := values(findings, model.AssetIP)
	if _, ok := ips["198.51.100.20"]; !ok {
		t.Errorf("missing 198.51.100.20 (got %v)", ips)
	}
}

func TestWaybackFixture(t *testing.T) {
	c := NewWayback(fetcherFor(t, "wayback"))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})
	subs := values(findings, model.AssetSubdomain)
	for _, want := range []string{"news.example.com", "shop.example.com"} {
		if _, ok := subs[want]; !ok {
			t.Errorf("missing %s (host must be extracted from URL, port stripped; got %v)", want, subs)
		}
	}
}

func TestBGPViewFixture(t *testing.T) {
	c := NewBGPView(fetcherFor(t, "bgpview"))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedASN, Value: "AS64500"})
	nb := values(findings, model.AssetNetblock)
	if _, ok := nb["203.0.113.0/24"]; !ok {
		t.Errorf("missing v4 prefix (got %v)", nb)
	}
	if _, ok := nb["2001:db8::/32"]; !ok {
		t.Errorf("missing v6 prefix (got %v)", nb)
	}
	if len(nb) != 2 {
		t.Errorf("prefix dedup: got %v, want 2", nb)
	}
	if nb["203.0.113.0/24"].Asset.Attributes["asn"] != "AS64500" {
		t.Error("netblock must carry the asn attribute")
	}
}

func TestRIPEstatFixture(t *testing.T) {
	c := NewRIPEstat(fetcherFor(t, "ripestat"))
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedASN, Value: "64500"})
	nb := values(findings, model.AssetNetblock)
	if len(nb) != 1 {
		t.Errorf("ripestat dedup: got %v, want 1", nb)
	}
	if _, ok := nb["198.51.100.0/24"]; !ok {
		t.Errorf("missing 198.51.100.0/24 (got %v)", nb)
	}
}

func TestRDAPDomainFixture(t *testing.T) {
	c := NewRDAP(fetcherFor(t, "rdap"), "", "")
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedDomain, Value: "example.com"})
	if len(findings) != 1 {
		t.Fatalf("want 1 domain finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Asset.Type != model.AssetDomain || f.Asset.Value != "example.com" {
		t.Errorf("rdap domain finding = %+v", f.Asset)
	}
	rdap, _ := f.Asset.Attributes["rdap"].(map[string]any)
	if rdap == nil {
		t.Fatal("rdap attributes missing")
	}
	ns, _ := rdap["nameservers"].([]string)
	if len(ns) != 2 {
		t.Errorf("nameservers = %v, want 2", ns)
	}
}

func TestRDAPIPNework(t *testing.T) {
	body := []byte(`{
	  "objectClassName": "ip network",
	  "handle": "NET-203-0-113-0-1",
	  "name": "EXAMPLE-NET",
	  "startAddress": "203.0.113.0",
	  "endAddress": "203.0.113.255",
	  "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]
	}`)
	c := NewRDAP(FetcherFunc(func(context.Context, *Request) ([]byte, error) { return body, nil }), "", "")
	findings, _ := runConnector(t, c, model.Seed{Type: model.SeedCIDR, Value: "203.0.113.0/24"})
	nb := values(findings, model.AssetNetblock)
	if _, ok := nb["203.0.113.0/24"]; !ok {
		t.Errorf("missing netblock from cidr0_cidrs (got %v)", nb)
	}
}

// --- doc 02 §9: rate-spec compliance + registry mechanics -------------------

func TestRateSpecCompliance(t *testing.T) {
	fetch := FetcherFunc(func(context.Context, *Request) ([]byte, error) { return nil, ErrNotFound })
	keys := KeyProviderFunc(func(context.Context, string, string) (string, error) { return "k", nil })
	cat := NewCatalog(fetch, keys)
	reg, err := cat.BuildRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		spec := c.RateSpec()
		if spec.RPS <= 0 {
			t.Errorf("connector %s: rps must be > 0", name)
		}
		if spec.Burst < 1 {
			t.Errorf("connector %s: burst must be >= 1", name)
		}
		if spec.DailyQuota < 0 {
			t.Errorf("connector %s: daily_quota must be >= 0", name)
		}
		if len(c.Techniques()) == 0 {
			t.Errorf("connector %s: no techniques declared", name)
		}
	}
}

func TestTokenBucketEnforcesRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	b := newTokenBucket(2, 2, 0, clock) // 2 rps, burst 2
	ctx := context.Background()
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	// Bucket empty: a third wait must block until the clock advances.
	done := make(chan error, 1)
	go func() { done <- b.Wait(ctx) }()
	select {
	case <-done:
		t.Fatal("third acquire must wait for refill")
	case <-time.After(50 * time.Millisecond):
	}
	now = now.Add(time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not proceed after refill")
	}
}

func TestTokenBucketDailyQuota(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newTokenBucket(1000, 10, 2, func() time.Time { return now })
	ctx := context.Background()
	_ = b.Wait(ctx)
	_ = b.Wait(ctx)
	if err := b.Wait(ctx); err == nil {
		t.Fatal("daily quota must fail closed once exhausted")
	}
}

func TestCircuitBreakerOpensAfterFiveFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cb := newCircuitBreaker(5, 30*time.Second, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		if !cb.Allow() {
			t.Fatalf("breaker opened early at %d", i)
		}
		cb.Observe(false)
	}
	if cb.Allow() {
		t.Fatal("breaker must open after 5 consecutive failures")
	}
	now = now.Add(31 * time.Second)
	if !cb.Allow() {
		t.Fatal("breaker must half-open after the cooldown")
	}
	cb.Observe(true)
	if !cb.Allow() {
		t.Fatal("breaker must close after a success")
	}
}

// TestRegistryFailClosedOnCircuitOpen proves the doc 02 §7.2 posture: an
// open circuit fails the task SOURCE_UNAVAILABLE-style instead of hammering
// a down source.
func TestRegistryFailClosedOnCircuitOpen(t *testing.T) {
	calls := 0
	fetch := FetcherFunc(func(context.Context, *Request) ([]byte, error) {
		calls++
		return nil, context.DeadlineExceeded
	})
	cat := NewCatalog(fetch, nil)
	reg, err := cat.BuildRegistryFor(nil, map[string]bool{CrtSHName: true})
	if err != nil {
		t.Fatal(err)
	}
	in := RunInput{Task: model.Task{TaskID: "t", Seed: model.Seed{Type: model.SeedDomain, Value: "example.com"}}}
	emit := func(model.RawFinding, []model.EdgeRef) error { return nil }
	for i := 0; i < 5; i++ {
		_ = reg.Run(context.Background(), CrtSHName, in, emit)
	}
	before := calls
	err = reg.Run(context.Background(), CrtSHName, in, emit)
	if err == nil {
		t.Fatal("open circuit must fail the task")
	}
	if calls != before {
		t.Fatal("open circuit must not contact the source")
	}
}

// TestStaticKeysResolution covers the per-tenant key lookup + wildcard.
func TestStaticKeysResolution(t *testing.T) {
	keys := StaticKeys{
		"tenant-a": {CensysCTName: "a-key"},
		"*":        {VirusTotalName: "wild-key"},
	}
	if k, err := keys.APIKey(context.Background(), "tenant-a", CensysCTName); err != nil || k != "a-key" {
		t.Errorf("tenant key = %q, %v", k, err)
	}
	if k, err := keys.APIKey(context.Background(), "tenant-b", VirusTotalName); err != nil || k != "wild-key" {
		t.Errorf("wildcard key = %q, %v", k, err)
	}
	if _, err := keys.APIKey(context.Background(), "tenant-b", CensysCTName); err == nil {
		t.Error("missing key must fail closed")
	}
}
