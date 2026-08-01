package diff

import (
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

var testNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func dnsDoc(records map[string][]string) *snapshot.Document {
	return &snapshot.Document{
		ProbeType: snapshot.ProbeDNS, Status: snapshot.StatusOK,
		Data: snapshot.Data{DNS: &snapshot.DNSData{
			Records: records,
			Quorum:  snapshot.Quorum{Resolvers: 3, Agreeing: 3},
		}},
	}
}

func tlsDoc(fp, issuer, version string, days int, match bool) *snapshot.Document {
	return &snapshot.Document{
		ProbeType: snapshot.ProbeTLS, Status: snapshot.StatusOK,
		Data: snapshot.Data{TLS: &snapshot.TLSData{
			Leaf: snapshot.TLSCert{
				FingerprintSHA256: fp, Issuer: issuer,
				NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-12-31T00:00:00Z",
			},
			Negotiated:    snapshot.TLSNeg{Version: version, Cipher: "TLS_AES_128_GCM_SHA256"},
			DaysToExpiry:  days,
			HostnameMatch: match,
		}},
	}
}

func httpDoc(status int, title, simhash string, size int, headers map[string]string, tech []snapshot.Tech) *snapshot.Document {
	return &snapshot.Document{
		ProbeType: snapshot.ProbeHTTP, Status: snapshot.StatusOK,
		Data: snapshot.Data{HTTP: &snapshot.HTTPData{
			FinalURL: "https://api.acme.com/", Status: status, Title: title,
			BodySimHash: simhash, BodySize: size,
			HeadersCanonical: headers, Tech: tech,
		}},
	}
}

func find(changes []Change, typ string) *Change {
	for i := range changes {
		if changes[i].Type == typ {
			return &changes[i]
		}
	}
	return nil
}

func TestSnapshots_NilAndNotOK(t *testing.T) {
	if got := Snapshots(nil, dnsDoc(nil), Options{Now: testNow}); got != nil {
		t.Fatal("nil prev must yield no changes")
	}
	bad := dnsDoc(nil)
	bad.Status = snapshot.StatusTimeout
	if got := Snapshots(dnsDoc(nil), bad, Options{Now: testNow}); got != nil {
		t.Fatal("non-ok curr must yield no changes")
	}
}

func TestDNS_RecordsChanged(t *testing.T) {
	prev := dnsDoc(map[string][]string{"A": {"203.0.113.10"}})
	curr := dnsDoc(map[string][]string{"A": {"203.0.113.11"}})
	got := Snapshots(prev, curr, Options{Now: testNow})
	c := find(got, "dns.records_changed")
	if c == nil {
		t.Fatalf("want dns.records_changed, got %v", got)
	}
	if c.Severity != SevLow || c.Confidence != ConfConfirmed {
		t.Fatalf("severity/confidence = %s/%s", c.Severity, c.Confidence)
	}
}

func TestDNS_NewRecordsVsVanished(t *testing.T) {
	prev := dnsDoc(map[string][]string{"A": {"203.0.113.10"}})
	curr := dnsDoc(map[string][]string{
		"A":  {"203.0.113.10"},
		"MX": {"10 mail.acme.com"},
	})
	got := Snapshots(prev, curr, Options{Now: testNow})
	if c := find(got, "dns.new_records"); c == nil {
		t.Fatalf("want dns.new_records, got %v", got)
	}
	// Vanished record type is medium.
	got2 := Snapshots(curr, prev, Options{Now: testNow})
	c := find(got2, "dns.records_changed")
	if c == nil || c.DiffKey != "MX" || c.Severity != SevMedium {
		t.Fatalf("vanished MX: %+v", c)
	}
}

func TestDNS_NSAlwaysHigh(t *testing.T) {
	prev := dnsDoc(map[string][]string{"NS": {"ns1.acme.com"}})
	curr := dnsDoc(map[string][]string{"NS": {"ns1.acme.com", "ns2.acme.com"}})
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "dns.ns_changed")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("NS change must be ≥ high: %+v", c)
	}
	if len(c.Followups) == 0 {
		t.Fatal("NS change must carry a detect.scan followup")
	}
}

func TestDNS_DanglingCNAME(t *testing.T) {
	prev := dnsDoc(map[string][]string{"CNAME": {"app.acme.com"}})
	curr := dnsDoc(map[string][]string{"CNAME": {"app.acme.com"}})
	curr.Data.DNS.Dangling = &snapshot.DanglingCNAME{
		Target: "gone.azurewebsites.net", TakeableService: "azurewebsites.net",
		Reason: "CNAME target NXDOMAIN and matches takeable service azurewebsites.net",
	}
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "dns.dangling_cname")
	if c == nil || c.Severity != SevCritical {
		t.Fatalf("takeable dangling CNAME must be critical: %+v", c)
	}
	curr.Data.DNS.Dangling.TakeableService = ""
	c = find(Snapshots(prev, curr, Options{Now: testNow}), "dns.dangling_cname")
	if c == nil || c.Severity != SevMedium {
		t.Fatalf("non-takeable dangling CNAME must be medium: %+v", c)
	}
}

func TestDNS_QuorumDisagreementConfidence(t *testing.T) {
	prev := dnsDoc(map[string][]string{"A": {"203.0.113.10"}})
	curr := dnsDoc(map[string][]string{"A": {"203.0.113.11"}})
	curr.Data.DNS.Quorum = snapshot.Quorum{Resolvers: 3, Agreeing: 2, Disagreed: []string{"9.9.9.9"}}
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "dns.records_changed")
	if c == nil || c.Confidence != ConfPossible {
		t.Fatalf("resolver disagreement must be confidence possible: %+v", c)
	}
}

func TestTLS_CertChangedClassification(t *testing.T) {
	// Same CA + continuity → info.
	prev := tlsDoc("aa", "CN=CA One", "1.3", 100, true)
	curr := tlsDoc("bb", "CN=CA One", "1.3", 90, true)
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "tls.cert_changed")
	if c == nil || c.Severity != SevInfo {
		t.Fatalf("same-CA rotation must be info: %+v", c)
	}
	// CA change → high.
	curr = tlsDoc("bb", "CN=CA Two", "1.3", 90, true)
	c = find(Snapshots(prev, curr, Options{Now: testNow}), "tls.cert_changed")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("CA change must be high: %+v", c)
	}
	// Self-signed appearing → high.
	prev2 := tlsDoc("aa", "CN=CA One", "1.3", 100, true)
	curr2 := tlsDoc("bb", "CN=CA One", "1.3", 90, true)
	curr2.Data.TLS.Leaf.SelfSigned = true
	c = find(Snapshots(prev2, curr2, Options{Now: testNow}), "tls.cert_changed")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("self-signed appearing must be high: %+v", c)
	}
}

func TestTLS_ExpiryFacts(t *testing.T) {
	prev := tlsDoc("aa", "CN=CA", "1.3", 37, true)
	curr := tlsDoc("aa", "CN=CA", "1.3", 6, true)
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "tls.cert_expiring")
	if c == nil || c.Severity != SevHigh || c.Confidence != ConfConfirmed {
		t.Fatalf("≤7d expiry must be high 1-shot confirmed: %+v", c)
	}
	curr = tlsDoc("aa", "CN=CA", "1.3", -2, true)
	c = find(Snapshots(prev, curr, Options{Now: testNow}), "tls.cert_expired")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("expired must be high: %+v", c)
	}
}

func TestTLS_DowngradeAndMismatch(t *testing.T) {
	prev := tlsDoc("aa", "CN=CA", "1.3", 100, true)
	curr := tlsDoc("aa", "CN=CA", "1.1", 100, true)
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "tls.protocol_downgrade")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("downgrade to 1.1 must be high: %+v", c)
	}
	curr2 := tlsDoc("aa", "CN=CA", "1.3", 100, false)
	c = find(Snapshots(prev, curr2, Options{Now: testNow}), "tls.hostname_mismatch")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("hostname mismatch must be high: %+v", c)
	}
}

func TestHTTP_StatusClassTransitions(t *testing.T) {
	// 200→200 never emits.
	prev := httpDoc(200, "Home", "aaaabbbbccccdddd", 1000, nil, nil)
	curr := httpDoc(204, "Home", "aaaabbbbccccdddd", 1000, nil, nil)
	if c := find(Snapshots(prev, curr, Options{Now: testNow}), "http.status_changed"); c != nil {
		t.Fatal("200→204 must not emit")
	}
	// 2xx→5xx is high.
	curr = httpDoc(503, "", "aaaabbbbccccdddd", 1000, nil, nil)
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "http.status_changed")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("2xx→5xx must be high: %+v", c)
	}
	// Parked signature.
	curr = httpDoc(200, "This domain is for sale", "aaaabbbbccccdddd", 1000, nil, nil)
	c = find(Snapshots(prev, curr, Options{Now: testNow}), "http.status_changed")
	if c == nil || c.Severity != SevMedium {
		t.Fatalf("parked signature must be medium: %+v", c)
	}
}

func TestHTTP_ContentThresholds(t *testing.T) {
	prev := httpDoc(200, "Home", "0000000000000000", 1000, nil, nil)
	// Small change (distance 1, no size delta) → silent.
	curr := httpDoc(200, "Home", "0000000000000001", 1000, nil, nil)
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "http.content_changed")
	if c == nil || !c.Silent {
		t.Fatalf("sub-threshold content change must be silent: %+v", c)
	}
	// >40 % size delta → medium.
	curr = httpDoc(200, "Home", "0000000000000001", 1500, nil, nil)
	c = find(Snapshots(prev, curr, Options{Now: testNow}), "http.content_changed")
	if c == nil || c.Silent || c.Severity != SevMedium {
		t.Fatalf("40%% size delta must emit medium: %+v", c)
	}
	// distance > 24 → high only on critical assets.
	curr = httpDoc(200, "Home", "ffffffffffffffff", 1000, nil, nil)
	c = find(Snapshots(prev, curr, Options{Now: testNow, Criticality: "low"}), "http.content_changed")
	if c == nil || c.Severity != SevMedium {
		t.Fatalf("distance 64 on low asset must be medium: %+v", c)
	}
	c = find(Snapshots(prev, curr, Options{Now: testNow, Criticality: "critical"}), "http.content_changed")
	if c == nil || c.Severity != SevHigh {
		t.Fatalf("distance 64 on critical asset must be high: %+v", c)
	}
}

func TestHTTP_HeadersAndTech(t *testing.T) {
	prev := httpDoc(200, "Home", "aaaabbbbccccdddd", 1000,
		map[string]string{"server": "nginx", "x-frame-options": "DENY"},
		[]snapshot.Tech{{Name: "nginx", Confidence: "sure"}})
	curr := httpDoc(200, "Home", "aaaabbbbccccdddd", 1000,
		map[string]string{"server": "nginx", "content-security-policy": "default-src 'self'"},
		[]snapshot.Tech{{Name: "nginx", Confidence: "sure"}, {Name: "react", Confidence: "likely"}})
	got := Snapshots(prev, curr, Options{Now: testNow})
	if find(got, "http.headers_changed") == nil {
		t.Fatalf("header add/remove must emit: %v", got)
	}
	if c := find(got, "http.tech_added"); c == nil {
		t.Fatalf("tech added must emit: %v", got)
	}
	if c := find(got, "http.tech_removed"); c != nil {
		t.Fatal("no tech removed")
	}
}

func TestHTTP_RedirectTarget(t *testing.T) {
	prev := httpDoc(200, "Home", "aaaabbbbccccdddd", 1000, nil, nil)
	prev.Data.HTTP.RedirectChain = []string{"http://api.acme.com/"}
	prev.Data.HTTP.FinalURL = "https://api.acme.com/"
	curr := httpDoc(200, "Home", "aaaabbbbccccdddd", 1000, nil, nil)
	curr.Data.HTTP.RedirectChain = []string{"http://api.acme.com/"}
	curr.Data.HTTP.FinalURL = "https://www.acme.com/"
	c := find(Snapshots(prev, curr, Options{Now: testNow}), "http.redirect_target_changed")
	if c == nil || c.Severity != SevMedium {
		t.Fatalf("redirect target change must be medium: %+v", c)
	}
}

func TestTCP_PortTransitions(t *testing.T) {
	prev := &snapshot.Document{ProbeType: snapshot.ProbeTCPPort, Status: snapshot.StatusOK,
		Data: snapshot.Data{TCP: &snapshot.TCPData{Ports: []snapshot.PortState{
			{Port: 443, State: "open"}, {Port: 22, State: "closed"},
		}}}}
	curr := &snapshot.Document{ProbeType: snapshot.ProbeTCPPort, Status: snapshot.StatusOK,
		Data: snapshot.Data{TCP: &snapshot.TCPData{Ports: []snapshot.PortState{
			{Port: 443, State: "closed"}, {Port: 22, State: "open"},
		}}}}
	got := Snapshots(prev, curr, Options{Now: testNow})
	c := find(got, "port.opened")
	if c == nil || c.Severity != SevHigh { // 22 is admin class
		t.Fatalf("admin port opened must be high: %+v", c)
	}
	if len(c.Followups) == 0 {
		t.Fatal("port.opened must suggest detect.scan")
	}
	if c := find(got, "port.closed"); c == nil || c.Severity != SevLow {
		t.Fatalf("port closed must be low: %+v", c)
	}
}

func TestPassive_DowngradesConfirmedToProbable(t *testing.T) {
	prev := tlsDoc("aa", "CN=CA", "1.3", 37, true)
	curr := tlsDoc("aa", "CN=CA", "1.3", 6, true)
	c := find(Snapshots(prev, curr, Options{Now: testNow, Passive: true}), "tls.cert_expiring")
	if c == nil || c.Confidence != ConfProbable {
		t.Fatalf("passive mode must mark probable (doc 03 §5.3): %+v", c)
	}
}
