package scope

import "testing"

func TestCanonicalize(t *testing.T) {
	cases := map[string]string{
		"api.acme.com":                    "api.acme.com",
		"API.Acme.COM.":                   "api.acme.com",
		"https://api.acme.com/graphql":    "api.acme.com",
		"HTTPS://API.acme.com:8443/x?q=1": "api.acme.com",
		"http://user@api.acme.com/path":   "api.acme.com",
		"api.acme.com:8080":               "api.acme.com",
		"api.acme.com/path":               "api.acme.com",
		"203.0.113.10":                    "203.0.113.10",
		"203.0.113.10:443":                "203.0.113.10",
		"[2001:db8::1]:443":               "2001:db8::1",
		"  api.acme.com  ":                "api.acme.com",
		"":                                "",
		"   ":                             "",
	}
	for in, want := range cases {
		if got := Canonicalize(in); got != want {
			t.Errorf("Canonicalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func testScope() *Scope {
	return &Scope{
		Domains:  []string{"acme.com", "*.acme.com", "198.51.100.7"},
		CIDRs:    []string{"203.0.113.0/24"},
		Excludes: []string{"status.acme.com", "203.0.113.99", "10.0.0.0/8"},
	}
}

func TestCheckIncludes(t *testing.T) {
	s := testScope()
	inScope := []string{
		"acme.com",               // exact host
		"api.acme.com",           // wildcard subdomain
		"deep.sub.acme.com",      // nested subdomain
		"https://API.ACME.com/x", // canonicalized URL form
		"198.51.100.7",           // literal IP include
		"203.0.113.10",           // CIDR include
		"203.0.113.10:8443",      // CIDR include, port stripped
	}
	for _, target := range inScope {
		if v := s.Check(target); v != InScope {
			t.Errorf("Check(%q) = %v, want IN_SCOPE", target, v)
		}
	}
}

func TestCheckOutOfScope(t *testing.T) {
	s := testScope()
	out := []string{
		"evilacme.com", // suffix look-alike must NOT match
		"notacme.com.evil.io",
		"example.com",
		"192.0.2.1",    // outside CIDR
		"203.0.114.10", // adjacent network
		"",             // unparseable → fail-closed
	}
	for _, target := range out {
		if v := s.Check(target); v != OutOfScope {
			t.Errorf("Check(%q) = %v, want OUT_OF_SCOPE", target, v)
		}
	}
}

func TestWildcardDoesNotMatchApex(t *testing.T) {
	s := &Scope{Domains: []string{"*.acme.com"}}
	if v := s.Check("acme.com"); v != OutOfScope {
		t.Errorf("wildcard must not match apex: Check(acme.com) = %v", v)
	}
	if v := s.Check("api.acme.com"); v != InScope {
		t.Errorf("wildcard must match subdomain: Check(api.acme.com) = %v", v)
	}
}

func TestExclusionsAlwaysWin(t *testing.T) {
	s := testScope()
	excluded := []string{
		"status.acme.com",          // exact exclusion beats wildcard include
		"https://status.acme.com/", // canonicalized exclusion
		"v1.status.acme.com",       // subdomain of excluded host also excluded
		"203.0.113.99",             // IP exclusion beats CIDR include
		"203.0.113.99:443",         // canonicalized IP exclusion
	}
	for _, target := range excluded {
		if v := s.Check(target); v != Excluded {
			t.Errorf("Check(%q) = %v, want EXCLUDED (exclusions always win)", target, v)
		}
	}
	// Excluded CIDR wins over any include.
	s2 := &Scope{Domains: []string{"*"}, Excludes: []string{"10.0.0.0/8"}}
	if v := s2.Check("10.1.2.3"); v != Excluded {
		t.Errorf("excluded CIDR: Check(10.1.2.3) = %v, want EXCLUDED", v)
	}
}

func TestCheckAll(t *testing.T) {
	s := testScope()
	if err := s.CheckAll([]string{"acme.com", "api.acme.com", "203.0.113.5"}); err != nil {
		t.Errorf("CheckAll in-scope: %v", err)
	}
	if err := s.CheckAll([]string{"acme.com", "status.acme.com"}); err == nil {
		t.Error("CheckAll must fail on excluded target")
	}
	if err := s.CheckAll([]string{"acme.com", "evil.io"}); err == nil {
		t.Error("CheckAll must fail on out-of-scope target")
	}
}

func TestMatchCapabilityPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"stress.*", "stress.http_flood", true},
		{"stress.*", "stress.dns_amp", true},
		{"stress.*", "detect.scan", false},
		{"detect.scan", "detect.scan", true},
		{"detect.scan", "detect.scan.web", false},
		{"monitor.watch", "monitor.watch", true},
	}
	for _, c := range cases {
		if got := MatchCapabilityPattern(c.pattern, c.name); got != c.want {
			t.Errorf("MatchCapabilityPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
