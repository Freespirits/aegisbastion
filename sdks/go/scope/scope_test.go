package scope

import (
	"testing"
)

func TestCanonicalize_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantErr   bool
		wantKind  Kind
		wantCanon string
		wantHost  string
	}{
		{name: "plain host", in: "api.acme.com", wantKind: KindHost, wantCanon: "api.acme.com", wantHost: "api.acme.com"},
		{name: "case folded", in: "API.Acme.COM", wantKind: KindHost, wantCanon: "api.acme.com", wantHost: "api.acme.com"},
		{name: "trailing dot stripped", in: "api.acme.com.", wantKind: KindHost, wantCanon: "api.acme.com", wantHost: "api.acme.com"},
		{name: "host:port", in: "api.acme.com:8443", wantKind: KindHost, wantCanon: "api.acme.com", wantHost: "api.acme.com"},
		{name: "ipv4", in: "203.0.113.10", wantKind: KindIP, wantCanon: "203.0.113.10", wantHost: "203.0.113.10"},
		{name: "ipv6 canonicalized", in: "2001:DB8::1", wantKind: KindIP, wantCanon: "2001:db8::1"},
		{name: "cidr masked", in: "203.0.113.7/24", wantKind: KindCIDR, wantCanon: "203.0.113.0/24"},
		{name: "https url", in: "https://API.Acme.COM/graphql", wantKind: KindURL, wantCanon: "https://api.acme.com/graphql", wantHost: "api.acme.com"},
		{name: "url default port stripped", in: "https://api.acme.com:443/x", wantKind: KindURL, wantCanon: "https://api.acme.com/x", wantHost: "api.acme.com"},
		{name: "url non-default port kept", in: "http://api.acme.com:8080/x?q=1", wantKind: KindURL, wantCanon: "http://api.acme.com:8080/x?q=1", wantHost: "api.acme.com"},
		{name: "url userinfo+fragment dropped", in: "https://user:pw@api.acme.com/x#frag", wantKind: KindURL, wantCanon: "https://api.acme.com/x", wantHost: "api.acme.com"},
		{name: "url with ip host", in: "https://203.0.113.10/admin", wantKind: KindURL, wantCanon: "https://203.0.113.10/admin", wantHost: "203.0.113.10"},
		{name: "empty", in: "  ", wantErr: true},
		{name: "wildcard not a target", in: "*.acme.com", wantErr: true},
		{name: "illegal chars", in: "api.acme.com/x", wantErr: true},
		{name: "bad url", in: "https://", wantErr: true},
		{name: "single colon junk port", in: "api.acme.com:https", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Canonicalize(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize(%q) error = %v", tc.in, err)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", got.Kind, tc.wantKind)
			}
			if got.Canonical != tc.wantCanon {
				t.Errorf("canonical = %q, want %q", got.Canonical, tc.wantCanon)
			}
			if tc.wantHost != "" && got.Host != tc.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tc.wantHost)
			}
		})
	}
}

func testScope() *Scope {
	return &Scope{
		Domains:          []string{"acme.com", "*.acme.com", "exact.example.org"},
		CIDRs:            []string{"203.0.113.0/24", "10.0.0.0/8"},
		ExplicitExcludes: []string{"status.acme.com", "203.0.113.99", "10.9.0.0/16"},
	}
}

func TestEvaluate_TableDriven(t *testing.T) {
	cases := []struct {
		name         string
		scope        *Scope
		target       string
		wantAllowed  bool
		wantExcluded bool
	}{
		// Includes.
		{name: "exact host matches", scope: testScope(), target: "acme.com", wantAllowed: true},
		{name: "exact host via URL", scope: testScope(), target: "https://acme.com/path", wantAllowed: true},
		{name: "exact other domain", scope: testScope(), target: "exact.example.org", wantAllowed: true},
		{name: "wildcard matches subdomain", scope: testScope(), target: "api.acme.com", wantAllowed: true},
		{name: "wildcard matches deep subdomain", scope: testScope(), target: "a.b.acme.com", wantAllowed: true},
		{name: "wildcard matches via URL", scope: testScope(), target: "https://api.acme.com:8443/v1", wantAllowed: true},
		{name: "wildcard does NOT match apex", scope: &Scope{Domains: []string{"*.acme.com"}}, target: "acme.com", wantAllowed: false},
		{name: "wildcard does not match sibling", scope: testScope(), target: "evil-acme.com", wantAllowed: false},
		{name: "suffix trick does not match", scope: testScope(), target: "notacme.com", wantAllowed: false},
		{name: "CIDR contains ip", scope: testScope(), target: "203.0.113.10", wantAllowed: true},
		{name: "CIDR contains ip via URL", scope: testScope(), target: "https://203.0.113.10/x", wantAllowed: true},
		{name: "CIDR outside denied", scope: testScope(), target: "198.51.100.7", wantAllowed: false},
		{name: "hostname not forced into CIDR (no DNS)", scope: &Scope{CIDRs: []string{"203.0.113.0/24"}}, target: "api.acme.com", wantAllowed: false},

		// Exclusions ALWAYS WIN (doc 01 §5.4/§10.1).
		{name: "excluded host inside wildcard", scope: testScope(), target: "status.acme.com", wantAllowed: false, wantExcluded: true},
		{name: "excluded host via URL", scope: testScope(), target: "https://status.acme.com/health", wantAllowed: false, wantExcluded: true},
		{name: "excluded ip inside CIDR", scope: testScope(), target: "203.0.113.99", wantAllowed: false, wantExcluded: true},
		{name: "excluded CIDR inside included CIDR", scope: testScope(), target: "10.9.1.2", wantAllowed: false, wantExcluded: true},
		{name: "exclusion only, no includes at all", scope: &Scope{ExplicitExcludes: []string{"acme.com"}}, target: "acme.com", wantAllowed: false, wantExcluded: true},

		// Fail-closed (doc 03 §9.2, Ruling A.5).
		{name: "nil scope fails closed", scope: nil, target: "acme.com", wantAllowed: false},
		{name: "empty scope fails closed", scope: &Scope{}, target: "acme.com", wantAllowed: false},
		{name: "unparseable target fails closed", scope: testScope(), target: "ht tp://broken host", wantAllowed: false},
		{name: "empty target fails closed", scope: testScope(), target: "", wantAllowed: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.scope.Evaluate(tc.target)
			if got.Allowed != tc.wantAllowed {
				t.Errorf("Evaluate(%q).Allowed = %v, want %v (reason: %s)", tc.target, got.Allowed, tc.wantAllowed, got.Reason)
			}
			if got.Excluded != tc.wantExcluded {
				t.Errorf("Evaluate(%q).Excluded = %v, want %v", tc.target, got.Excluded, tc.wantExcluded)
			}
		})
	}
}

func TestEvaluate_LongestPrefixRule(t *testing.T) {
	// The deciding rule reported is the most specific (longest-prefix) match.
	s := &Scope{
		CIDRs: []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"},
	}
	d := s.Evaluate("10.1.2.7")
	if !d.Allowed {
		t.Fatalf("denied: %s", d.Reason)
	}
	if d.Rule != "10.1.2.0/24" {
		t.Fatalf("rule = %q, want longest prefix 10.1.2.0/24", d.Rule)
	}

	// Same for exclusions: the most specific exclusion is reported.
	s2 := &Scope{
		Domains:          []string{"*.acme.com"},
		ExplicitExcludes: []string{"203.0.113.0/24", "203.0.113.99"},
	}
	d2 := s2.Evaluate("203.0.113.99")
	if !d2.Excluded {
		t.Fatalf("not excluded: %+v", d2)
	}
	if d2.Rule != "203.0.113.99" {
		t.Fatalf("exclusion rule = %q, want exact IP", d2.Rule)
	}
}
