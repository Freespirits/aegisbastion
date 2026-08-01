package scopecanon

import "testing"

func TestCanonical(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"https://shop.acme.com/path?q=1", "shop.acme.com", true},
		{"http://shop.acme.com:8443/", "shop.acme.com", true},
		{"SHOP.ACME.COM.", "shop.acme.com", true},
		{"shop.acme.com:443", "shop.acme.com", true},
		{"203.0.113.10", "203.0.113.10", true},
		{"https://user@shop.acme.com", "shop.acme.com", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"", "", false},
		{"https://", "", false},
		{"*.acme.com", "*.acme.com", true},
		{"203.0.113.0/24", "203.0.113.0/24", true},
	}
	for _, c := range cases {
		got, ok := Canonical(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Canonical(%q) = %q,%v; want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMatchEntry(t *testing.T) {
	cases := []struct {
		entry, target string
		want          bool
	}{
		{"acme.com", "acme.com", true},
		{"acme.com", "shop.acme.com", false},  // exact host only
		{"*.acme.com", "shop.acme.com", true}, // wildcard subdomain
		{"*.acme.com", "acme.com", true},      // wildcard covers apex
		{"*.acme.com", "evilacme.com", false}, // dot-boundary enforced
		{"*.acme.com", "acme.com.evil.org", false},
		{"203.0.113.0/24", "203.0.113.10", true},
		{"203.0.113.0/24", "203.0.114.10", false},
		{"203.0.113.0/24", "shop.acme.com", false}, // CIDR only matches IPs
		{"203.0.113.10", "203.0.113.10", true},
		{"203.0.113.10", "203.0.113.11", false},
		{"https://shop.acme.com", "shop.acme.com", true},
	}
	for _, c := range cases {
		if got := MatchEntry(c.entry, c.target); got != c.want {
			t.Errorf("MatchEntry(%q, %q) = %v; want %v", c.entry, c.target, got, c.want)
		}
	}
}

func TestEvaluateExclusionsAlwaysWin(t *testing.T) {
	includes := []string{"*.acme.com", "203.0.113.0/24"}
	excludes := []string{"legacy.acme.com", "203.0.113.50"}

	in, ex := Evaluate(includes, excludes, "shop.acme.com")
	if !in || ex {
		t.Errorf("shop.acme.com should be in scope, got in=%v excluded=%v", in, ex)
	}
	in, ex = Evaluate(includes, excludes, "legacy.acme.com")
	if in || !ex {
		t.Errorf("legacy.acme.com must be excluded (exclusions win), got in=%v excluded=%v", in, ex)
	}
	in, ex = Evaluate(includes, excludes, "203.0.113.50")
	if in || !ex {
		t.Errorf("203.0.113.50 must be excluded, got in=%v excluded=%v", in, ex)
	}
	in, ex = Evaluate(includes, excludes, "203.0.113.51")
	if !in || ex {
		t.Errorf("203.0.113.51 should be in scope, got in=%v excluded=%v", in, ex)
	}
	in, ex = Evaluate(includes, excludes, "other.org")
	if in || ex {
		t.Errorf("other.org should be out of scope, got in=%v excluded=%v", in, ex)
	}
	// Wildcard exclusion wins over wildcard include.
	in, ex = Evaluate([]string{"*.acme.com"}, []string{"*.internal.acme.com"}, "db.internal.acme.com")
	if in || !ex {
		t.Errorf("db.internal.acme.com must be excluded via wildcard exclusion, got in=%v excluded=%v", in, ex)
	}
}
