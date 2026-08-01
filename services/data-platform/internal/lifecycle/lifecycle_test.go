package lifecycle

import "testing"

func TestLegalEdges(t *testing.T) {
	legal := [][2]State{
		{New, Triaged},
		{Triaged, Validating},
		{Triaged, FalsePositive},
		{Validating, ConfirmedOpen},
		{Validating, AcceptedRisk},
		{ConfirmedOpen, RemediationClaimed},
		{RemediationClaimed, VerifiedClosed},
		{RemediationClaimed, Reopened},
		{Reopened, ConfirmedOpen},
	}
	for _, e := range legal {
		if !Legal(e[0], e[1]) {
			t.Errorf("Legal(%s, %s) = false, want true (doc 04 §7.3)", e[0], e[1])
		}
	}
}

func TestIllegalEdges(t *testing.T) {
	illegal := [][2]State{
		{New, ConfirmedOpen},            // must pass triaged/validating
		{New, VerifiedClosed},           // no shortcut to terminal
		{Triaged, ConfirmedOpen},        // validating required
		{ConfirmedOpen, VerifiedClosed}, // remediation_claimed required
		{VerifiedClosed, Reopened},      // terminal states never leave
		{FalsePositive, New},
		{AcceptedRisk, ConfirmedOpen},
		{New, New}, // self-transition is not an edge
	}
	for _, e := range illegal {
		if Legal(e[0], e[1]) {
			t.Errorf("Legal(%s, %s) = true, want false (doc 04 §7.3)", e[0], e[1])
		}
	}
}

func TestPath(t *testing.T) {
	p, ok := Path(New, VerifiedClosed)
	if !ok {
		t.Fatal("Path(new, verified_closed) not found")
	}
	want := []State{Triaged, Validating, ConfirmedOpen, RemediationClaimed, VerifiedClosed}
	if len(p) != len(want) {
		t.Fatalf("Path = %v, want %v", p, want)
	}
	for i := range want {
		if p[i] != want[i] {
			t.Fatalf("Path = %v, want %v", p, want)
		}
	}
	if _, ok := Path(FalsePositive, New); ok {
		t.Error("Path(false_positive, new) found, want unreachable (terminal)")
	}
	if p, ok := Path(ConfirmedOpen, ConfirmedOpen); !ok || p != nil {
		t.Errorf("Path(self) = %v,%v, want nil,true (no-op)", p, ok)
	}
}

func TestTerminal(t *testing.T) {
	for _, s := range []State{VerifiedClosed, FalsePositive, AcceptedRisk} {
		if !Terminal(s) {
			t.Errorf("Terminal(%s) = false", s)
		}
	}
	for _, s := range []State{New, Triaged, Validating, ConfirmedOpen, RemediationClaimed, Reopened} {
		if Terminal(s) {
			t.Errorf("Terminal(%s) = true", s)
		}
	}
}

func TestParse(t *testing.T) {
	for _, s := range All {
		if _, err := Parse(string(s)); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	if _, err := Parse("open"); err == nil {
		t.Error("Parse(open) accepted — doc 09 §4.2's sketch enum is superseded by doc 04 §7.3")
	}
	if _, err := Parse(""); err == nil {
		t.Error("Parse(\"\") accepted")
	}
}
