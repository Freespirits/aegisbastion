package ctlog

import (
	"context"
	"testing"
	"time"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"
)

type fakeCandStore struct{ inserted []string }

func (f *fakeCandStore) InsertCandidate(_ context.Context, missionID, identifier, kind, scopeMatch string, _ []byte) (bool, error) {
	f.inserted = append(f.inserted, identifier+":"+scopeMatch)
	return true, nil
}

type fakeSink struct{ got []Candidate }

func (f *fakeSink) OnCandidate(_ context.Context, c Candidate) error {
	f.got = append(f.got, c)
	return nil
}

func TestPoller_ScopeDiscipline(t *testing.T) {
	src := NewFixtureSource()
	// Anchored to the wall clock: Register's first-poll backfill window
	// (lastPoll = now-24h, minus the 10-min overlap) filters entries older
	// than ~24h, so a hardcoded date turns this test into a time bomb.
	now := time.Now().UTC()
	src.Entries["acme.com"] = []CertName{
		{Name: "grafana.acme.com", CN: "grafana.acme.com", Log: "fixture", NotBefore: now},
		{Name: "status.acme.com", CN: "status.acme.com", Log: "fixture", NotBefore: now},
		{Name: "sister-other.com", CN: "sister-other.com", Log: "fixture", NotBefore: now},
	}
	st := &fakeCandStore{}
	sink := &fakeSink{}
	feeds := NewFeedRegistry()
	feeds.Register(Feed{
		MissionID: "msn_1", ROEID: "roe_1", Domain: "acme.com",
		Scope: &sdkscope.Scope{
			Domains:          []string{"acme.com", "*.acme.com"},
			ExplicitExcludes: []string{"status.acme.com"},
		},
	})
	p := NewPoller(src, st, feeds, sink)
	p.Now = func() time.Time { return now }
	p.pollRound(context.Background())

	byName := map[string]Candidate{}
	for _, c := range sink.got {
		byName[c.Name] = c
	}
	if byName["grafana.acme.com"].ScopeMatch != monitorv1.ScopeMatch_SCOPE_MATCH_IN_SCOPE {
		t.Fatalf("grafana scope_match = %v", byName["grafana.acme.com"].ScopeMatch)
	}
	if byName["grafana.acme.com"].Confidence != "probable" {
		t.Fatalf("passive confidence = %q", byName["grafana.acme.com"].Confidence)
	}
	if byName["status.acme.com"].ScopeMatch != monitorv1.ScopeMatch_SCOPE_MATCH_EXCLUDED {
		t.Fatalf("excluded scope_match = %v", byName["status.acme.com"].ScopeMatch)
	}
	// Excluded candidates are never stored (doc 03 §9.4).
	for _, ins := range st.inserted {
		if ins == "status.acme.com:excluded" {
			t.Fatal("excluded candidate must not be stored")
		}
	}
	// out_of_scope via fixture must be classified such when the source
	// returns adjacent names (the crt.sh source filters sideways matches;
	// fixtures may not) — assert on stored metadata-only semantics.
	stored := map[string]bool{}
	for _, ins := range st.inserted {
		stored[ins] = true
	}
	if !stored["grafana.acme.com:in_scope"] {
		t.Fatalf("in-scope candidate not stored: %v", st.inserted)
	}
}

func TestPoller_ClassifyOutOfScope(t *testing.T) {
	p := NewPoller(NewFixtureSource(), &fakeCandStore{}, NewFeedRegistry(), &fakeSink{})
	f := Feed{MissionID: "msn_1", Domain: "acme.com",
		Scope: &sdkscope.Scope{Domains: []string{"acme.com", "*.acme.com"}}}
	c := p.classify(f, CertName{Name: "evil-acme.com"})
	if c.ScopeMatch != monitorv1.ScopeMatch_SCOPE_MATCH_OUT_OF_SCOPE {
		t.Fatalf("scope_match = %v, want out_of_scope", c.ScopeMatch)
	}
	c = p.classify(f, CertName{Name: "acme.com"})
	if c.ScopeMatch != monitorv1.ScopeMatch_SCOPE_MATCH_IN_SCOPE || c.Kind != "domain" {
		t.Fatalf("apex classification wrong: %+v", c)
	}
}

func TestFeedRegistry_RegisterDetach(t *testing.T) {
	r := NewFeedRegistry()
	r.Register(Feed{MissionID: "msn_1", Domain: "acme.com"})
	r.Register(Feed{MissionID: "msn_1", Domain: "acme.com"}) // idempotent refresh
	if got := len(r.List()); got != 1 {
		t.Fatalf("feeds = %d", got)
	}
	r.Detach("msn_1", "acme.com")
	if got := len(r.List()); got != 0 {
		t.Fatalf("feeds after detach = %d", got)
	}
}
