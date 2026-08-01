// Package ctlog is the M7 Feed Ingester (doc 03 §3.1): Certificate
// Transparency polling for in-scope domains (MVP: crt.sh JSON API polling —
// doc 03 §10 "polling major logs' get-entries (MVP) → certstream-style
// tailing (Later)"), extracting new names and feeding the new-asset pipeline
// with doc 03 §9.4 out-of-scope discipline:
//
//   - in_scope   → watch-set candidate + monitor.assets.new
//   - out_of_scope → metadata-only record + monitor.assets.new (never probed)
//   - excluded   → audit record only (customer-declared do-not-touch)
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	"github.com/aegisbastion/aegisbastion/sdks/go/scope"
)

// CertName is one name observed in a CT log entry.
type CertName struct {
	Name      string    `json:"name"`
	CN        string    `json:"cn"`
	Log       string    `json:"log"`
	NotBefore time.Time `json:"not_before"`
}

// Source fetches newly-seen cert names for a scope domain (R0 passive —
// no target contact, doc 03 §6.1).
type Source interface {
	FetchNew(ctx context.Context, domain string, since time.Time) ([]CertName, error)
}

// ---------------------------------------------------------------------------
// crt.sh production source
// ---------------------------------------------------------------------------

// CRTSh polls the crt.sh JSON API (CT log aggregate — MVP per doc 03 §10).
type CRTSh struct {
	BaseURL string       // default https://crt.sh
	Client  *http.Client // default 30 s timeout
}

// crtShEntry is the crt.sh JSON row.
type crtShEntry struct {
	NameValue      string `json:"name_value"`
	CommonName     string `json:"common_name"`
	NotBefore      string `json:"not_before"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// FetchNew implements Source.
func (c *CRTSh) FetchNew(ctx context.Context, domain string, since time.Time) ([]CertName, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://crt.sh"
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", strings.TrimSuffix(base, "/"), domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AegisBastion-Monitor/0.1 (CT polling)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ctlog: crt.sh %s: %w", domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctlog: crt.sh %s: status %d", domain, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("ctlog: crt.sh decode: %w", err)
	}
	seen := map[string]bool{}
	var out []CertName
	for _, e := range entries {
		ts := parseCTTime(e.NotBefore)
		if ts.IsZero() {
			ts = parseCTTime(e.EntryTimestamp)
		}
		if !since.IsZero() && ts.Before(since) {
			continue
		}
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			name = strings.TrimSuffix(name, ".")
			if name == "" || seen[name] || !strings.Contains(name, ".") {
				continue
			}
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue // crt.sh substring matches can drift sideways
			}
			seen[name] = true
			out = append(out, CertName{
				Name: name, CN: e.CommonName, Log: "crt.sh", NotBefore: ts,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func parseCTTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ---------------------------------------------------------------------------
// fixture source (tests / seeded harness, doc 03 §15)
// ---------------------------------------------------------------------------

// FixtureSource scripts CT observations per domain.
type FixtureSource struct {
	mu      sync.Mutex
	Entries map[string][]CertName
	Calls   map[string]int
}

// NewFixtureSource builds a fixture.
func NewFixtureSource() *FixtureSource {
	return &FixtureSource{Entries: map[string][]CertName{}, Calls: map[string]int{}}
}

// FetchNew implements Source.
func (f *FixtureSource) FetchNew(_ context.Context, domain string, since time.Time) ([]CertName, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls[domain]++
	var out []CertName
	for _, e := range f.Entries[domain] {
		if !since.IsZero() && e.NotBefore.Before(since) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// feed registry (monitor.feed.sync attaches domains)
// ---------------------------------------------------------------------------

// Feed is one attached passive feed binding.
type Feed struct {
	MissionID string
	ROEID     string
	OrgID     string
	Domain    string
	Scope     *scope.Scope // canonical RoE scope for candidate classification
	lastPoll  time.Time
}

// FeedRegistry tracks attached feeds (monitor.feed.sync, doc 03 §4.2).
type FeedRegistry struct {
	mu    sync.Mutex
	feeds map[string]*Feed // mission|domain
}

// NewFeedRegistry builds an empty registry.
func NewFeedRegistry() *FeedRegistry { return &FeedRegistry{feeds: map[string]*Feed{}} }

// Register attaches (or refreshes) a feed.
func (r *FeedRegistry) Register(f Feed) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := f.MissionID + "|" + f.Domain
	if prev, ok := r.feeds[key]; ok {
		f.lastPoll = prev.lastPoll
	} else {
		f.lastPoll = time.Now().UTC().Add(-24 * time.Hour) // first poll backfills 24 h
	}
	r.feeds[key] = &f
}

// Detach removes a feed (monitor.feed.sync detach — empty domain list
// semantics are owned by the caller).
func (r *FeedRegistry) Detach(missionID, domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.feeds, missionID+"|"+domain)
}

// List snapshots the attached feeds.
func (r *FeedRegistry) List() []Feed {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Feed, 0, len(r.feeds))
	for _, f := range r.feeds {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// markPolled advances the feed cursor.
func (r *FeedRegistry) markPolled(missionID, domain string, ts time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.feeds[missionID+"|"+domain]; ok {
		f.lastPoll = ts
	}
}

// ---------------------------------------------------------------------------
// candidate pipeline
// ---------------------------------------------------------------------------

// Candidate is one classified new-asset observation.
type Candidate struct {
	MissionID  string
	ROEID      string
	OrgID      string
	Domain     string
	Name       string
	Kind       string
	ScopeMatch monitorv1.ScopeMatch
	Source     map[string]any
	Confidence string
}

// CandidateSink receives classified candidates (the coordinator emits
// monitor.assets.new, watch-set additions, and exclusion audit records).
type CandidateSink interface {
	OnCandidate(ctx context.Context, c Candidate) error
}

// CandidateStore records passive candidates (production: *store.Store).
type CandidateStore interface {
	InsertCandidate(ctx context.Context, missionID, identifier, kind, scopeMatch string, source []byte) (bool, error)
}

// Poller is M7. Passive (R0) only — CT polling never contacts targets.
type Poller struct {
	src   Source
	st    CandidateStore
	feeds *FeedRegistry
	sink  CandidateSink

	// Interval between poll rounds (default 5 min).
	Interval time.Duration
	// TryLock elects the single poller replica (doc 03 §3.1: leader-elected
	// via PG advisory lock — main wires store.TryAdvisoryLock). Nil disables
	// leader election (tests, single-replica dev).
	TryLock func(ctx context.Context) (release func(), ok bool, err error)
	Now     func() time.Time
}

// NewPoller builds a Poller.
func NewPoller(src Source, st CandidateStore, feeds *FeedRegistry, sink CandidateSink) *Poller {
	return &Poller{src: src, st: st, feeds: feeds, sink: sink,
		Interval: 5 * time.Minute,
		Now:      func() time.Time { return time.Now().UTC() }}
}

// Run polls until ctx is done. With a TryLock it first wins the leader lock
// (single M7 replica, doc 03 §3.1) and re-contends on loss.
func (p *Poller) Run(ctx context.Context) error {
	if p.TryLock == nil {
		return p.loop(ctx)
	}
	for {
		release, ok, err := p.TryLock(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}
		if !ok {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(15 * time.Second):
				continue
			}
		}
		err = p.loop(ctx)
		release()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			time.Sleep(5 * time.Second)
		}
	}
}

func (p *Poller) loop(ctx context.Context) error {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		p.pollRound(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// pollRound polls every attached feed once.
func (p *Poller) pollRound(ctx context.Context) {
	for _, f := range p.feeds.List() {
		p.pollFeed(ctx, f)
	}
}

// overlap keeps a small re-fetch window so cursor races never skip names
// (dedup via asset_candidates PK makes re-observation idempotent).
const overlap = 10 * time.Minute

func (p *Poller) pollFeed(ctx context.Context, f Feed) {
	since := f.lastPoll.Add(-overlap)
	names, err := p.src.FetchNew(ctx, f.Domain, since)
	if err != nil {
		return // transient; next round retries (feed errors never block probing)
	}
	now := p.Now()
	for _, n := range names {
		c := p.classify(f, n)
		switch c.ScopeMatch {
		case monitorv1.ScopeMatch_SCOPE_MATCH_EXCLUDED:
			// Exclusions are customer-declared do-not-touch: audit record
			// only, never stored (doc 03 §9.4).
			_ = p.sink.OnCandidate(ctx, c)
			continue
		}
		inserted, err := p.st.InsertCandidate(ctx, f.MissionID, c.Name, c.Kind,
			scopeMatchString(c.ScopeMatch), mustJSON(c.Source))
		if err != nil || !inserted {
			continue
		}
		_ = p.sink.OnCandidate(ctx, c)
	}
	p.feeds.markPolled(f.MissionID, f.Domain, now)
}

// classify applies doc 03 §9.4: exclusions win; includes watch; the rest is
// out-of-scope metadata.
func (p *Poller) classify(f Feed, n CertName) Candidate {
	kind := "subdomain"
	if n.Name == f.Domain {
		kind = "domain"
	}
	c := Candidate{
		MissionID: f.MissionID, ROEID: f.ROEID, OrgID: f.OrgID,
		Domain: f.Domain, Name: n.Name, Kind: kind,
		Confidence: "probable", // passive single-source (doc 03 §7.5)
		Source: map[string]any{
			"type": "ct_log",
			"detail": fmt.Sprintf("log:%s, cert cn=%s, first_seen %s",
				n.Log, n.CN, n.NotBefore.Format(time.RFC3339)),
		},
	}
	if f.Scope == nil {
		c.ScopeMatch = monitorv1.ScopeMatch_SCOPE_MATCH_OUT_OF_SCOPE
		return c
	}
	dec := f.Scope.Evaluate(n.Name)
	switch {
	case dec.Excluded:
		c.ScopeMatch = monitorv1.ScopeMatch_SCOPE_MATCH_EXCLUDED
	case dec.Allowed:
		c.ScopeMatch = monitorv1.ScopeMatch_SCOPE_MATCH_IN_SCOPE
	default:
		c.ScopeMatch = monitorv1.ScopeMatch_SCOPE_MATCH_OUT_OF_SCOPE
	}
	return c
}

func scopeMatchString(m monitorv1.ScopeMatch) string {
	switch m {
	case monitorv1.ScopeMatch_SCOPE_MATCH_IN_SCOPE:
		return "in_scope"
	case monitorv1.ScopeMatch_SCOPE_MATCH_EXCLUDED:
		return "excluded"
	case monitorv1.ScopeMatch_SCOPE_MATCH_OUT_OF_SCOPE:
		return "out_of_scope"
	}
	return "unspecified"
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
