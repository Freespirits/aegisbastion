package probes

import (
	"context"
	"fmt"
	"sync"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// FixtureProbe is a deterministic probe for tests and the seeded harness
// (doc 03 §15): canned documents per (probe_type, target), scriptable in
// sequence to simulate change over time. Zero network access.
type FixtureProbe struct {
	probeType string

	mu        sync.Mutex
	frames    map[string][]*snapshot.Document // target → successive documents
	calls     map[string]int
	rawBodies map[string][]byte
}

// NewFixtureProbe builds a fixture executor for probeType ("dns"|"tls"|"http").
func NewFixtureProbe(probeType string) *FixtureProbe {
	return &FixtureProbe{
		probeType: probeType,
		frames:    map[string][]*snapshot.Document{},
		calls:     map[string]int{},
		rawBodies: map[string][]byte{},
	}
}

// SetFrames scripts the successive observations for target: call N returns
// frame min(N, len-1). Documents are cloned shallowly and stamped per call.
func (f *FixtureProbe) SetFrames(target string, docs ...*snapshot.Document) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames[target] = docs
}

// SetRawBody scripts a raw HTTP body for target.
func (f *FixtureProbe) SetRawBody(target string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawBodies[target] = body
}

// Calls reports how many times target was probed (harness request counters,
// doc 03 §15 acceptance test 3: zero target contact in passive-only mode).
func (f *FixtureProbe) Calls(target string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[target]
}

// TotalCalls reports the sum of probe calls across targets.
func (f *FixtureProbe) TotalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

// Type implements Probe.
func (f *FixtureProbe) Type() string { return f.probeType }

// Probe implements Probe — deterministic, offline.
func (f *FixtureProbe) Probe(_ context.Context, req Request) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	frames, ok := f.frames[req.Target]
	if !ok || len(frames) == 0 {
		return nil, fmt.Errorf("fixture: no frames for %s probe on %q", f.probeType, req.Target)
	}
	n := f.calls[req.Target]
	f.calls[req.Target] = n + 1
	if n >= len(frames) {
		n = len(frames) - 1
	}
	src := frames[n]
	doc := *src
	doc.ProbeType = f.probeType
	doc.AssetID = req.AssetID
	doc.MissionID = req.MissionID
	doc.ProbeTS = req.Now.UTC()
	doc.Observer = snapshot.Observer{WorkerID: req.WorkerID, ResolverSet: "fixture"}
	doc.Authorization = snapshot.Authorization{TokenJTI: req.TokenJTI, ROEVersion: req.ROEVersion}
	return &Result{Doc: &doc, RawBody: f.rawBodies[req.Target]}, nil
}
