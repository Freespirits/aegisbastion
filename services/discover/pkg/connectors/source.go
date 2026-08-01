package connectors

import (
	"context"
	"sync"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// EdgeRef is an inferred asset edge with endpoints as asset identities (the
// reducer upserts endpoints, then resolves ids).
type EdgeRef = model.EdgeRef

// Finding is one parsed record from a source response.
type Finding struct {
	Asset          model.Asset
	Edges          []EdgeRef
	ConfidenceHint float64 // 0 ⇒ reducer uses the doc 02 §4.4 source weight
	EvidenceURI    string  // set by the worker when the raw body is archived
}

// ParseFunc converts a recorded/live source body into findings. Pure — this
// is the unit fixture tests exercise.
type ParseFunc func(body []byte, in RunInput) ([]Finding, error)

// RequestFunc builds the source request. apiKey is empty for keyless sources.
type RequestFunc func(in RunInput, apiKey string) (*Request, error)

// httpSource is the shared engine for request/response connectors: build →
// rate/circuit gate (registry) → fetch → parse → emit.
type httpSource struct {
	name          string
	techniques    []model.Technique
	rate          RateSpec
	requiresCreds bool
	fetch         Fetcher
	keys          KeyProvider
	buildReq      RequestFunc
	parse         ParseFunc

	// Archive, when set, stores the raw source response body (doc 02 §2.2
	// object store) and returns its evidence URI. Best-effort: a failure
	// degrades to "" and never fails the task. Wired by the worker.
	Archive func(ctx context.Context, body []byte) string

	mu     sync.Mutex
	health Health
}

func (s *httpSource) Name() string                  { return s.name }
func (s *httpSource) Techniques() []model.Technique { return s.techniques }
func (s *httpSource) RateSpec() RateSpec            { return s.rate }
func (s *httpSource) RequiresCredentials() bool     { return s.requiresCreds }

func (s *httpSource) Healthcheck(context.Context) Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health == "" {
		return HealthOK
	}
	return s.health
}

func (s *httpSource) setHealth(h Health) {
	s.mu.Lock()
	s.health = h
	s.mu.Unlock()
}

// Run implements Connector. Each parsed Finding is emitted as a
// model.RawFinding plus its (possibly empty) edge list.
func (s *httpSource) Run(ctx context.Context, in RunInput, emit EmitFunc) error {
	var apiKey string
	if s.requiresCreds {
		if s.keys == nil {
			s.setHealth(HealthDegraded)
			return &CredentialError{Connector: s.name}
		}
		key, err := s.keys.APIKey(ctx, in.Task.TenantID, s.name)
		if err != nil {
			s.setHealth(HealthDegraded)
			return &CredentialError{Connector: s.name, Err: err}
		}
		apiKey = key
	}
	req, err := s.buildReq(in, apiKey)
	if err != nil {
		return err
	}
	body, err := s.fetch.Fetch(ctx, req)
	if err != nil {
		s.setHealth(HealthDegraded)
		return err
	}
	evidenceURI := ""
	if s.Archive != nil {
		evidenceURI = s.Archive(ctx, body)
	}
	findings, err := s.parse(body, in)
	if err != nil {
		s.setHealth(HealthDegraded)
		return err
	}
	s.setHealth(HealthOK)
	for _, f := range findings {
		uri := f.EvidenceURI
		if uri == "" {
			uri = evidenceURI
		}
		rf := model.RawFinding{
			TaskID:         in.Task.TaskID,
			OrderID:        in.Task.OrderID,
			Asset:          f.Asset,
			Source:         s.name,
			ObservedAt:     observedAt(in),
			EvidenceURI:    uri,
			ConfidenceHint: f.ConfidenceHint,
		}
		if err := emit(rf, f.Edges); err != nil {
			return err
		}
	}
	return nil
}

func observedAt(in RunInput) time.Time {
	if !in.ObservedAt.IsZero() {
		return in.ObservedAt
	}
	return time.Now().UTC()
}

// CredentialError marks missing per-tenant source credentials — the task
// fails SOURCE_UNAVAILABLE-style and the connector reports degraded.
type CredentialError struct {
	Connector string
	Err       error
}

func (e *CredentialError) Error() string {
	if e.Err != nil {
		return "connectors: " + e.Connector + ": credentials: " + e.Err.Error()
	}
	return "connectors: " + e.Connector + ": credentials required but not configured"
}

func (e *CredentialError) Unwrap() error { return e.Err }
