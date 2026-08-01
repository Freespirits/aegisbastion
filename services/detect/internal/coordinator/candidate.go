package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"

	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/evs"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/normalize"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/risk"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// pipeline carries one task's candidate-processing state (doc 04 §3.2:
// validation is inline, not a batch afterthought).
type pipeline struct {
	c        *Coordinator
	t        *agentsdk.Task
	emit     *agentsdk.Emitter
	params   *Params
	proxyURL string

	tools *ave.Tools
	dedup *normalize.Dedup

	tokenJTI   string
	roeID      string
	scopeToken string

	counts taskCounts
}

// taskCounts is the task-level rollup (doc 04 §4.4).
type taskCounts struct {
	candidates       int
	confirmed        int
	notReproducible  int
	inconclusive     int
	notValidatable   int
	suppressedFP     int
	severityMax      string
	scoreMax         int
	evidenceFailures int
}

// track folds one verdict into the task counters.
func (c *taskCounts) track(verdict ave.Verdict, severity string, score int) {
	switch verdict {
	case ave.VerdictConfirmed:
		c.confirmed++
	case ave.VerdictNotReproducible:
		c.notReproducible++
	case ave.VerdictNotValidatable:
		c.notValidatable++
	default:
		c.inconclusive++
	}
	if severityRank(severity) > severityRank(c.severityMax) {
		c.severityMax = severity
	}
	if score > c.scoreMax {
		c.scoreMax = score
	}
}

// newPipeline builds the per-task pipeline: run deduper over the cross-run
// view, and the scoped AVE tools (every validator request egresses through
// the task proxy AND the allowlist round-tripper — the application-layer
// re-check in front of the network-layer guard, doc 04 §10.1 layers 3–4;
// the SDK guard authorizes the enumerated targets exactly, so derived-URL
// requests are enforced here and at the proxy).
func newPipeline(c *Coordinator, t *agentsdk.Task, emit *agentsdk.Emitter, params *Params, proxyURL string) *pipeline {
	p := &pipeline{c: c, t: t, emit: emit, params: params, proxyURL: proxyURL, dedup: normalize.NewDedup(c.d.KnownView)}
	if g := t.Guard(); g != nil {
		p.tokenJTI = g.Claims().ID
		p.roeID = g.Claims().ROEID
	}
	p.scopeToken = t.Assignment.GetAuthorizationToken()
	p.tools = &ave.Tools{
		HTTP: scopedHTTPClient(proxyURL, evs.NewAllowlist(appendTargets(t, c.d.OOBBaseURL))),
		OOB:  c.d.OOB,
	}
	return p
}

func appendTargets(t *agentsdk.Task, oobBase string) []string {
	out := append([]string(nil), t.Assignment.GetTargets()...)
	if oobBase != "" {
		out = append(out, oobBase)
	}
	return out
}

// scopedHTTPClient builds an *http.Client whose requests all pass the
// allowlist check (pre-connect, application layer) and egress through the
// task proxy (network layer).
func scopedHTTPClient(proxyURL string, allow *evs.Allowlist) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if proxyURL != "" {
		base.Proxy = http.ProxyURL(parseProxyURL(proxyURL))
	}
	return &http.Client{
		Transport: &allowlistRoundTripper{allow: allow, next: base},
		Timeout:   30 * time.Second,
	}
}

// allowlistRoundTripper refuses out-of-scope requests before they are sent
// (fail-closed; the proxy would refuse them at the network layer anyway).
type allowlistRoundTripper struct {
	allow *evs.Allowlist
	next  http.RoundTripper
}

func (rt *allowlistRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostPort := req.URL.Host
	if !strings.Contains(hostPort, ":") {
		if req.URL.Scheme == "https" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}
	if rt.allow != nil && !rt.allow.Allows(hostPort) {
		return nil, fmt.Errorf("scope guard: %s not in task allowlist (fail-closed)", hostPort)
	}
	return rt.next.RoundTrip(req)
}

// process runs one RawResult through triage → dedup → validate → score →
// publish (doc 04 §3.2). Errors are logged and counted, never fatal to the
// task — one bad candidate must not sink the run.
func (p *pipeline) process(ctx context.Context, raw scanner.RawResult) {
	log := p.c.d.Log.With("task_id", raw.TaskID, "check_id", raw.CheckID)
	p.counts.candidates++

	// --- Fast-path triage (doc 04 §3.2): known-false-positive signatures
	// are suppressed, logged, never published.
	sig := ids.SHA256Hex([]byte(raw.CheckID + "|" + raw.VulnClass))
	if p.c.d.Suppressions != nil {
		suppressed, err := p.c.d.Suppressions.Suppressed(ctx, sig)
		if err != nil {
			log.Warn("suppression lookup failed (treating as unsuppressed)", "err", err)
		} else if suppressed {
			p.counts.suppressedFP++
			log.Info("candidate suppressed (known FP signature)")
			return
		}
	}

	// --- D8 normalize + fingerprint + intra-run/cross-run dedup (§7.2).
	fingerprint := normalize.Fingerprint(
		p.t.Assignment.GetMissionId(), raw.Target, raw.MatchedAt, normalize.VulnIdentity(raw))
	entry, dup, err := p.dedup.Merge(fingerprint, ids.New("fnd"))
	if err != nil {
		log.Error("dedup failed — candidate dropped", "err", err)
		return
	}
	if dup {
		return // merged into the first occurrence (occurrences++)
	}

	// --- D4 AVE validation (doc 04 §6).
	cand := ave.Candidate{
		Target: raw.Target, MatchedAt: raw.MatchedAt, CheckID: raw.CheckID,
		VulnClass: raw.VulnClass, Title: raw.Title, CVE: raw.CVE,
		Severity: raw.Severity, Evidence: raw.Evidence,
	}
	verdict, err := p.c.d.AVE.Validate(ctx, cand, p.tools)
	if err != nil {
		if ctx.Err() != nil {
			return // kill/deadline — the task is ending
		}
		log.Error("validator error — INCONCLUSIVE", "err", err)
		verdict = &ave.Result{Verdict: ave.VerdictInconclusive, Method: "ave.error",
			Confidence: 0.2, Detail: err.Error()}
	}

	// Credential testing requires explicit RoE opt-in (safe_mode=false
	// surfaced through the plan, doc 04 §10.3) — absence = skipped, logged.
	if raw.VulnClass == scanner.ClassDefaultCreds && p.params.SafeMode {
		verdict = &ave.Result{
			Verdict: ave.VerdictInconclusive, Method: "ave.none",
			Confidence: 0.2,
			Detail:     "SKIPPED_NOT_AUTHORIZED: credential testing requires safe_mode=false (RoE opt-in)",
		}
	}

	// --- D5 EVS (doc 04 §7.1 trigger).
	exploitVerified := false
	var evsBundle []byte
	if p.c.d.EVS != nil && evs.ShouldVerify(raw.Severity, verdict.Verdict, p.params.ExploitVerify) {
		evsRes, bundle, verr := p.c.d.EVS.Verify(ctx, cand, p.proxyURL, p.params.SafeMode)
		switch {
		case verr != nil && ctx.Err() != nil:
			return // killed mid-proof; partial evidence preserved in bundle
		case verr != nil:
			log.Error("evs failed — AVE verdict stands", "err", verr)
		case evsRes != nil:
			verdict = evsRes
			evsBundle = bundle
			exploitVerified = evsRes.Verdict == ave.VerdictConfirmed
		}
	}

	// --- D9 evidence (doc 04 §6 evidence contract): CONFIRMED /
	// NOT_REPRODUCIBLE verdicts MUST carry a stored transcript; a CONFIRMED
	// finding without evidence is a contract violation → downgraded.
	evidenceRefs := p.storeEvidence(ctx, raw, verdict, evsBundle, fingerprint)
	if verdict.Verdict == ave.VerdictConfirmed && len(evidenceRefs) == 0 {
		p.counts.evidenceFailures++
		verdict = &ave.Result{
			Verdict: ave.VerdictInconclusive, Method: verdict.Method,
			Confidence: 0.3,
			Detail:     "evidence upload unavailable — CONFIRMED downgraded (doc 04 §12 contract)",
		}
	}

	// --- D6 risk-v1 scoring (doc 04 §8).
	epss, kev := 0.0, false
	if p.c.d.Intel != nil && raw.CVE != "" {
		epss, kev = p.c.d.Intel.Lookup(raw.CVE)
	}
	severity := capSeverity(raw.Severity, verdict.Verdict, raw.VulnClass)
	scored := risk.ScoreFactors(risk.Factors{
		CVSS:             cvssForSeverity(severity),
		EPSS:             epss,
		KEV:              kev,
		Exposure:         evidenceString(raw, "exposure"),
		AssetCriticality: evidenceString(raw, "asset_criticality"),
		ExploitVerified:  exploitVerified,
		Verdict:          string(verdict.Verdict),
		IntelStale:       p.c.d.Intel != nil && p.c.d.Intel.Stale(),
		IntelMirror:      intelVersion(p.c.d.Intel),
	})
	p.counts.track(verdict.Verdict, severity, scored.Score)

	// --- FindingReport (doc 04 §4.3).
	fr := p.buildReport(raw, verdict, severity, scored, evidenceRefs, fingerprint, entry)

	// --- Publish: detect.findings (canonical full stream).
	if _, err := p.c.d.Findings.PublishFinding(ctx, fr, p.t.Assignment.GetMissionId(), p.t.Assignment.GetTraceContext()); err != nil {
		log.Error("detect.findings publish failed", "err", err)
		return
	}
	// --- D11 alert mapping (Ruling C8).
	alertBus := AlertPublisher(p.c.d.Bus)
	if p.c.d.AlertBus != nil {
		alertBus = p.c.d.AlertBus
	}
	if _, err := p.c.d.Alerts.PublishAlert(ctx, alertBus, fr, p.tokenJTI); err != nil {
		log.Error("detect.alert mapping/publish failed (findings stream unaffected)", "err", err)
	}
	// --- System of record (09 Ingest API; fallback table at MVP).
	if p.c.d.Sink != nil {
		if err := p.c.d.Sink.StoreFinding(ctx, fr, p.scopeToken); err != nil {
			log.Error("finding sink store failed (findings stream already published)", "err", err)
		}
	}
}

// buildReport assembles the proto FindingReport (doc 04 §4.3).
func (p *pipeline) buildReport(raw scanner.RawResult, verdict *ave.Result, severity string,
	scored risk.Score, evidenceRefs []string, fingerprint string, entry *normalize.Entry) *detectv1.FindingReport {
	now := p.c.now()
	factors, _ := structpb.NewStruct(scored.Factors)
	vulnID := raw.CVE
	if vulnID == "" {
		vulnID = raw.CheckID
	}
	fr := &detectv1.FindingReport{
		FindingId:   entry.FindingID,
		Fingerprint: fingerprint,
		MissionId:   p.t.Assignment.GetMissionId(),
		TaskId:      p.t.Assignment.GetTaskId(),
		RoeId:       p.roeID,
		Target:      raw.MatchedAt,
		AssetRef:    "asset:host:" + hostOf(raw.Target),
		Vulnerability: &detectv1.Vulnerability{
			Id:         vulnID,
			Source:     raw.Adapter,
			TemplateId: raw.CheckID,
			Title:      raw.Title,
			Cwe:        raw.CWE,
			References: raw.References,
		},
		Severity: severityProto(severity),
		Validation: &detectv1.Validation{
			Verdict:          verdictProto(verdict.Verdict),
			Method:           verdict.Method,
			EvidenceRefs:     evidenceRefs,
			ValidatedAt:      timestamppb.New(now),
			ValidatorVersion: validatorVersion(verdict),
			Confidence:       verdict.Confidence,
		},
		Risk: &detectv1.RiskScore{
			Score:         uint32(scored.Score),
			Tier:          scored.Tier,
			ScorerVersion: risk.Version,
			Factors:       factors,
		},
		Status:      statusProto(verdict.Verdict),
		FirstSeen:   timestamppb.New(now),
		LastSeen:    timestamppb.New(now),
		Occurrences: entry.Occurrences,
	}
	if raw.MatchedAt == "" {
		fr.Target = raw.Target
	}
	return fr
}

// storeEvidence uploads the validation transcript + raw scanner record to
// the task's artifact prefix (doc 04 §3.1 D9; content-hashed, redacted).
// Returns the artifact refs (empty when the evidence store is unavailable).
func (p *pipeline) storeEvidence(ctx context.Context, raw scanner.RawResult, verdict *ave.Result, evsBundle []byte, fingerprint string) []string {
	st := p.c.d.Evidence
	if st == nil {
		return nil
	}
	up := p.t.Assignment.GetArtifactUpload()
	if up.GetBucket() == "" {
		return nil
	}
	fnd := ids.UUIDv5(fingerprint)[:8]
	prefix := up.GetPrefix() + fnd + "/"
	var refs []string

	if verdict.Transcript != nil {
		data, err := json.MarshalIndent(verdict.Transcript, "", "  ")
		if err == nil {
			if ref, _, uerr := st.Upload(ctx, up.GetBucket(), prefix, "transcript.json", data); uerr != nil {
				p.c.d.Log.Error("evidence transcript upload failed", "err", uerr)
			} else {
				refs = append(refs, ref)
				p.emit.AddArtifactRef(ref)
			}
		}
	}
	if len(raw.Raw) > 0 {
		if ref, _, uerr := st.Upload(ctx, up.GetBucket(), prefix, "scanner-raw.out", raw.Raw); uerr != nil {
			p.c.d.Log.Error("evidence raw upload failed", "err", uerr)
		} else {
			refs = append(refs, ref)
			p.emit.AddArtifactRef(ref)
		}
	}
	if len(evsBundle) > 0 {
		if ref, _, uerr := st.Upload(ctx, up.GetBucket(), prefix, "evs-bundle.json", evsBundle); uerr != nil {
			p.c.d.Log.Error("evidence evs bundle upload failed", "err", uerr)
		} else {
			refs = append(refs, ref)
			p.emit.AddArtifactRef(ref)
		}
	}
	return refs
}

// summary renders the doc 04 §4.4 TaskResult summary rollup.
func (p *pipeline) summary() map[string]any {
	return map[string]any{
		"candidates":        p.counts.candidates,
		"confirmed":         p.counts.confirmed,
		"not_reproducible":  p.counts.notReproducible,
		"inconclusive":      p.counts.inconclusive,
		"not_validatable":   p.counts.notValidatable,
		"suppressed_fp":     p.counts.suppressedFP,
		"severity_max":      p.counts.severityMax,
		"score_max":         p.counts.scoreMax,
		"evidence_failures": p.counts.evidenceFailures,
	}
}
