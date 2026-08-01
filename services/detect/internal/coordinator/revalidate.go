package coordinator

import (
	"context"
	"fmt"

	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/evs"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// runRevalidate implements detect.revalidate (doc 04 §4.1/§7.3): re-verify
// specific existing findings (remediation verification / regression). The
// validator no longer reproducing drives remediation_claimed →
// verified_closed; still reproducing → reopened (regression signal,
// escalated with the original evidence plus new).
func (c *Coordinator) runRevalidate(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter, params *Params) error {
	store := c.d.Revalidate
	if store == nil {
		return fmt.Errorf("detect.revalidate requires the local fallback store at MVP (DETECT_FINDINGS_FALLBACK=true)")
	}

	proxy := evs.NewProxy(evs.NewAllowlist(appendTargets(t, c.d.OOBBaseURL)), c.d.Log)
	proxyURL, err := proxy.Start()
	if err != nil {
		return err
	}
	defer func() { _ = proxy.Close(ctx) }()

	tools := &ave.Tools{
		HTTP: scopedHTTPClient(proxyURL, evs.NewAllowlist(appendTargets(t, c.d.OOBBaseURL))),
		OOB:  c.d.OOB,
	}

	verifiedClosed, reopened, missing, invalid := 0, 0, 0, 0
	for _, fp := range params.FindingFingerprints {
		if err := ctx.Err(); err != nil {
			return err
		}
		target, err := store.FindingByFingerprint(ctx, c.d.TenantID, fp)
		if err != nil || target == nil {
			missing++
			c.d.Log.Warn("revalidate: fingerprint not found", "fingerprint", fp)
			continue
		}
		// Defense-in-depth: the stored target must still be in scope for the
		// revalidate task's token (fail-closed, doc 04 §10.1).
		if err := c.authorizeTarget(ctx, t, target.Target); err != nil {
			invalid++
			c.d.Log.Warn("revalidate: stored target out of scope — skipped", "fingerprint", fp)
			continue
		}
		res, err := c.d.AVE.Validate(ctx, ave.Candidate{
			Target: target.Target, MatchedAt: target.MatchedAt,
			CheckID: target.CheckID, VulnClass: target.VulnClass,
		}, tools)
		if err != nil {
			invalid++
			continue
		}
		switch res.Verdict {
		case ave.VerdictNotReproducible:
			// Validator no longer reproduces → remediation verified.
			if err := store.TransitionState(ctx, c.d.TenantID, target.FindingID, "verified_closed"); err != nil {
				return err
			}
			verifiedClosed++
		case ave.VerdictConfirmed:
			// Still reproduces → regression (or unaddressed): reopened.
			if err := store.TransitionState(ctx, c.d.TenantID, target.FindingID, "reopened"); err != nil {
				return err
			}
			reopened++
		default:
			invalid++ // ambiguous — state unchanged
		}
	}

	return emit.SetSummary(map[string]any{
		"fingerprints":    len(params.FindingFingerprints),
		"verified_closed": verifiedClosed,
		"reopened":        reopened,
		"not_found":       missing,
		"inconclusive":    invalid,
		"score_max":       0,
		"severity_max":    "",
	})
}

// runEnrich implements detect.enrich (doc 04 §4.1, R1): a light-touch
// service/version fingerprint refresh feeding scoring (banner + TLS). It
// publishes informational exposure findings (NOT_VALIDATABLE — enrichment
// records, not vulnerability claims) on detect.findings.
func (c *Coordinator) runEnrich(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter, params *Params) error {
	proxy := evs.NewProxy(evs.NewAllowlist(appendTargets(t, c.d.OOBBaseURL)), c.d.Log)
	proxyURL, err := proxy.Start()
	if err != nil {
		return err
	}
	defer func() { _ = proxy.Close(ctx) }()

	pipe := newPipeline(c, t, emit, params, proxyURL)
	probed := 0
	for _, target := range t.Assignment.GetTargets() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.authorizeTarget(ctx, t, target); err != nil {
			return err // fail-closed (defense-in-depth re-check)
		}
		raw := enrichProbe(ctx, pipe.tools, target, t.Assignment.GetTaskId())
		probed++
		pipe.process(ctx, raw)
		_ = emit.Progress(ctx, map[string]any{"targets_probed": probed, "targets_total": len(t.Assignment.GetTargets())})
	}
	summary := pipe.summary()
	summary["targets_probed"] = probed
	return emit.SetSummary(summary)
}

// enrichProbe runs the R1 fingerprint probes for one target (TLS profile
// when applicable; the security-header re-fetch doubles as the HTTP banner
// surface) and renders it as an informational candidate.
func enrichProbe(ctx context.Context, tools *ave.Tools, target, taskID string) (raw scanner.RawResult) {
	raw = scanner.RawResult{
		TaskID: taskID, Adapter: "custom", Target: target, MatchedAt: target,
		CheckID: "enrich.fingerprint", Title: "service fingerprint refresh",
		Severity: "informational", VulnClass: scanner.ClassExposure,
		Evidence: map[string]any{},
	}
	// TLS profile (independent re-handshake; non-destructive).
	if tlsProf, err := probeTLS(ctx, tools, target); err == nil && tlsProf != nil {
		raw.Evidence["tls_min_version"] = fmt.Sprintf("0x%04x", tlsProf.MinVersionOffered)
		raw.Evidence["tls_server_name"] = tlsProf.ServerName
		raw.Evidence["tls_cipher_count"] = len(tlsProf.CipherSuites)
	}
	// HTTP banner surface.
	if server, xpb := probeBanner(ctx, tools, target); server != "" {
		raw.Evidence["server_banner"] = server
		raw.Evidence["x_powered_by"] = xpb
	}
	return raw
}
