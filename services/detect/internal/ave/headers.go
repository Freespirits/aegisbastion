package ave

import (
	"context"
	"net/url"
	"strings"
)

// HeadersValidator implements doc 04 §6 "Security header/config": re-fetch
// and re-parse; confirm the absence/misconfig REPRODUCIBLY (weakest class —
// informational severity cap is applied by the coordinator per doc 04 §6).
type HeadersValidator struct{}

// Name implements Validator.
func (HeadersValidator) Name() string { return "ave.headers" }

// Classes implements Validator.
func (HeadersValidator) Classes() []string { return []string{"security_header"} }

// requiredHeaders are the baseline security headers whose absence the
// validator confirms reproducibly.
var requiredHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
}

// Validate implements Validator.
func (HeadersValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.headers", Transcript: tr}

	target := baseTarget(cand)
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		u, err = url.Parse("https://" + target)
		if err != nil {
			res.Verdict = VerdictInconclusive
			res.Detail = "target not parseable: " + target
			return res, nil
		}
	}

	// Re-fetch twice: the absence must reproduce (doc 04 §6 "confirm
	// absence/misconfig reproducibly").
	missing1, err1 := missingSecurityHeaders(ctx, tools, tr, u.String(), "refetch_1")
	missing2, err2 := missingSecurityHeaders(ctx, tools, tr, u.String(), "refetch_2")
	if err1 != nil || err2 != nil {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "re-fetch failed"
		return res, nil
	}
	if len(missing1) == 0 {
		res.Verdict = VerdictNotReproducible
		res.Confidence = 0.9
		res.Detail = "all baseline security headers present on re-fetch"
		return res, nil
	}
	// Reproducibility: the same missing set twice.
	if !sameStringSet(missing1, missing2) {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.4
		res.Detail = "missing-header set diverged between re-fetches"
		return res, nil
	}
	res.Verdict = VerdictConfirmed
	res.Confidence = 0.9
	res.Detail = "missing security headers reproduced twice: " + strings.Join(missing1, ", ")
	return res, nil
}

// missingSecurityHeaders fetches url once and lists absent baseline headers.
func missingSecurityHeaders(ctx context.Context, tools *Tools, tr *Transcript, url, label string) ([]string, error) {
	resp, _, err := doExchange(ctx, tools, tr, label, "GET", url, "", nil)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, h := range requiredHeaders {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	return missing, nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}
