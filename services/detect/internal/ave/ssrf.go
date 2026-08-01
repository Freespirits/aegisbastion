package ave

import (
	"context"
	"net/url"
	"time"
)

// SSRFValidator implements doc 04 §6 "SSRF / blind XXE / blind RCE": a unique
// OOB canary URL is injected into URL-accepting parameters; the verdict rests
// solely on an observed callback bound to the canary token at the
// platform-owned OOB collector (D7). No OOB service → NOT_VALIDATABLE
// (doc 04 §12 "OOB service down").
type SSRFValidator struct {
	// WaitWindow is how long to poll for the callback after injection.
	WaitWindow time.Duration
	// PollInterval paces the interaction lookup.
	PollInterval time.Duration
}

// Name implements Validator.
func (SSRFValidator) Name() string { return "ave.ssrf" }

// Classes implements Validator.
func (SSRFValidator) Classes() []string { return []string{"ssrf", "blind_xxe", "blind_rce"} }

// ssrfParams are the URL-accepting parameter names probed when the scanner
// evidence does not name one.
var ssrfParams = []string{"url", "uri", "link", "src", "href", "callback", "webhook", "feed", "image", "target", "fetch"}

// Validate implements Validator.
func (v SSRFValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.ssrf", Transcript: tr}

	if tools == nil || tools.OOB == nil {
		res.Verdict = VerdictNotValidatable
		res.Confidence = 0.3
		res.Detail = "OOB service unavailable — blind validation impossible (doc 04 §12)"
		tr.Notes = append(tr.Notes, "no OOB client wired")
		return res, nil
	}

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

	token, canaryURL, err := tools.OOB.NewCanary(ctx, "ssrf:"+cand.CheckID+":"+cand.MatchedAt)
	if err != nil {
		res.Verdict = VerdictNotValidatable
		res.Confidence = 0.3
		res.Detail = "canary mint failed: " + err.Error()
		return res, nil
	}
	tr.Canary = token

	param := evidenceString(cand.Evidence, "param", "parameter")
	params := []string{}
	if param != "" {
		params = append(params, param)
	}
	if param == "" && u.RawQuery != "" {
		for k := range u.Query() {
			params = append(params, k)
			break
		}
	}
	for _, p := range ssrfParams {
		if !contains(params, p) {
			params = append(params, p)
		}
	}

	injected := false
	for i, p := range params {
		if i >= 4 {
			break
		}
		q := u.Query()
		q.Set(p, canaryURL)
		probe := *u
		probe.RawQuery = q.Encode()
		if _, _, err := doExchange(ctx, tools, tr, "inject_"+p, "GET", probe.String(), "", nil); err == nil {
			injected = true
		}
	}
	if !injected {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "no injection probe reached the target"
		return res, nil
	}

	// Poll the OOB collector for a callback bound to THIS canary token.
	window := v.WaitWindow
	if window <= 0 {
		window = 10 * time.Second
	}
	poll := v.PollInterval
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(window)
	for {
		its, err := tools.OOB.Interactions(ctx, token)
		if err == nil && len(its) > 0 {
			res.Verdict = VerdictConfirmed
			res.Confidence = 0.97
			res.Detail = "OOB callback observed for canary token (" + its[0].Method + " from " + its[0].Remote + ")"
			tr.Notes = append(tr.Notes, "callback at "+its[0].At.Format(time.RFC3339)+" via "+its[0].Path)
			return res, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			res.Verdict = VerdictInconclusive
			res.Confidence = 0.2
			res.Detail = "validation cancelled while awaiting callback"
			return res, nil
		case <-time.After(poll):
		}
	}

	res.Verdict = VerdictNotReproducible
	res.Confidence = 0.8
	res.Detail = "no OOB callback observed within the wait window"
	return res, nil
}
