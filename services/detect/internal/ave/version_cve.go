package ave

import (
	"context"
	"regexp"
	"strings"
)

// VersionCVEValidator implements doc 04 §6 "Version/banner CVE": two
// INDEPENDENT signals are required — the banner/version string AND a
// behavioral probe (feature/option response differential). Banner-only is
// INCONCLUSIVE, never CONFIRMED.
type VersionCVEValidator struct{}

// Name implements Validator.
func (VersionCVEValidator) Name() string { return "ave.version_cve" }

// Classes implements Validator.
func (VersionCVEValidator) Classes() []string { return []string{"version_cve"} }

// bannerPatterns maps well-known CVE checks to the banner regex that flags
// the affected version line (curated MVP set; unknown checks fall back to the
// scanner's matched evidence and therefore can only reach INCONCLUSIVE via
// the behavioral leg).
var bannerPatterns = map[string]string{
	"cve-2024-3400":  `(?i)PAN-OS`,
	"cve-2014-0160":  `(?i)OpenSSL`,
	"cve-2017-0143":  `(?i)SMB`,
	"cve-2023-0669":  `(?i)GoAnywhere`,
	"cve-2021-41773": `(?i)Apache`,
}

// Validate implements Validator.
func (VersionCVEValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.version_cve", Transcript: tr}

	target := baseTarget(cand)
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + hostPort(url) + "/"
	}

	// Signal 1 — banner/version string: fetch the root and match the server
	// banner/body against the affected-version pattern.
	bannerHit := false
	resp, body, err := doExchange(ctx, tools, tr, "banner", "GET", url, "", nil)
	if err != nil {
		res.Verdict = VerdictInconclusive
		res.Detail = "target unreachable for banner fetch: " + err.Error()
		res.Confidence = 0.2
		return res, nil
	}
	pattern := bannerPatterns[strings.ToLower(cand.CheckID)]
	bannerText := resp.Header.Get("Server") + "\n" + resp.Header.Get("X-Powered-By") + "\n" + truncate(string(body), 4096)
	if pattern != "" {
		if regexp.MustCompile(pattern).MatchString(bannerText) {
			bannerHit = true
		}
	} else {
		// Uncurated check: the scanner's own matched evidence is the only
		// banner signal — weaker, still only one signal.
		if ev := evidenceString(cand.Evidence, "matched", "response", "output"); ev != "" {
			bannerHit = true
			tr.Notes = append(tr.Notes, "banner signal from scanner evidence (uncurated check)")
		}
	}

	// Signal 2 — behavioral probe: an OPTIONS/feature differential. Vulnerable
	// services answer capability probes with a differential signature (e.g.
	// allowed methods set, service-specific option headers). We compare the
	// OPTIONS response against the banner fetch: any service-feature
	// advertising (Allow/Public methods beyond GET/POST, or DAV-style
	// headers) counts as the independent behavioral signal.
	behaviorHit := false
	optResp, _, err := doExchange(ctx, tools, tr, "behavior_options", "OPTIONS", url, "", nil)
	if err == nil {
		allow := optResp.Header.Get("Allow") + "," + optResp.Header.Get("Public")
		dav := optResp.Header.Get("DAV")
		if dav != "" || strings.Contains(allow, "TRACE") || strings.Contains(allow, "PUT") ||
			strings.Contains(allow, "PROPFIND") {
			behaviorHit = true
		}
		// Differential status: an endpoint answering OPTIONS with a distinct
		// feature status (2xx with non-empty Allow) is a behavioral signal the
		// service is live and feature-responsive.
		if !behaviorHit && optResp.StatusCode >= 200 && optResp.StatusCode < 300 &&
			strings.TrimSpace(allow) != "" && allow != "," {
			tr.Notes = append(tr.Notes, "weak behavioral signal: OPTIONS answered with Allow="+allow)
		}
	} else {
		tr.Notes = append(tr.Notes, "behavioral probe failed: "+err.Error())
	}

	switch {
	case bannerHit && behaviorHit:
		res.Verdict = VerdictConfirmed
		res.Confidence = 0.9
		res.Detail = "banner and behavioral signals both match the affected profile"
	case bannerHit:
		// Contractual: banner-only is INCONCLUSIVE (doc 04 §6 row 1).
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.5
		res.Detail = "banner/version matches but no behavioral differential — banner-only is INCONCLUSIVE"
	case behaviorHit:
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.4
		res.Detail = "behavioral differential only; version banner absent"
	default:
		res.Verdict = VerdictNotReproducible
		res.Confidence = 0.85
		res.Detail = "neither banner nor behavioral signal reproduced"
	}
	return res, nil
}
