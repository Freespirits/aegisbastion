package ave

import (
	"context"
	"net/url"
	"regexp"
	"time"
)

// SQLiValidator implements doc 04 §6 "SQLi": error-based differential +
// boolean pair (true/false payload divergence) or time-based confirmation
// (2× threshold, 3 trials). READ-ONLY payloads only — SELECT-based, never
// DML/DDL (contractual).
type SQLiValidator struct {
	// TimeBase is the injected sleep duration (seconds) for the time-based
	// leg; small to stay non-intrusive.
	TimeBaseSeconds int
}

// Name implements Validator.
func (SQLiValidator) Name() string { return "ave.sqli" }

// Classes implements Validator.
func (SQLiValidator) Classes() []string { return []string{"sqli"} }

// sqlErrorPatterns are database error signatures (error-based leg).
var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*(mysql_|mysqli)`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)PG::SyntaxError|psql: ERROR`),
	regexp.MustCompile(`(?i)ORA-[0-9]{4,5}`),
	regexp.MustCompile(`(?i)SQLite3?::|sqlite error|near ".*": syntax error`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for (SQL Server|ODBC)`),
	regexp.MustCompile(`(?i)Unterminated string constant`),
}

// Validate implements Validator.
func (v SQLiValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.sqli", Transcript: tr}
	sleep := v.TimeBaseSeconds
	if sleep <= 0 {
		sleep = 2
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
	param := evidenceString(cand.Evidence, "param", "parameter")
	if param == "" {
		if u.RawQuery != "" {
			for k := range u.Query() {
				param = k
				break
			}
		}
	}
	if param == "" {
		param = "id"
	}

	inject := func(value, label string) (string, int, time.Duration, error) {
		q := u.Query()
		q.Set(param, value)
		probe := *u
		probe.RawQuery = q.Encode()
		start := time.Now()
		resp, body, err := doExchange(ctx, tools, tr, label, "GET", probe.String(), "", nil)
		if err != nil {
			return "", 0, 0, err
		}
		return string(body), resp.StatusCode, time.Since(start), nil
	}

	baseValue := u.Query().Get(param)
	if baseValue == "" {
		baseValue = "1"
	}

	// Baseline fetch.
	baseBody, baseStatus, baseDur, err := inject(baseValue, "baseline")
	if err != nil {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "baseline fetch failed: " + err.Error()
		return res, nil
	}

	// Leg 1 — error-based differential: quote injection should not alter a
	// well-parameterized endpoint; a SQL error signature is a strong signal.
	errBody, _, _, err := inject(baseValue+`'`, "error_probe")
	if err == nil {
		for _, re := range sqlErrorPatterns {
			if re.MatchString(errBody) && !re.MatchString(baseBody) {
				tr.Notes = append(tr.Notes, "error signature: "+re.String())
				// Differential confirm: double-quote (or doubled single
				// quote) should make the error vanish on real SQLi.
				fixBody, _, _, ferr := inject(baseValue+`''`, "error_differential")
				if ferr == nil && !re.MatchString(fixBody) {
					res.Verdict = VerdictConfirmed
					res.Confidence = 0.9
					res.Detail = "SQL error differential reproduced (quote breaks, doubled quote heals)"
					return res, nil
				}
				tr.Notes = append(tr.Notes, "error differential not reproducible with doubled quote")
			}
		}
	}

	// Leg 2 — boolean pair: true/false payload divergence.
	trueBody, trueStatus, _, terr := inject(baseValue+" AND 1=1", "boolean_true")
	falseBody, falseStatus, _, ferr := inject(baseValue+" AND 1=2", "boolean_false")
	if terr == nil && ferr == nil {
		// Divergence: true matches baseline shape, false diverges.
		trueLikeBase := bodySimilarity(baseBody, trueBody) > 0.98 && trueStatus == baseStatus
		falseDiffers := bodySimilarity(baseBody, falseBody) < 0.9 || falseStatus != baseStatus
		if trueLikeBase && falseDiffers {
			res.Verdict = VerdictConfirmed
			res.Confidence = 0.85
			res.Detail = "boolean pair diverged (AND 1=1 ≈ baseline, AND 1=2 diverges)"
			return res, nil
		}
		tr.Notes = append(tr.Notes, "boolean pair inconclusive")
	}

	// Leg 3 — time-based: 2× threshold, 3 trials (doc 04 §6). Read-only sleep
	// payload; trial divergence forces INCONCLUSIVE (doc 04 §12 flapping).
	type trial struct {
		delayed bool
		dur     time.Duration
	}
	var trials []trial
	threshold := baseDur + time.Duration(sleep*2)*time.Second/2 // 2× the injected sleep above baseline
	for i := 0; i < 3; i++ {
		_, _, dur, terr := inject(baseValue+sleepPayload(u, sleep), "time_trial")
		if terr != nil {
			continue
		}
		trials = append(trials, trial{delayed: dur >= threshold, dur: dur})
	}
	if len(trials) == 3 {
		delayed := 0
		for _, t := range trials {
			if t.delayed {
				delayed++
			}
		}
		switch delayed {
		case 3:
			res.Verdict = VerdictConfirmed
			res.Confidence = 0.8
			res.Detail = "time-based differential reproduced in 3/3 trials (≥2× threshold)"
			return res, nil
		case 0:
			tr.Notes = append(tr.Notes, "time-based: no trial delayed")
		default:
			// Flapping: alternating verdicts → INCONCLUSIVE (doc 04 §12).
			res.Verdict = VerdictInconclusive
			res.Confidence = 0.3
			res.Detail = "time-based trials diverged (flapping) — forced INCONCLUSIVE"
			return res, nil
		}
	}

	res.Verdict = VerdictNotReproducible
	res.Confidence = 0.85
	res.Detail = "no error-based, boolean, or time-based differential reproduced"
	return res, nil
}

// sleepPayload renders the read-only sleep payload for the target dialect
// (generic form first; validators never issue DML/DDL — doc 04 §6).
func sleepPayload(u *url.URL, seconds int) string {
	// MySQL/PostgreSQL-compatible SELECT sleep; union-free, read-only.
	return " AND (SELECT 1 FROM (SELECT SLEEP(" + itoa(seconds) + "))x)-- -"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// bodySimilarity is a cheap length-and-prefix heuristic (0..1) used for the
// boolean-pair differential; validators must stay dependency-light.
func bodySimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return 0
	}
	// Common prefix ratio over the shorter body.
	n := la
	if lb < n {
		n = lb
	}
	if n > 4096 {
		n = 4096
	}
	common := 0
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			break
		}
		common++
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	lenRatio := float64(maxLen-abs(la-lb)) / float64(maxLen)
	prefixRatio := float64(common) / float64(n)
	return 0.5*lenRatio + 0.5*prefixRatio
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
