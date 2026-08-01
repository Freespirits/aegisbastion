package ave

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
)

// XSSValidator implements doc 04 §6 "Reflected XSS": inject a unique random
// token with a context-varying payload; CONFIRMED only when the token
// reflects in an EXECUTABLE context (script body, event handler, unquoted
// attribute, or unescaped HTML markup) — plain escaped text reflections are
// NOT_REPRODUCIBLE. Non-destructive (GETs only).
type XSSValidator struct{}

// Name implements Validator.
func (XSSValidator) Name() string { return "ave.xss" }

// Classes implements Validator.
func (XSSValidator) Classes() []string { return []string{"reflected_xss"} }

// injectParams are the parameter names probed, in order, when the scanner
// evidence does not name one.
var injectParams = []string{"q", "search", "query", "s", "name", "id", "input", "term"}

// Validate implements Validator.
func (XSSValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.xss", Transcript: tr}

	canary := "s48x" + randHex(8)
	tr.Canary = canary

	target := baseTarget(cand)
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		u, err = url.Parse("https://" + target)
		if err != nil {
			res.Verdict = VerdictInconclusive
			res.Detail = "target not parseable: " + target
			res.Confidence = 0.2
			return res, nil
		}
	}

	param := evidenceString(cand.Evidence, "param", "parameter")
	params := []string{}
	if param != "" {
		params = append(params, param)
	}
	// If the matched URL already carries a query, probe its first key first.
	if param == "" && u.RawQuery != "" {
		for k := range u.Query() {
			params = append(params, k)
			break
		}
	}
	for _, p := range injectParams {
		if p != param && !contains(params, p) {
			params = append(params, p)
		}
	}

	// Context-varying payloads (doc 04 §6): markup-breaking, attribute-breaking,
	// and script-context forms — all carry the unique canary.
	payloads := []struct {
		label   string
		payload string
	}{
		{"markup", `"><` + canary + `>`},
		{"attr", `" onfocus="` + canary + `" autofocus="`},
		{"script", `</script><script>` + canary + `</script>`},
	}

	probed := 0
	for _, p := range params {
		if probed >= 4 {
			break
		}
		for _, pl := range payloads {
			if probed >= 4 {
				break
			}
			probed++
			q := u.Query()
			q.Set(p, pl.payload)
			probe := *u
			probe.RawQuery = q.Encode()
			_, body, err := doExchange(ctx, tools, tr, "inject_"+pl.label+"_"+p, "GET", probe.String(), "", nil)
			if err != nil {
				continue
			}
			text := string(body)
			if !strings.Contains(text, canary) {
				// Token not reflected at all for this payload.
				continue
			}
			// The canary reflected — classify the context. Escaped forms
			// (&quot;, &lt;) mean the reflection is inert.
			escaped := strings.Contains(text, `&lt;`) && strings.Contains(text, strings.ReplaceAll(pl.payload, "<", "&lt;"))
			rawMarkup := strings.Contains(text, `"><`+canary+`>`)
			rawHandler := strings.Contains(text, `" onfocus="`+canary+`"`)
			rawScript := strings.Contains(text, `</script><script>`+canary+`</script>`)
			switch {
			case rawMarkup || rawHandler || rawScript:
				res.Verdict = VerdictConfirmed
				res.Confidence = 0.95
				res.Detail = "canary reflected in executable context (" + pl.label + ") via parameter " + p
				return res, nil
			case escaped:
				tr.Notes = append(tr.Notes, "canary reflected but HTML-escaped for "+pl.label+" on "+p)
			default:
				// Reflected but context unclear (e.g. inside JSON) — ambiguous.
				tr.Notes = append(tr.Notes, "canary reflected in ambiguous context for "+pl.label+" on "+p)
			}
		}
	}

	// Distinguish NOT_REPRODUCIBLE (target answered, nothing reflected) from
	// INCONCLUSIVE (nothing probed successfully).
	if len(tr.Exchanges) == 0 {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "target unreachable for XSS probes"
		return res, nil
	}
	for _, note := range tr.Notes {
		if strings.Contains(note, "ambiguous") {
			res.Verdict = VerdictInconclusive
			res.Confidence = 0.4
			res.Detail = "canary reflected only in ambiguous (non-executable) contexts"
			return res, nil
		}
	}
	res.Verdict = VerdictNotReproducible
	res.Confidence = 0.9
	res.Detail = "canary never reflected in an executable context"
	return res, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
