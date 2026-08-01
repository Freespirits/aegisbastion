package ave

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

// TraversalValidator implements doc 04 §6 "Path traversal / LFI": retrieve a
// BENIGN known-content file (web-root robots.txt via traversal, or
// /etc/hostname) and hash-compare. NEVER credential files, never data files —
// contractual canary-only proof (doc 04 §10.5).
type TraversalValidator struct{}

// Name implements Validator.
func (TraversalValidator) Name() string { return "ave.traversal" }

// Classes implements Validator.
func (TraversalValidator) Classes() []string { return []string{"path_traversal"} }

// benignTargets are the only retrievable files — benign known-content files
// exclusively. /etc/passwd and friends are NEVER requested (doc 04 §6).
var benignTargets = []struct {
	name    string
	payload string
	// match is a content signature proving the file was actually read.
	match *regexp.Regexp
}{
	{"robots_txt", "robots.txt", regexp.MustCompile(`(?im)^(user-agent|disallow|allow|sitemap)\s*:`)},
	{"etc_hostname", "../../../../../../../../etc/hostname", regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}\s*$`)},
}

// traversalParams are the file-path parameter names probed when evidence is
// silent.
var traversalParams = []string{"file", "path", "page", "template", "include", "doc", "name", "filename"}

// Validate implements Validator.
func (TraversalValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.traversal", Transcript: tr}

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

	// Reference fetch: the benign file through its NORMAL route. The
	// hash-compare below requires the traversal response to match this
	// reference (doc 04 §6 hash-compare) or carry the content signature.
	refHashes := map[string]string{}
	for _, bt := range benignTargets {
		ref := *u
		ref.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(bt.payload, "../"), "/")
		ref.RawQuery = ""
		if bt.name == "robots_txt" {
			ref.Path = "/robots.txt"
			_, body, err := doExchange(ctx, tools, tr, "reference_"+bt.name, "GET", ref.String(), "", nil)
			if err == nil {
				sum := sha256.Sum256(body)
				refHashes[bt.name] = hex.EncodeToString(sum[:])
			}
		}
	}

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
	for _, p := range traversalParams {
		if !contains(params, p) {
			params = append(params, p)
		}
	}

	probed := 0
	for _, p := range params {
		for _, bt := range benignTargets {
			if probed >= 6 {
				break
			}
			probed++
			q := u.Query()
			q.Set(p, bt.payload)
			probe := *u
			probe.RawQuery = q.Encode()
			_, body, err := doExchange(ctx, tools, tr, "traverse_"+p+"_"+bt.name, "GET", probe.String(), "", nil)
			if err != nil {
				continue
			}
			content := strings.TrimSpace(string(body))
			// Signal 1 — content signature (robots.txt directives / hostname
			// shape) in a response that should not contain them.
			sigHit := bt.match.MatchString(content) && !bt.match.MatchString(evidenceString(cand.Evidence, "response"))
			// Signal 2 — hash-compare with the reference fetch.
			hashHit := false
			if ref := refHashes[bt.name]; ref != "" {
				sum := sha256.Sum256(body)
				hashHit = hex.EncodeToString(sum[:]) == ref
			}
			if sigHit || hashHit {
				res.Verdict = VerdictConfirmed
				res.Confidence = 0.92
				how := "content signature"
				if hashHit {
					how = "hash-compare with reference fetch"
				}
				res.Detail = "benign file " + bt.name + " retrieved via parameter " + p + " (" + how + ")"
				return res, nil
			}
		}
	}

	if probed == 0 {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "no traversal probe reached the target"
		return res, nil
	}
	res.Verdict = VerdictNotReproducible
	res.Confidence = 0.85
	res.Detail = "no benign-file retrieval reproduced"
	return res, nil
}
