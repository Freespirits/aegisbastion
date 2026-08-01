package evs

import (
	"fmt"
)

// builtinPacksJSON holds the three curated, signed MVP PoC packs
// (doc 04 §13: one SSRF, one RCE-echo, one auth-bypass — proving the
// sandbox path; non_destructive class only). Signatures verify against the
// key from PackVerificationKey; a tampered pack never executes.
var builtinPacksJSON = []string{
	// ssrf-canary — blind proof via OOB callback bound to the planted canary.
	`{"id":"ssrf-canary","version":"1.0.0","safety":"non_destructive","target_classes":["ssrf","blind_xxe","blind_rce"],"requires_oob":true,"program":{"steps":[{"name":"trigger","http":{"method":"GET","url":"{{matched_at}}"}},{"name":"await_callback","oob":{"min_interactions":1,"timeout_ms":15000}}],"confirm":[{"var":"trigger.status","status_equals":200}]},"signature":"eLDEA5QHtHlDihjn53xUjQHrmU+jdUGb+Iu/+vE1fAvxkVyyUMhO9SRsEomygAPm5j0mZLtz/NeRs9mdLbXFDQ=="}`,
	// rce-echo — echo-token proof (canary planted by the verifier must come
	// back in command output; real data access is never the proof, §7.1).
	`{"id":"rce-echo","version":"1.0.0","safety":"non_destructive","target_classes":["rce","version_cve"],"requires_oob":false,"program":{"steps":[{"name":"probe","http":{"method":"POST","url":"{{matched_at}}","headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"cmd=echo+{{echo_token}}"}}],"confirm":[{"var":"probe.body","contains":"{{echo_token}}"}]},"signature":"wfN35TXw2FJdB1P86Q/FepHxQMw8v3S7bhYu0L9+lcNYdkuIXWp6vLiWIfhj6nUdurLdYAEzvtggI9X9wyWwAQ=="}`,
	// auth-bypass-default-creds — login with the scanner-reported default
	// pair, then IMMEDIATELY log out, zero further actions (doc 04 §6).
	`{"id":"auth-bypass-default-creds","version":"1.0.0","safety":"non_destructive","target_classes":["default_creds"],"requires_oob":false,"program":{"steps":[{"name":"login","http":{"method":"POST","url":"{{matched_at}}","headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"username={{evidence.username}}&password={{evidence.password}}"}},{"name":"logout","http":{"method":"POST","url":"{{evidence.logout_url}}"}}],"confirm":[{"var":"login.body","contains":"{{echo_token}}"}]},"signature":"6QKOOmcUDFolGNsW5xqmnPhCtsKOaiepfHLRT9QOJ694rEi3b02N+2bSSHrqlUVDc9CIx86zml1NNRji3V/QBg=="}`,
}

// BuiltinPacks loads and signature-verifies the curated MVP pack set against
// the configured (or dev) verification key. Any failure is fatal to the EVS
// path (fail-closed: unverifiable packs never run).
func BuiltinPacks(configuredKeyHex string) ([]*Pack, error) {
	pub, _, err := PackVerificationKey(configuredKeyHex)
	if err != nil {
		return nil, err
	}
	out := make([]*Pack, 0, len(builtinPacksJSON))
	for _, blob := range builtinPacksJSON {
		p, err := LoadPack([]byte(blob), pub)
		if err != nil {
			return nil, fmt.Errorf("evs: builtin pack: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}
