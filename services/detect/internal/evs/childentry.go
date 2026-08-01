package evs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/oob"
)

// ChildMain is the sandbox entrypoint (`detect evs-run`): it reads one
// RunRequest from stdin, reconstructs the program environment (proxy-forced
// HTTP client + OOB lookup API — nothing else), executes the pack program,
// and writes one RunResult to stdout. The process exits non-zero only on
// protocol errors; verification outcomes are reported in-band.
func ChildMain(ctx context.Context, stdin io.Reader, stdout io.Writer) int {
	var req RunRequest
	dec := json.NewDecoder(io.LimitReader(stdin, 8<<20))
	if err := dec.Decode(&req); err != nil {
		fmt.Fprintf(stdout, `{"error":"bad run request: %s"}`, err)
		return 2
	}
	if req.Pack == nil {
		fmt.Fprint(stdout, `{"error":"no pack in request"}`)
		return 2
	}
	env := &ProgramEnv{
		Target:      req.Env.Target,
		MatchedAt:   req.Env.MatchedAt,
		CanaryURL:   req.Env.CanaryURL,
		CanaryToken: req.Env.CanaryToken,
		EchoToken:   req.Env.EchoToken,
		Evidence:    req.Env.Evidence,
		HTTP:        HTTPClient(req.Env.ProxyURL, 60*1e9),
	}
	if req.Env.OOBBaseURL != "" {
		var oc ave.OOBClient = oob.NewHTTPClient(req.Env.OOBBaseURL, nil)
		env.OOB = oc
	}
	out, err := RunProgram(ctx, req.Pack.Program, env)
	res := RunResult{Outcome: out}
	if err != nil {
		res.Error = err.Error()
	}
	_ = json.NewEncoder(stdout).Encode(res)
	return 0
}
