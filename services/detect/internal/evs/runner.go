package evs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// RunRequest is one sandbox verification (doc 04 §7.1): one curated pack
// against one target, ephemeral, egress-locked through ProxyURL.
type RunRequest struct {
	JobID     string  `json:"job_id"`
	Pack      *Pack   `json:"pack"`
	Env       EnvSpec `json:"env"`
	TimeoutMS int     `json:"timeout_ms"`
}

// EnvSpec is the serializable program environment handed to the sandbox.
type EnvSpec struct {
	Target      string         `json:"target"`
	MatchedAt   string         `json:"matched_at,omitempty"`
	CanaryURL   string         `json:"canary_url,omitempty"`
	CanaryToken string         `json:"canary_token,omitempty"`
	EchoToken   string         `json:"echo_token,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	// ProxyURL is the scope-enforcing egress proxy (doc 04 §10.2) — the only
	// network path the program gets.
	ProxyURL string `json:"proxy_url"`
	// OOBBaseURL is the OOB lookup API for blind proofs.
	OOBBaseURL string `json:"oob_base_url,omitempty"`
}

// RunResult is what a runner reports back.
type RunResult struct {
	Outcome *Outcome `json:"outcome"`
	Error   string   `json:"error,omitempty"`
	Runner  string   `json:"runner"`
}

// Runner executes one verification in isolation (doc 04 §7.1: one ephemeral
// sandbox per verification; gVisor at MVP where available, else the
// process-isolated local runner). The sandbox entrypoint (`evs-run` in the
// detect binary) reconstructs the program environment from EnvSpec: the
// proxy-forced HTTP client and the OOB lookup API over OOBBaseURL.
type Runner interface {
	// Kind is the runner id ("local" | "gvisor").
	Kind() string
	// Run executes the request and returns the verifier outcome. It must
	// honor ctx cancellation (kill → teardown immediately, partial evidence
	// preserved in Outcome when available).
	Run(ctx context.Context, req RunRequest) (*RunResult, error)
}

// ---------------------------------------------------------------------------
// Local runner — process isolation (doc 04 §7.1 fallback; gVisor where
// available). The verifier program runs in a CHILD PROCESS (the detect
// binary re-invoked as `evs-run`) with a scrubbed environment: no database
// DSN, no object-storage credentials, no bus identity — only the request on
// stdin and the proxy as its network path.
// ---------------------------------------------------------------------------

// LocalRunner re-invokes the current executable as a sandboxed child.
type LocalRunner struct {
	// Bin overrides the executable (tests; default os.Executable()).
	Bin string
	// Args overrides the child arguments (tests run the test binary's helper;
	// default ["evs-run"]).
	Args []string
	// ExtraEnv is appended to the scrubbed child environment (tests).
	ExtraEnv []string
	log      *slog.Logger
}

// NewLocalRunner builds the process-isolated local runner.
func NewLocalRunner(log *slog.Logger) *LocalRunner {
	if log == nil {
		log = slog.Default()
	}
	return &LocalRunner{log: log}
}

// Kind implements Runner.
func (r *LocalRunner) Kind() string { return "local" }

// Run implements Runner.
func (r *LocalRunner) Run(ctx context.Context, req RunRequest) (*RunResult, error) {
	bin := r.Bin
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("evs: locate executable: %w", err)
		}
		bin = exe
	}
	if req.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	args := r.Args
	if len(args) == 0 {
		args = []string{"evs-run"}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(payload)
	// Scrubbed environment: the child inherits NOTHING but its sandbox marker
	// and a minimal PATH (doc 04 §7.1 isolation: no persistence, no creds).
	cmd.Env = append([]string{"S48_EVS_CHILD=1", "PATH=" + os.Getenv("PATH")}, r.ExtraEnv...)
	setSandboxProcAttrs(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	res := &RunResult{Runner: r.Kind()}
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), res); err != nil {
			return nil, fmt.Errorf("evs: child result undecodable: %w (stderr: %s)", err, truncateStr(stderr.String(), 512))
		}
		res.Runner = r.Kind() // the child cannot know which runner spawned it
	}
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return res, ctx.Err()
		}
		if res.Error != "" {
			return res, errors.New(res.Error)
		}
		return res, fmt.Errorf("evs: child exited: %w (stderr: %s)", runErr, truncateStr(stderr.String(), 512))
	}
	if res.Outcome == nil && res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// gVisor runner (doc 04 §9: runsc on Docker at MVP → Firecracker later).
// The same `evs-run` entrypoint runs inside a one-shot runsc container with
// dropped caps, read-only rootfs, and resource caps (1 vCPU / 512 MiB,
// doc 04 §7.1). Egress is still only possible through the proxy URL inside
// the request.
// ---------------------------------------------------------------------------

// GVisorRunner executes verifications in one-shot gVisor containers.
type GVisorRunner struct {
	// Image is the detect image carrying the evs-run entrypoint
	// (DETECT_EVS_IMAGE in compose).
	Image string
	// DockerBin overrides the docker CLI path (tests).
	DockerBin string
	log       *slog.Logger
}

// NewGVisorRunner builds the runner for image.
func NewGVisorRunner(image, dockerBin string, log *slog.Logger) *GVisorRunner {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if log == nil {
		log = slog.Default()
	}
	return &GVisorRunner{Image: image, DockerBin: dockerBin, log: log}
}

// Kind implements Runner.
func (r *GVisorRunner) Kind() string { return "gvisor" }

// Available reports whether a runsc-capable docker is present.
func (r *GVisorRunner) Available(ctx context.Context) bool {
	if r.Image == "" {
		return false
	}
	if _, err := exec.LookPath(r.DockerBin); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.DockerBin, "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return false
	}
	return bytes.Contains(out, []byte("runsc"))
}

// Run implements Runner.
func (r *GVisorRunner) Run(ctx context.Context, req RunRequest) (*RunResult, error) {
	if req.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	args := []string{
		"run", "--rm", "-i",
		"--runtime=runsc",
		"--network=host", // egress still forced through the request's proxy URL
		"--cap-drop=ALL",
		"--read-only",
		"--memory=512m", "--cpus=1", "--pids-limit=128",
		r.Image, "evs-run",
	}
	cmd := exec.CommandContext(ctx, r.DockerBin, args...)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	res := &RunResult{Runner: r.Kind()}
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), res); err != nil {
			return nil, fmt.Errorf("evs: gvisor result undecodable: %w (stderr: %s)", err, truncateStr(stderr.String(), 512))
		}
		res.Runner = r.Kind()
	}
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return res, ctx.Err()
		}
		return res, fmt.Errorf("evs: gvisor run: %w (stderr: %s)", runErr, truncateStr(stderr.String(), 512))
	}
	if res.Outcome == nil && res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// SelectRunner picks the sandbox runner per config (doc 04 §9/§13): gVisor
// when available ("auto"), else the process-isolated local runner. An
// explicit "gvisor" request with no runsc available FAILS CLOSED (no
// sandbox, no EVS verdicts — never silently downgrade isolation).
func SelectRunner(ctx context.Context, kind, image, dockerBin string, log *slog.Logger) (Runner, error) {
	if log == nil {
		log = slog.Default()
	}
	switch kind {
	case "local":
		return NewLocalRunner(log), nil
	case "gvisor":
		g := NewGVisorRunner(image, dockerBin, log)
		if !g.Available(ctx) {
			return nil, fmt.Errorf("evs: gVisor runner requested but runsc/image unavailable (fail-closed)")
		}
		return g, nil
	default: // auto
		g := NewGVisorRunner(image, dockerBin, log)
		if g.Available(ctx) {
			log.Info("evs: gVisor runtime detected — sandboxing with runsc")
			return g, nil
		}
		log.Info("evs: gVisor unavailable — using process-isolated local runner")
		return NewLocalRunner(log), nil
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
