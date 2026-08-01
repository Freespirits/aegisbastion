package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/executor"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/jobs"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeDeadStore struct {
	mu   sync.Mutex
	rows []string
}

func (f *fakeDeadStore) InsertDeadJob(_ context.Context, _ []byte, errText string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, errText)
	return nil
}

func (f *fakeDeadStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

type fakeExecutor struct {
	calls int
	out   executor.Outcome
	err   error
}

func (f *fakeExecutor) ScanAsset(_ context.Context, _ executor.ScanRequest) (executor.Outcome, error) {
	f.calls++
	return f.out, f.err
}

type auditCapture struct {
	mu   sync.Mutex
	evts []*platformv1.AuditEvent
}

func (a *auditCapture) Emit(_ context.Context, evt *platformv1.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.evts = append(a.evts, evt)
	return nil
}

func (a *auditCapture) violations() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.evts {
		if e.GetType() == platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// token minting (mirrors sdks/go token tests)
// ---------------------------------------------------------------------------

type tokenEnv struct {
	priv ed25519.PrivateKey
	kid  string
	src  token.KeySource
}

func newTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "gk-test"
	src := token.KeySourceFunc(func(context.Context) ([]token.JWK, error) {
		return []token.JWK{{
			Kty: "OKP", Crv: "Ed25519", Kid: kid, Alg: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(pub),
		}}, nil
	})
	return &tokenEnv{priv: priv, kid: kid, src: src}
}

// scopeManifestBytes is the canonical scope document carried by the
// scope-bound watch token (Ruling A).
var scopeManifestBytes = []byte(`{"roe_id":"roe_1","roe_version":1,"scope":{"domains":["acme.com","*.acme.com"],"cidrs":[],"explicit_excludes":["status.acme.com"]}}`)

func scopeManifestSHA() string {
	sum := sha256.Sum256(scopeManifestBytes)
	return hex.EncodeToString(sum[:])
}

func (e *tokenEnv) mintWatchToken(t *testing.T, taskID string) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "gatekeeper.platform", "aud": "aegisbastion.modules",
		"jti": "tok_watch1", "sub": "agent_1", "task_id": taskID,
		"roe_id": "roe_1", "roe_version": 1, "risk_class": "R1",
		"capabilities": []string{"monitor.watch"},
		"targets": map[string]any{
			"hash_alg": "sha256", "manifest_uri": "blob://tokens/tok_watch1/scope.json",
			"manifest_sha256": scopeManifestSHA(),
		},
		"scope_bound": true,
		"rate_caps":   map[string]any{"max_rps": 10, "max_concurrent": 2},
		"iat":         now, "nbf": now, "exp": now + 900,
	}
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": e.kid})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(e.priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func manifestFetcher() manifest.Fetcher {
	return manifest.FetcherFunc(func(_ context.Context, uri string) ([]byte, error) {
		if uri != "blob://tokens/tok_watch1/scope.json" {
			return nil, fmt.Errorf("unknown manifest %s", uri)
		}
		return scopeManifestBytes, nil
	})
}

func jobFor(env *tokenEnv, t *testing.T, taskID, identifier string) *jobs.Job {
	return &jobs.Job{
		JobID: "job-1", AuthorizationToken: env.mintWatchToken(t, taskID),
		TaskID: taskID, Capability: "monitor.watch",
		MissionID: "msn_1", ROEID: "roe_1", OrgID: "org_1",
		Identifier: identifier, ProbeTypes: []string{"dns"},
		ReportEvents: true,
	}
}

func newWorker(env *tokenEnv, dead *fakeDeadStore, exec ScanExecutor, aud audit.Emitter, rev *pep.RevocationCache) *Worker {
	return New(Config{
		AgentID:  "mon-w-test",
		Verifier: token.NewVerifier(token.NewKeyCache(env.src)),
		Fetcher:  manifestFetcher(), Revocations: rev,
		Emitter: aud, Executor: exec, Store: dead,
	}, nil)
}

// ---------------------------------------------------------------------------
// fail-closed gate proofs (doc 03 §9.2/§15.2)
// ---------------------------------------------------------------------------

func TestWorker_ForgedTokenDeadLettered(t *testing.T) {
	env := newTokenEnv(t)
	dead, exec, aud := &fakeDeadStore{}, &fakeExecutor{}, &auditCapture{}
	w := newWorker(env, dead, exec, aud, pep.NewRevocationCache())

	j := jobFor(env, t, "tsk_1", "api.acme.com")
	j.AuthorizationToken = j.AuthorizationToken[:len(j.AuthorizationToken)-4] + "AAAA" // corrupt signature
	if d := w.Handle(context.Background(), j, 1); d != jobs.Term {
		t.Fatalf("disposition = %v, want Term", d)
	}
	if exec.calls != 0 {
		t.Fatal("executor must never run on a forged token (zero target contact)")
	}
	if dead.count() != 1 {
		t.Fatalf("dead-letter rows = %d, want 1", dead.count())
	}
	if aud.violations() != 1 {
		t.Fatalf("SCOPE_VIOLATION audit records = %d, want 1", aud.violations())
	}
}

func TestWorker_TaskBindingMismatchDeadLettered(t *testing.T) {
	env := newTokenEnv(t)
	dead, exec, aud := &fakeDeadStore{}, &fakeExecutor{}, &auditCapture{}
	w := newWorker(env, dead, exec, aud, pep.NewRevocationCache())

	j := jobFor(env, t, "tsk_1", "api.acme.com")
	j.TaskID = "tsk_other" // token bound to tsk_1
	if d := w.Handle(context.Background(), j, 1); d != jobs.Term {
		t.Fatalf("disposition = %v, want Term", d)
	}
	if exec.calls != 0 || dead.count() != 1 || aud.violations() != 1 {
		t.Fatalf("calls=%d dead=%d violations=%d", exec.calls, dead.count(), aud.violations())
	}
}

func TestWorker_OutOfScopeTargetDeadLettered(t *testing.T) {
	env := newTokenEnv(t)
	dead, exec, aud := &fakeDeadStore{}, &fakeExecutor{}, &auditCapture{}
	w := newWorker(env, dead, exec, aud, pep.NewRevocationCache())

	for _, target := range []string{"evil.com", "status.acme.com"} {
		j := jobFor(env, t, "tsk_1", target)
		if d := w.Handle(context.Background(), j, 1); d != jobs.Term {
			t.Fatalf("%s: disposition = %v, want Term", target, d)
		}
	}
	if exec.calls != 0 {
		t.Fatal("out-of-scope target must never reach the executor")
	}
	if dead.count() != 2 {
		t.Fatalf("dead rows = %d, want 2 (out-of-scope + excluded)", dead.count())
	}
	if aud.violations() != 2 {
		t.Fatalf("violations = %d, want 2", aud.violations())
	}
}

func TestWorker_InScopeExecutes(t *testing.T) {
	env := newTokenEnv(t)
	dead := &fakeDeadStore{}
	exec := &fakeExecutor{out: executor.Outcome{ProbesRun: 1}}
	aud := &auditCapture{}
	w := newWorker(env, dead, exec, aud, pep.NewRevocationCache())

	j := jobFor(env, t, "tsk_1", "api.acme.com")
	if d := w.Handle(context.Background(), j, 1); d != jobs.Ack {
		t.Fatalf("disposition = %v, want Ack", d)
	}
	if exec.calls != 1 {
		t.Fatalf("executor calls = %d", exec.calls)
	}
	if dead.count() != 0 {
		t.Fatalf("dead rows = %d", dead.count())
	}
}

// TestWorker_RevocationHaltsBeforeContact is the doc 03 §15.2 gate proof at
// the worker leg: once the RoE is revoked, the PEP denies every probe —
// zero target contact — and the job is dead-lettered WITHOUT a violation
// record (revocation is not a violation; gatekeeper audited it).
func TestWorker_RevocationHaltsBeforeContact(t *testing.T) {
	env := newTokenEnv(t)
	dead, exec, aud := &fakeDeadStore{}, &fakeExecutor{}, &auditCapture{}
	rev := pep.NewRevocationCache()
	rev.Apply(&gatekeeperv1.Revocation{
		Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
		Key:   "roe_1", Reason: "test revocation",
	})
	w := newWorker(env, dead, exec, aud, rev)

	j := jobFor(env, t, "tsk_1", "api.acme.com")
	// The pre-check passes (scope contains the target), then the guard's
	// revocation check denies the probe itself.
	exec.out = executor.Outcome{Unauthorized: true, UnauthorizedErr: "pep: revoked: test"}
	if d := w.Handle(context.Background(), j, 1); d != jobs.Term {
		t.Fatalf("disposition = %v, want Term", d)
	}
	if dead.count() != 1 {
		t.Fatalf("dead rows = %d", dead.count())
	}
	if aud.violations() != 0 {
		t.Fatalf("revocation must not raise SCOPE_VIOLATION: %d", aud.violations())
	}
}

func TestWorker_PoisonJobRetriesThenDies(t *testing.T) {
	env := newTokenEnv(t)
	dead := &fakeDeadStore{}
	exec := &fakeExecutor{err: fmt.Errorf("postgres down")}
	aud := &auditCapture{}
	w := newWorker(env, dead, exec, aud, pep.NewRevocationCache())

	j := jobFor(env, t, "tsk_1", "api.acme.com")
	if d := w.Handle(context.Background(), j, 1); d != jobs.Nak {
		t.Fatalf("first failure: disposition = %v, want Nak", d)
	}
	if d := w.Handle(context.Background(), j, jobs.MaxDeliver); d != jobs.Term {
		t.Fatalf("final failure: disposition = %v, want Term", d)
	}
	if dead.count() != 1 {
		t.Fatalf("dead rows = %d", dead.count())
	}
}

var _ = audit.NopEmitter{}
