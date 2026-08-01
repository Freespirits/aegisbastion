package audit

import (
	"strings"
	"testing"
	"time"
)

// Hash-chain determinism (doc 01 §5.9): same event content → same hash;
// any content change → different hash. The chain link binds prev_hash.
func TestComputeHashDeterministic(t *testing.T) {
	ts := time.Date(2026, 7, 30, 7, 31, 5, 221000000, time.UTC)
	ev := &Event{
		EventID: "aud_1", Seq: 7, TS: ts, Type: AuthzDecision,
		Actor:   Actor{Kind: "service", ID: "orchestrator-1"},
		Subject: Subject{MissionID: "msn_1", TaskID: "tsk_1", RoeID: "roe_1"},
		Payload: map[string]any{"decision": "ALLOW", "decision_id": "dec_1"},
	}
	h1, err := computeHash(ev)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash must carry the sha256: prefix, got %q", h1)
	}
	h2, _ := computeHash(ev)
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}

	// prev_hash is part of the link.
	ev.PrevHash = "sha256:aa10"
	h3, _ := computeHash(ev)
	if h3 == h1 {
		t.Fatal("prev_hash must change the link hash")
	}

	// Payload tampering is evident.
	ev2 := *ev
	ev2.Payload = map[string]any{"decision": "DENY", "decision_id": "dec_1"}
	h4, _ := computeHash(&ev2)
	if h4 == h3 {
		t.Fatal("payload change must change the hash (tamper evidence)")
	}

	// The hash field itself is excluded from the hashed content.
	ev3 := *ev
	ev3.Hash = "sha256:garbage"
	h5, _ := computeHash(&ev3)
	if h5 != h3 {
		t.Fatal("hash field must be excluded from canonical content")
	}
}

// Map key order must not affect the canonical form (sorted keys).
func TestCanonicalKeyOrderIndependent(t *testing.T) {
	ts := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	a := &Event{EventID: "e", Seq: 1, TS: ts, Type: TaskDispatched,
		Actor:   Actor{Kind: "service", ID: "x"},
		Payload: map[string]any{"b": 1, "a": 2, "c": 3}}
	b := &Event{EventID: "e", Seq: 1, TS: ts, Type: TaskDispatched,
		Actor:   Actor{Kind: "service", ID: "x"},
		Payload: map[string]any{"c": 3, "b": 1, "a": 2}}
	ca, _ := canonicalJSON(a)
	cb, _ := canonicalJSON(b)
	if string(ca) != string(cb) {
		t.Fatalf("canonical form must be key-order independent:\n%s\n%s", ca, cb)
	}
}
