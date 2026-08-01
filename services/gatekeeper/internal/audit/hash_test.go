package audit

import (
	"testing"
	"time"
)

func testEvent(seq uint64, prev, kind string) *Event {
	return &Event{
		EventID:    "evt_test",
		OrgID:      "org_test",
		Seq:        seq,
		PrevHash:   prev,
		Kind:       kind,
		Actor:      map[string]any{"kind": "service", "id": "svc-x"},
		Subject:    map[string]any{"task_id": "task_1"},
		Payload:    map[string]any{"decision": "allow"},
		OccurredAt: time.Date(2026, 7, 30, 7, 30, 0, 0, time.UTC),
		RecordedAt: time.Date(2026, 7, 30, 7, 30, 1, 0, time.UTC),
	}
}

func TestHashDeterministic(t *testing.T) {
	e := testEvent(1, "", KindAuthorizationDecision)
	h1, err := Hash(e)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(e)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}
	if len(h1) != 64 {
		t.Fatalf("hash must be 64 hex chars, got %d", len(h1))
	}
}

func TestHashTamperEvidence(t *testing.T) {
	e := testEvent(2, "aa", KindAuthorizationDecision)
	h1, _ := Hash(e)

	mutations := []func(*Event){
		func(e *Event) { e.Payload["decision"] = "deny" },
		func(e *Event) { e.Seq = 3 },
		func(e *Event) { e.PrevHash = "bb" },
		func(e *Event) { e.Actor["id"] = "svc-y" },
		func(e *Event) { e.RecordedAt = e.RecordedAt.Add(time.Second) },
	}
	for i, mutate := range mutations {
		m := testEvent(2, "aa", KindAuthorizationDecision)
		mutate(m)
		h2, err := Hash(m)
		if err != nil {
			t.Fatal(err)
		}
		if h2 == h1 {
			t.Errorf("mutation %d did not change the hash — chain is not tamper-evident", i)
		}
	}
}

// TestChainLinkage simulates a chain: each link's hash feeds the next
// prev_hash, and any break is detectable by recomputation (the same check
// VerifyRange performs over DB rows).
func TestChainLinkage(t *testing.T) {
	var prev string
	chain := make([]*Event, 5)
	for i := range chain {
		e := testEvent(uint64(i+1), prev, KindTokenMinted)
		h, err := Hash(e)
		if err != nil {
			t.Fatal(err)
		}
		e.EventHash = h
		chain[i] = e
		prev = h
	}
	// Verify linkage + recomputation.
	prev = ""
	for _, e := range chain {
		if e.PrevHash != prev {
			t.Fatalf("seq %d: prev_hash linkage broken", e.Seq)
		}
		want, _ := Hash(e)
		if want != e.EventHash {
			t.Fatalf("seq %d: hash mismatch", e.Seq)
		}
		prev = e.EventHash
	}
	// Tamper with link 3: links 3+ must all fail verification.
	chain[2].Payload["decision"] = "deny"
	prev = ""
	brokenFrom := -1
	for _, e := range chain {
		want, _ := Hash(e)
		if want != e.EventHash && brokenFrom == -1 {
			brokenFrom = int(e.Seq)
		}
		prev = e.EventHash
	}
	if brokenFrom != 3 {
		t.Fatalf("tampering must be detected at seq 3, got %d", brokenFrom)
	}
}
