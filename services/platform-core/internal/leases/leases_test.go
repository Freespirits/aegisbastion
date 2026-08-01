package leases

import (
	"context"
	"testing"
	"time"
)

// Doc 01 §6.4: one intrusive task per target at a time, platform-wide.
func TestMemStoreMutualExclusion(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()

	ok, err := m.Acquire(ctx, "api.acme.com", "tsk_A", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first acquire must succeed: ok=%v err=%v", ok, err)
	}
	// Second owner on the SAME target is excluded.
	ok, err = m.Acquire(ctx, "api.acme.com", "tsk_B", time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if ok {
		t.Fatal("second acquire on held target must fail (mutual exclusion)")
	}
	// A DIFFERENT target is unaffected.
	ok, err = m.Acquire(ctx, "db.acme.com", "tsk_B", time.Minute)
	if err != nil || !ok {
		t.Fatal("different target must acquire cleanly")
	}
	// Same owner re-acquiring its own held lease is also excluded (KV Create
	// semantics — renewals go through Release first).
	ok, _ = m.Acquire(ctx, "api.acme.com", "tsk_A", time.Minute)
	if ok {
		t.Fatal("re-acquire of a held key must fail (KV Create)")
	}
}

func TestMemStoreReleaseOwnership(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	_, _ = m.Acquire(ctx, "api.acme.com", "tsk_A", time.Minute)

	// A non-owner must not be able to release (lease handover after TTL).
	if err := m.Release(ctx, "api.acme.com", "tsk_B"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if h, _ := m.Holder(ctx, "api.acme.com"); h != "tsk_A" {
		t.Fatalf("non-owner release must not drop the lease, holder=%q", h)
	}
	if err := m.Release(ctx, "api.acme.com", "tsk_A"); err != nil {
		t.Fatalf("owner release: %v", err)
	}
	if h, _ := m.Holder(ctx, "api.acme.com"); h != "" {
		t.Fatalf("lease must be free after owner release, holder=%q", h)
	}
	// Re-acquire after release works.
	ok, _ := m.Acquire(ctx, "api.acme.com", "tsk_C", time.Minute)
	if !ok {
		t.Fatal("re-acquire after release must succeed")
	}
}

func TestMemStoreTTLExpiry(t *testing.T) {
	m := NewMemStore()
	now := time.Now()
	m.now = func() time.Time { return now }
	ctx := context.Background()

	_, _ = m.Acquire(ctx, "api.acme.com", "tsk_A", 10*time.Second)
	// Agent crashed — lease TTL (task deadline) frees the target (doc 01 §13).
	now = now.Add(11 * time.Second)
	ok, err := m.Acquire(ctx, "api.acme.com", "tsk_B", time.Minute)
	if err != nil || !ok {
		t.Fatal("expired lease must free the target")
	}
}
