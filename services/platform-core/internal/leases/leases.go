// Package leases implements the per-target intrusive lease (doc 01 §6.4,
// Ruling C12): the platform-wide serializer for R2/R3 work. One intrusive
// task per target at a time — CAI's Detect scan and HexStrike's probe of the
// same host serialize automatically. Backed by the NATS KV bucket "leases"
// (created by deploy/jetstream-bootstrap); keys are
// target/{sha256(target)}, value TTL equals the task deadline.
package leases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Store is the lease interface (NATS KV in production; in-memory for tests).
type Store interface {
	// Acquire takes the lease for target owned by owner until ttl. Returns
	// false (no error) when another owner already holds it.
	Acquire(ctx context.Context, target, owner string, ttl time.Duration) (bool, error)
	// Release drops the lease only if still held by owner.
	Release(ctx context.Context, target, owner string) error
	// Holder returns the current owner ("" when free).
	Holder(ctx context.Context, target string) (string, error)
}

// Key derives the KV key for a target (doc 01 §6.4: leases/target/{sha256}).
func Key(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "target/" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// NATS KV implementation
// ---------------------------------------------------------------------------

// KVStore is the production lease store over NATS KV.
type KVStore struct {
	kv nats.KeyValue
}

// NewKVStore wraps a bucket handle.
func NewKVStore(kv nats.KeyValue) *KVStore { return &KVStore{kv: kv} }

// Acquire creates the key atomically; KV Create fails with ErrKeyExists when
// another owner holds the lease — that failure IS the mutual exclusion.
// Note: the bucket-level TTL (24 h safety net) bounds lease lifetime; the
// per-entry ttl is encoded in the value and honored by Reaper logic, while
// Release deletes eagerly on completion.
func (s *KVStore) Acquire(ctx context.Context, target, owner string, ttl time.Duration) (bool, error) {
	val := fmt.Sprintf("%s|%d", owner, time.Now().Add(ttl).Unix())
	_, err := s.kv.Create(Key(target), []byte(val))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, nats.ErrKeyExists) {
		return false, nil
	}
	return false, err
}

// Release deletes the key only when the value still names owner (never
// release someone else's lease after our TTL lapsed and another task took
// over).
func (s *KVStore) Release(ctx context.Context, target, owner string) error {
	entry, err := s.kv.Get(Key(target))
	if errors.Is(err, nats.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(entry.Value()) == "" || ownerOf(string(entry.Value())) != owner {
		return nil
	}
	return s.kv.Delete(Key(target))
}

// Holder returns the current owner, "" when free.
func (s *KVStore) Holder(ctx context.Context, target string) (string, error) {
	entry, err := s.kv.Get(Key(target))
	if errors.Is(err, nats.ErrKeyNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ownerOf(string(entry.Value())), nil
}

func ownerOf(v string) string {
	for i, c := range v {
		if c == '|' {
			return v[:i]
		}
	}
	return v
}

// ---------------------------------------------------------------------------
// In-memory implementation (unit tests)
// ---------------------------------------------------------------------------

// MemStore is an in-memory lease store with TTL support.
type MemStore struct {
	mu    sync.Mutex
	held  map[string]string
	until map[string]time.Time
	now   func() time.Time
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{held: map[string]string{}, until: map[string]time.Time{}, now: time.Now}
}

func (m *MemStore) expired(key string) bool {
	u, ok := m.until[key]
	return ok && m.now().After(u)
}

// Acquire takes the lease; false when another owner holds a live lease.
func (m *MemStore) Acquire(_ context.Context, target, owner string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := Key(target)
	if _, ok := m.held[k]; ok && !m.expired(k) {
		return false, nil
	}
	m.held[k] = owner
	m.until[k] = m.now().Add(ttl)
	return true, nil
}

// Release drops the lease only when held by owner.
func (m *MemStore) Release(_ context.Context, target, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := Key(target)
	if m.held[k] == owner {
		delete(m.held, k)
		delete(m.until, k)
	}
	return nil
}

// Holder returns the live owner ("" when free or expired).
func (m *MemStore) Holder(_ context.Context, target string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := Key(target)
	if m.expired(k) {
		return "", nil
	}
	return m.held[k], nil
}
