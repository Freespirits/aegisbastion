package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := New()
	l.SetNow(func() time.Time { return now })

	// rps=2: two immediate allows, third denied.
	if ok, _ := l.Allow("k", 2); !ok {
		t.Fatal("first allow should pass")
	}
	if ok, _ := l.Allow("k", 2); !ok {
		t.Fatal("second allow should pass")
	}
	ok, retry := l.Allow("k", 2)
	if ok {
		t.Fatal("third allow within the same second must be denied")
	}
	if retry <= 0 {
		t.Fatalf("retryAfter must be positive, got %v", retry)
	}
	// Advance 600ms → 1.2 tokens refilled → one allow.
	now = now.Add(600 * time.Millisecond)
	if ok, _ := l.Allow("k", 2); !ok {
		t.Fatal("allow after refill should pass")
	}
	// Different key has its own bucket.
	if ok, _ := l.Allow("other", 2); !ok {
		t.Fatal("separate key should have a full bucket")
	}
	// rps=0 → uncapped.
	if ok, _ := l.Allow("k", 0); !ok {
		t.Fatal("rps=0 means uncapped")
	}
}
