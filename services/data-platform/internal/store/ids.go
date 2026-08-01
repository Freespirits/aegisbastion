package store

import "github.com/google/uuid"

// newUUIDv7 mints a time-ordered UUIDv7 (doc 09 §12: ID format is UUIDv7
// everywhere — time-ordered, index-friendly).
func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// NewUUIDv7 mints a UUIDv7 for callers outside the store package.
func NewUUIDv7() string { return newUUIDv7() }
