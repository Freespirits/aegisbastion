// Package ids generates prefixed ULID identifiers for gatekeeper records
// (tok_, roe_, dec_, req_, appr_, rev_, evt_). ULIDs are time-ordered and
// URL-safe, matching the id shapes used across the design docs (doc 11 §3).
package ids

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// New returns a new prefixed ULID, e.g. New("tok") -> "tok_01J9ZM8W3F…".
func New(prefix string) string {
	return prefix + "_" + ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader).String()
}
