// Package ids generates the platform's prefixed ULID identifiers
// (doc 01 §5: msn_…, pln_…, tsk_…, agent_…, aud_…, req_…).
package ids

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// New returns a fresh ULID with the given prefix, e.g. New("tsk").
func New(prefix string) string {
	return prefix + "_" + ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader).String()
}
