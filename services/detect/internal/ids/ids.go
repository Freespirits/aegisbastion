// Package ids mints the Detect module's identifiers: ULIDs for wire ids
// (fnd_/job_/evt_) and a deterministic UUIDv5 mapping for the Postgres
// fallback store (whose finding_id column is uuid — copy-migration to
// dp.findings stays stable across redeliveries).
package ids

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/oklog/ulid/v2"
)

// uuidV5Namespace is RFC 4122 §4.3 name-space DNS, matching uuidv5 usage for
// deterministic name→UUID derivation.
var uuidV5Namespace = [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// New returns a fresh ULID with the given prefix, e.g. New("fnd") →
// "fnd_01J9A7K2…" (doc 04 §4.3 finding_id form).
func New(prefix string) string { return prefix + "_" + ulid.Make().String() }

// UUIDv5 deterministically maps a wire id (e.g. "fnd_01J9A7…") to a UUID
// string for uuid-typed Postgres columns. Same input → same UUID, so
// duplicate publishes upsert onto the same fallback row.
func UUIDv5(name string) string {
	h := sha1.New()
	h.Write(uuidV5Namespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// SHA256Hex hashes bytes to lowercase hex ("sha256" fingerprints, doc 04 §7.2).
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
