// Package ids mints the prefixed identifiers the platform contracts use
// (plan ids "pln_…", idempotency keys, event ids) and deterministic ids for
// the CAI stub planner, where the same mission intent must always yield the
// same plan.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// crockford is the base32 alphabet used by ULIDs.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns "<prefix>_<ULID>" — e.g. "pln_01J90AKQ6X…". The id is a
// real ULID: 48-bit millisecond timestamp + 80 bits of crypto-random entropy,
// Crockford base32 encoded. It falls back to a panic on entropy failure
// because an id-minter that cannot mint must never silently collide.
func NewULID(prefix string) string {
	var entropy [10]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic(fmt.Sprintf("ids: crypto/rand unavailable: %v", err))
	}
	var raw [16]byte
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(raw[0:8], ms<<16) // 48-bit time in the high bytes
	copy(raw[6:], entropy[:])
	if prefix == "" {
		return encodeBase32(raw[:])
	}
	return prefix + "_" + encodeBase32(raw[:])
}

// encodeBase32 encodes 16 bytes as 26 Crockford characters (ULID layout).
func encodeBase32(b []byte) string {
	out := make([]byte, 26)
	// 128 bits → 26 groups of 5 bits (first group uses only the low bit).
	bitPos := 0
	for i := 0; i < 26; i++ {
		bytePos := bitPos / 8
		shift := bitPos % 8
		var v uint16
		if bytePos < len(b) {
			v = uint16(b[bytePos]) << 8
		}
		if bytePos+1 < len(b) {
			v |= uint16(b[bytePos+1])
		}
		out[i] = crockford[(v>>(11-shift))&0x1F]
		bitPos += 5
	}
	return string(out)
}

// Deterministic returns "<prefix>_<hex20>" derived from sha256(seed). Used by
// the CAI stub planner so identical intents produce identical plan ids and
// idempotency keys (replays are safe and tests are stable).
func Deterministic(prefix string, seed []byte) string {
	sum := sha256.Sum256(seed)
	return prefix + "_" + hex.EncodeToString(sum[:])[:20]
}

// Hash12 returns the first 12 hex chars of sha256(seed), for compact
// idempotency-key suffixes.
func Hash12(seed []byte) string {
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:])[:12]
}
