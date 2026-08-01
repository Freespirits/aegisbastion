package ids

import (
	"strings"
	"testing"
)

func TestNewULIDShape(t *testing.T) {
	id := NewULID("pln")
	if !strings.HasPrefix(id, "pln_") {
		t.Errorf("id = %q, want pln_ prefix", id)
	}
	if len(id) != len("pln_")+26 {
		t.Errorf("id = %q (len %d), want 26-char ULID body", id, len(id))
	}
	for _, c := range id[4:] {
		if !strings.ContainsRune(crockford, c) {
			t.Errorf("id %q contains non-Crockford char %q", id, c)
		}
	}
	// Two mints must differ (time+entropy).
	if NewULID("pln") == NewULID("pln") {
		t.Error("consecutive ULIDs collided")
	}
	// Empty prefix mints a bare ULID.
	if strings.HasPrefix(NewULID(""), "_") {
		t.Error("empty prefix must not leave a leading underscore")
	}
}

func TestDeterministic(t *testing.T) {
	a := Deterministic("pln_caistub", []byte("seed"))
	b := Deterministic("pln_caistub", []byte("seed"))
	if a != b {
		t.Errorf("same seed, different ids: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "pln_caistub_") || len(a) != len("pln_caistub_")+20 {
		t.Errorf("id = %q", a)
	}
	if Deterministic("pln_caistub", []byte("other")) == a {
		t.Error("different seeds collided")
	}
	if Hash12([]byte("seed")) == Hash12([]byte("other")) {
		t.Error("Hash12 collision on different seeds")
	}
}
