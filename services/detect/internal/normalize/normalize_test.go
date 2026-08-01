package normalize

import (
	"testing"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/login", "CVE-2024-3400")
	b := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/login", "CVE-2024-3400")
	if a != b {
		t.Fatalf("fingerprint not deterministic: %s vs %s", a, b)
	}
	if len(a) != len("sha256:")+64 {
		t.Fatalf("bad fingerprint form: %s", a)
	}
	c := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/other", "CVE-2024-3400")
	if a == c {
		t.Fatal("different paths must fingerprint differently")
	}
	d := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/login", "CVE-2024-3401")
	if a == d {
		t.Fatal("different vuln identities must fingerprint differently")
	}
}

func TestFingerprintCollapsesIDSegments(t *testing.T) {
	a := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/users/12345", "nuclei:cve-x")
	b := Fingerprint("tenant", "https://api.acme.com", "https://api.acme.com/users/98765", "nuclei:cve-x")
	if a != b {
		t.Fatal("numeric id segments must collapse onto one fingerprint")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                             "/",
		"/":                            "/",
		"/users/123":                   "/users/{id}",
		"/a/4f8c2b1d9e/x":              "/a/{hex}/x",
		"/r/01J9A7K2M3V4B5N6P7Q8R9S0T": "/r/{tok}",
		"/api/v1/items/42/":            "/api/v1/items/{id}",
		"/plain/path":                  "/plain/path",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVulnIdentity(t *testing.T) {
	if got := VulnIdentity(scanner.RawResult{CVE: "cve-2024-3400"}); got != "CVE-2024-3400" {
		t.Fatalf("CVE identity: %s", got)
	}
	r := scanner.RawResult{Adapter: scanner.AdapterNuclei, CheckID: "cve-2024-3400"}
	if got := VulnIdentity(r); got != "nuclei:cve-2024-3400" {
		t.Fatalf("source:template identity: %s", got)
	}
}

type memView struct {
	m map[string]*Entry
}

func (v *memView) Lookup(fp string) (string, uint64, bool, error) {
	if e, ok := v.m[fp]; ok {
		return e.FindingID, e.Occurrences, true, nil
	}
	return "", 0, false, nil
}

func (v *memView) Record(fp, findingID string) error {
	if e, ok := v.m[fp]; ok {
		e.Occurrences++
		return nil
	}
	v.m[fp] = &Entry{Fingerprint: fp, FindingID: findingID, Occurrences: 1}
	return nil
}

func TestDedupMergesWithinRun(t *testing.T) {
	d := NewDedup(nil)
	fp := Fingerprint("t", "https://a", "https://a/x", "CVE-1")
	e1, dup1, err := d.Merge(fp, "fnd_1")
	if err != nil || dup1 {
		t.Fatalf("first sighting: dup=%v err=%v", dup1, err)
	}
	e2, dup2, _ := d.Merge(fp, "fnd_2")
	if !dup2 {
		t.Fatal("second sighting must be a dup")
	}
	if e2.FindingID != e1.FindingID || e2.Occurrences != 2 {
		t.Fatalf("merge state wrong: %+v", e2)
	}
	if d.Len() != 1 {
		t.Fatalf("len = %d, want 1", d.Len())
	}
}

func TestDedupCrossRunKnownView(t *testing.T) {
	view := &memView{m: map[string]*Entry{}}
	fp := Fingerprint("t", "https://a", "https://a/x", "CVE-1")

	// Run 1: new finding id assigned and recorded.
	d1 := NewDedup(view)
	e1, dup, err := d1.Merge(fp, "fnd_run1")
	if err != nil || dup || e1.Known {
		t.Fatalf("run1: %+v dup=%v err=%v", e1, dup, err)
	}

	// Run 2: the same fingerprint resolves to the SAME finding id (no respam).
	d2 := NewDedup(view)
	e2, dup2, err := d2.Merge(fp, "fnd_run2")
	if err != nil || dup2 {
		t.Fatalf("run2: dup=%v err=%v", dup2, err)
	}
	if !e2.Known || e2.FindingID != "fnd_run1" {
		t.Fatalf("cross-run dedup failed: %+v", e2)
	}
	if e2.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", e2.Occurrences)
	}
}
