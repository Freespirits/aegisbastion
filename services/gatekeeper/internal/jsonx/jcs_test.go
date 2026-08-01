package jsonx

import "testing"

func TestCanonical(t *testing.T) {
	out, err := Canonical(map[string]any{"b": 1, "a": "x", "c": []any{true, nil}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"x","b":1,"c":[true,null]}`
	if string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}

func TestCanonicalNestedSorted(t *testing.T) {
	out, err := Canonical(map[string]any{
		"scope": map[string]any{
			"domains":           []any{"acme.com"},
			"cidrs":             []any{},
			"explicit_excludes": []any{"legacy.acme.com"},
		},
		"roe_id": "roe_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"roe_id":"roe_1","scope":{"cidrs":[],"domains":["acme.com"],"explicit_excludes":["legacy.acme.com"]}}`
	if string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}
