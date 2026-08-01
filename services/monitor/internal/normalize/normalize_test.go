package normalize

import (
	"strings"
	"testing"
)

func TestCanonicalHeaders(t *testing.T) {
	in := map[string][]string{
		"Server":          {"nginx"},
		"Date":            {"Thu, 30 Jul 2026 12:00:00 GMT"},
		"Set-Cookie":      {"session=abc"},
		"X-Request-Id":    {"r-1"},
		"CF-Ray":          {"8f…"},
		"X-Amz-Date":      {"20260730T120000Z"},
		"X-Frame-Options": {"DENY", "SAMEORIGIN"},
	}
	out := CanonicalHeaders(in)
	if out["server"] != "nginx" {
		t.Fatalf("server = %q", out["server"])
	}
	for _, dropped := range []string{"date", "set-cookie", "x-request-id", "cf-ray", "x-amz-date"} {
		if _, ok := out[dropped]; ok {
			t.Fatalf("volatile header %q must be dropped (doc 03 §6.3/§9.5)", dropped)
		}
	}
	if out["x-frame-options"] != "DENY, SAMEORIGIN" {
		t.Fatalf("multi-value header not sorted/joined: %q", out["x-frame-options"])
	}
}

func TestSimHash_StabilityAndDistance(t *testing.T) {
	body1 := []byte(`<html><body><h1>Welcome to Acme</h1><p>Products and services.</p></body></html>`)
	// Same content, different nonce/csrf/analytics → same hash (doc 03 §6.3).
	body2 := []byte(`<html><head><script nonce="r4nd0m"></script><meta name="csrf-token" content="abc123"></head><body><h1>Welcome to Acme</h1><p>Products and services.</p><a href="?utm_source=nl">x</a></body></html>`)
	h1 := SimHash64(TokenizeBody(body1))
	h2 := SimHash64(TokenizeBody(body2))
	if HammingDistance(h1, h2) > 6 {
		t.Fatalf("volatile-token churn must not move the hash much: distance %d", HammingDistance(h1, h2))
	}
	// Completely different content → large distance.
	body3 := []byte(`<html><body><h1>Error 503</h1><p>Database connection failed at node 7.</p></body></html>`)
	h3 := SimHash64(TokenizeBody(body3))
	if HammingDistance(h1, h3) < 12 {
		t.Fatalf("different content must exceed the medium threshold: distance %d", HammingDistance(h1, h3))
	}
	if got := SimHashHex(h1); len(got) != 16 {
		t.Fatalf("SimHashHex len = %d, want 16", len(got))
	}
}

func TestRedactPII(t *testing.T) {
	body := []byte(`contact jane.doe@acme.com or call; card 4111 1111 1111 1111; token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c`)
	redacted, classes := RedactPII(body, nil)
	s := string(redacted)
	if strings.Contains(s, "jane.doe@acme.com") || strings.Contains(s, "4111 1111") || strings.Contains(s, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("PII not redacted: %s", s)
	}
	want := map[string]bool{"pii:email": true, "pci:card_track": true, "pii:jwt": true}
	for _, c := range classes {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Fatalf("missing redaction classes: %v (got %v)", want, classes)
	}
}

func TestFingerprintTech(t *testing.T) {
	headers := map[string]string{
		"server":       "Apache/2.4.41 (Ubuntu)",
		"x-powered-by": "PHP/7.2.34",
	}
	body := []byte(`<html><body><div data-reactroot=""></div><script src="jquery.min.js"></script></body></html>`)
	tech := FingerprintTech(headers, body)
	names := map[string]string{}
	for _, te := range tech {
		names[te.Name] = te.Version
	}
	if names["apache"] != "2.4.41" {
		t.Fatalf("apache version = %q", names["apache"])
	}
	if names["php"] != "7.2.34" {
		t.Fatalf("php version = %q", names["php"])
	}
	if _, ok := names["react"]; !ok {
		t.Fatal("react not detected via body marker")
	}
	if _, ok := names["jquery"]; !ok {
		t.Fatal("jquery not detected via body marker")
	}
}
