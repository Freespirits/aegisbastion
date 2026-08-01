package evidence

import (
	"bytes"
	"testing"
)

func TestRedactStripsSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		must string // must be gone
	}{
		{"auth header", "GET / HTTP/1.1\r\nAuthorization: Bearer abcdef1234567890\r\n\r\n", "abcdef1234567890"},
		{"cookie", "HTTP/1.1 200 OK\r\nSet-Cookie: sid=supersecretvalue123\r\n\r\n", "supersecretvalue123"},
		{"json password", `{"username":"admin","password":"hunter2"}`, "hunter2"},
		{"json token", `{"access_token":"tok_live_99z88y77"}`, "tok_live_99z88y77"},
		{"form secret", "user=a&password=s3cr3t-pass&ok=1", "s3cr3t-pass"},
		{"aws key", "key = AKIAIOSFODNN7EXAMPLE in body", "AKIAIOSFODNN7EXAMPLE"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIblah\n-----END RSA PRIVATE KEY-----", "MIIblah"},
		{"bearer inline", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"},
	}
	for _, tc := range cases {
		out := Redact([]byte(tc.in))
		if bytes.Contains(out, []byte(tc.must)) {
			t.Errorf("%s: secret %q survived redaction: %s", tc.name, tc.must, out)
		}
		if !bytes.Contains(out, []byte("[REDACTED")) {
			t.Errorf("%s: no redaction marker in output: %s", tc.name, out)
		}
	}
}

func TestRedactKeepsBenignContent(t *testing.T) {
	in := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>canary s48abc123</html>"
	out := Redact([]byte(in))
	if !bytes.Contains(out, []byte("canary s48abc123")) {
		t.Fatalf("benign canary content destroyed: %s", out)
	}
	if !bytes.Contains(out, []byte("Content-Type: text/html")) {
		t.Fatalf("benign header destroyed: %s", out)
	}
}

func TestSpillWritesFile(t *testing.T) {
	dir := t.TempDir()
	s := &Store{SpillDir: dir}
	path, err := s.spill("msn_x/tsk_y/fnd_z/transcript.http", []byte("payload"))
	if err != nil {
		t.Fatalf("spill: %v", err)
	}
	if path == "" {
		t.Fatal("empty spill path")
	}
}
