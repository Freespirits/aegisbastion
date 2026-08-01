package registry

import (
	"os"
	"testing"
)

// testDatabaseURL mirrors the orchestrator integration gate.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AEGISBASTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("integration test needs AEGISBASTION_TEST_DATABASE_URL")
	}
	return dsn
}
