// Package config provides env-driven configuration helpers shared by the
// commander adapters (doc 01 §7.1). Every knob is an environment variable so
// the same binary runs in Docker Compose and on a developer box unchanged.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Getenv returns the value of the environment variable key, or def when unset
// or empty.
func Getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// RequireMode validates that the environment variable key holds one of the
// allowed modes, returning the effective mode (def when unset). Any other
// value is a hard config error — adapters fail fast at startup rather than
// running in an unintended mode.
func RequireMode(key, def string, allowed ...string) (string, error) {
	mode := Getenv(key, def)
	for _, a := range allowed {
		if mode == a {
			return mode, nil
		}
	}
	return "", fmt.Errorf("config: %s=%q is not a supported mode (allowed: %s)",
		key, mode, strings.Join(allowed, ", "))
}
