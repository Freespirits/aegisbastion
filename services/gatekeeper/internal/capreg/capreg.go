// Package capreg maps capability names to their canonical risk class
// (R0–R3, doc 01 §5.3 / Ruling B.4). policy-service needs the risk class of a
// requested capability to evaluate pipeline steps 5–7; the authoritative
// source at MVP is this registry (seeded from doc 01 §5.3's module mapping +
// Ruling A), overridable via a JSON file for new capabilities.
package capreg

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Registry resolves capability → risk class. Pattern entries use a trailing
// ".*" wildcard (e.g. "stress.*").
type Registry struct {
	mu      sync.RWMutex
	exact   map[string]platformv1.RiskClass
	pattern map[string]platformv1.RiskClass // key without the trailing ".*"
}

// Default returns the registry seeded with the canonical MVP capability set:
//   - doc 01 §5.3: Discover=R0/R1, Monitor=R0/R1 (Ruling A), Detect=R1–R2,
//     Alert=R0, stress engine=R2, Phish-Catcher=R0, AI red-team=R3
//   - Ruling A: monitor.watch / monitor.rescan are R1; monitor.baseline.set /
//     monitor.feed.sync are R0.
func Default() *Registry {
	r := &Registry{
		exact:   map[string]platformv1.RiskClass{},
		pattern: map[string]platformv1.RiskClass{},
	}
	seed := map[string]platformv1.RiskClass{
		// Monitor (Ruling A).
		"monitor.watch":        platformv1.RiskClass_RISK_CLASS_R1,
		"monitor.rescan":       platformv1.RiskClass_RISK_CLASS_R1,
		"monitor.baseline.set": platformv1.RiskClass_RISK_CLASS_R0,
		"monitor.feed.sync":    platformv1.RiskClass_RISK_CLASS_R0,
		// Alert delivery (R0).
		"alert.deliver": platformv1.RiskClass_RISK_CLASS_R0,
		// Phish-Catcher client-side checks (R0).
		"intel.phishing_indicators": platformv1.RiskClass_RISK_CLASS_R0,
	}
	for k, v := range seed {
		r.exact[k] = v
	}
	patterns := map[string]platformv1.RiskClass{
		"discover.passive": platformv1.RiskClass_RISK_CLASS_R0,
		"discover.cloud":   platformv1.RiskClass_RISK_CLASS_R0,
		"recon":            platformv1.RiskClass_RISK_CLASS_R1, // recon.subdomain_enum etc.
		"scan.active":      platformv1.RiskClass_RISK_CLASS_R1, // doc 11 §3.1 examples (non-exploiting scan)
		"detect.scan":      platformv1.RiskClass_RISK_CLASS_R2,
		"vuln.validate":    platformv1.RiskClass_RISK_CLASS_R2, // exploit validation = intrusive
		"stress":           platformv1.RiskClass_RISK_CLASS_R2, // stress.http_flood etc. (R2; prod needs four-eyes)
		"ai_redteam":       platformv1.RiskClass_RISK_CLASS_R3,
		"redteam":          platformv1.RiskClass_RISK_CLASS_R3,
	}
	for k, v := range patterns {
		r.pattern[k] = v
	}
	return r
}

// Lookup resolves a capability to its risk class. Exact entries win over
// patterns; the longest matching pattern wins among patterns.
func (r *Registry) Lookup(capability string) (platformv1.RiskClass, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if rc, ok := r.exact[capability]; ok {
		return rc, true
	}
	best := ""
	var rc platformv1.RiskClass
	for p, c := range r.pattern {
		if capability == p || strings.HasPrefix(capability, p+".") {
			if len(p) > len(best) {
				best, rc = p, c
			}
		}
	}
	if best == "" {
		return platformv1.RiskClass_RISK_CLASS_UNSPECIFIED, false
	}
	return rc, true
}

// LoadFile merges overrides from a JSON file of the form
// {"capability.or.pattern.*": "R2", …}. Later loads override earlier entries.
func (r *Registry) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("capreg: read %s: %w", path, err)
	}
	var entries map[string]string
	if err := json.Unmarshal(raw, &entries); err != nil {
		return fmt.Errorf("capreg: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for cap, cls := range entries {
		rc, err := ParseRiskClass(cls)
		if err != nil {
			return fmt.Errorf("capreg: %s: %w", cap, err)
		}
		if strings.HasSuffix(cap, ".*") {
			r.pattern[strings.TrimSuffix(cap, ".*")] = rc
		} else {
			r.exact[cap] = rc
		}
	}
	return nil
}

// ParseRiskClass parses "R0".."R3".
func ParseRiskClass(s string) (platformv1.RiskClass, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "R0":
		return platformv1.RiskClass_RISK_CLASS_R0, nil
	case "R1":
		return platformv1.RiskClass_RISK_CLASS_R1, nil
	case "R2":
		return platformv1.RiskClass_RISK_CLASS_R2, nil
	case "R3":
		return platformv1.RiskClass_RISK_CLASS_R3, nil
	default:
		return platformv1.RiskClass_RISK_CLASS_UNSPECIFIED, fmt.Errorf("invalid risk class %q", s)
	}
}

// RiskClassString renders a RiskClass enum as "R0".."R3".
func RiskClassString(rc platformv1.RiskClass) string {
	switch rc {
	case platformv1.RiskClass_RISK_CLASS_R0:
		return "R0"
	case platformv1.RiskClass_RISK_CLASS_R1:
		return "R1"
	case platformv1.RiskClass_RISK_CLASS_R2:
		return "R2"
	case platformv1.RiskClass_RISK_CLASS_R3:
		return "R3"
	default:
		return ""
	}
}
