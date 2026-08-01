package coordinator

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/planner"
)

// Params is the decoded task params schema (doc 04 §4.2, wire-exact inside
// TaskSpec.params / TaskAssignment.params).
type Params struct {
	Profile         string
	CheckIDs        []string
	ExcludeCheckIDs []string
	ExploitVerify   bool
	MaxRequests     uint32
	Ports           string
	SpecRef         string
	// SafeMode defaults TRUE: destructive/state-changing checks and
	// credential testing require explicit RoE param flags surfaced through
	// the plan (doc 04 §10.3); absence = skipped, never silently run.
	SafeMode bool
	// FindingFingerprints drives detect.revalidate (doc 04 §4.1).
	FindingFingerprints []string
}

// ParseParams decodes and validates the assignment params for capability.
// Unknown params are tolerated (forward-compat); malformed types are a
// plan-level rejection (FAILED with a structured error so commanders can
// correct the plan, doc 04 §4.5).
func ParseParams(capability string, s *structpb.Struct) (*Params, error) {
	p := &Params{SafeMode: true, Profile: planner.ProfileStandard}
	if s == nil {
		return p, nil
	}
	m := s.AsMap()
	get := func(k string) (any, bool) { v, ok := m[k]; return v, ok }
	str := func(k string) (string, error) {
		v, ok := get(k)
		if !ok {
			return "", nil
		}
		sv, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("params.%s must be a string", k)
		}
		return sv, nil
	}
	strList := func(k string) ([]string, error) {
		v, ok := get(k)
		if !ok {
			return nil, nil
		}
		lv, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("params.%s must be a string array", k)
		}
		out := make([]string, 0, len(lv))
		for _, e := range lv {
			sv, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("params.%s must be a string array", k)
			}
			if strings.TrimSpace(sv) != "" {
				out = append(out, sv)
			}
		}
		return out, nil
	}
	boolean := func(k string) (bool, bool, error) {
		v, ok := get(k)
		if !ok {
			return false, false, nil
		}
		bv, ok := v.(bool)
		if !ok {
			return false, false, fmt.Errorf("params.%s must be a bool", k)
		}
		return bv, true, nil
	}
	num := func(k string) (uint32, error) {
		v, ok := get(k)
		if !ok {
			return 0, nil
		}
		nv, ok := v.(float64)
		if !ok || nv < 0 {
			return 0, fmt.Errorf("params.%s must be a non-negative number", k)
		}
		return uint32(nv), nil
	}

	var err error
	if p.Profile, err = str("profile"); err != nil {
		return nil, err
	}
	if p.Profile == "" {
		p.Profile = planner.ProfileStandard
	}
	if p.CheckIDs, err = strList("check_ids"); err != nil {
		return nil, err
	}
	if p.ExcludeCheckIDs, err = strList("exclude_check_ids"); err != nil {
		return nil, err
	}
	if p.ExploitVerify, _, err = boolean("exploit_verify"); err != nil {
		return nil, err
	}
	if p.MaxRequests, err = num("max_requests"); err != nil {
		return nil, err
	}
	if p.Ports, err = str("ports"); err != nil {
		return nil, err
	}
	if p.SpecRef, err = str("spec_ref"); err != nil {
		return nil, err
	}
	if sm, present, berr := boolean("safe_mode"); berr != nil {
		return nil, berr
	} else if present {
		p.SafeMode = sm
	}
	if p.FindingFingerprints, err = strList("finding_fingerprints"); err != nil {
		return nil, err
	}

	switch capability {
	case planner.CapScanWeb, planner.CapScanNetwork, planner.CapScanAPI:
		// scanner params validated above.
	case planner.CapRevalidate:
		if len(p.FindingFingerprints) == 0 {
			return nil, fmt.Errorf("detect.revalidate requires params.finding_fingerprints[]")
		}
	case planner.CapEnrich:
		// targets only.
	}
	return p, nil
}
