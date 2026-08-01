// Package risk is the Detect Risk Scorer (doc 04 §8, D6): the deterministic
// risk-v1 scoring function — same inputs, same score, full factor breakdown
// for explainability and dispute resolution. Pure and side-effect free, so
// old findings can be batch-rescored if a risk-v2 ever ships.
//
//	base      = cvss40_base (fallback cvss31; 0–10)
//	m_exploit = 1.5 KEV | 1.3 epss ≥ 0.5 | 1.15 epss ≥ 0.1 | 1.0
//	m_exposure= 1.2 internet | 1.0 internal | 0.8 isolated
//	m_verdict = 1.0 CONFIRMED | 0.8 NOT_VALIDATABLE | 0.6 INCONCLUSIVE
//	m_asset   = 1.3 critical | 1.15 high | 1.0 medium | 0.85 low
//	bonus     = +1.0 flat on base when exploit_verified by EVS (capped 10)
//
//	score = round( clamp(0,10, base*m_exploit + bonus) × m_exposure
//	               × m_verdict × m_asset × 10 )
//	tiers: P1 ≥ 90 | P2 ≥ 70 | P3 ≥ 40 | P4 ≥ 15 | P5 < 15
package risk

import (
	"math"
	"strings"
)

// Version is the scorer build recorded on RiskScore.scorer_version.
const Version = "risk-v1"

// Verdict multipliers (doc 04 §8 m_verdict). NOT_REPRODUCIBLE is deliberately
// absent from the doc's table: those findings are false positives (doc 04 §6)
// and score 0 — they must never outrank a live candidate.
const (
	VerdictConfirmed       = "CONFIRMED"
	VerdictNotReproducible = "NOT_REPRODUCIBLE"
	VerdictInconclusive    = "INCONCLUSIVE"
	VerdictNotValidatable  = "NOT_VALIDATABLE"
)

// Factors is the scorer's input vector (doc 04 §8).
type Factors struct {
	// CVSS is the base score (CVSS 4.0 preferred, 3.1 fallback; 0–10).
	CVSS float64
	// EPSS is the exploit-probability from the local mirror (0 when unknown).
	EPSS float64
	// KEV marks CISA Known-Exploited membership.
	KEV bool
	// Exposure: "internet" | "internal" | "isolated" (asset inventory /
	// Discover labels; empty → internal, multiplier 1.0).
	Exposure string
	// AssetCriticality: "critical" | "high" | "medium" | "low" (empty → medium).
	AssetCriticality string
	// ExploitVerified: the EVS reproduced the exploit (flat +1.0 on base).
	ExploitVerified bool
	// Verdict: the AVE/EVS validation verdict (CONFIRMED|NOT_REPRODUCIBLE|
	// INCONCLUSIVE|NOT_VALIDATABLE).
	Verdict string
	// IntelStale marks a mirror older than 48 h (doc 04 §12: scoring
	// continues; tiers flagged for review).
	IntelStale bool
	// IntelMirror records the mirror version for reproducibility.
	IntelMirror string
}

// Score is the scorer output: 0–100 plus the P1–P5 tier and the full factor
// breakdown stored on the finding (doc 04 §4.3 risk.factors).
type Score struct {
	Score   int
	Tier    string
	Factors map[string]any
}

// TierFor maps a 0–100 score onto the P1–P5 bands (doc 04 §8).
func TierFor(score int) string {
	switch {
	case score >= 90:
		return "P1"
	case score >= 70:
		return "P2"
	case score >= 40:
		return "P3"
	case score >= 15:
		return "P4"
	default:
		return "P5"
	}
}

// TierAtOrAbove reports whether tier is at or above (more urgent than or
// equal to) the threshold tier — the Ruling C8 alert-mapping gate.
func TierAtOrAbove(tier, threshold string) bool {
	return tierRank(tier) <= tierRank(threshold)
}

func tierRank(t string) int {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	default:
		return 5
	}
}

// ScoreFactors evaluates risk-v1 (pure; doc 04 §8).
func ScoreFactors(f Factors) Score {
	base := clamp(f.CVSS, 0, 10)

	mExploit := 1.0
	switch {
	case f.KEV:
		mExploit = 1.5
	case f.EPSS >= 0.5:
		mExploit = 1.3
	case f.EPSS >= 0.1:
		mExploit = 1.15
	}

	mExposure := 1.0
	exposure := strings.ToLower(strings.TrimSpace(f.Exposure))
	switch exposure {
	case "internet", "internet-facing":
		mExposure = 1.2
		exposure = "internet"
	case "isolated":
		mExposure = 0.8
	default:
		exposure = "internal"
	}

	mVerdict := 0.0
	verdict := strings.ToUpper(strings.TrimSpace(f.Verdict))
	switch verdict {
	case VerdictConfirmed:
		mVerdict = 1.0
	case VerdictNotValidatable:
		mVerdict = 0.8
	case VerdictInconclusive:
		mVerdict = 0.6
	default: // NOT_REPRODUCIBLE and anything unrecognized → false-positive floor
		verdict = VerdictNotReproducible
	}

	mAsset := 1.0
	criticality := strings.ToLower(strings.TrimSpace(f.AssetCriticality))
	switch criticality {
	case "critical":
		mAsset = 1.3
	case "high":
		mAsset = 1.15
	case "low":
		mAsset = 0.85
	default:
		criticality = "medium"
	}

	weighted := base * mExploit
	if f.ExploitVerified {
		weighted = clamp(weighted+1.0, 0, 10) // flat bonus, capped at 10 (doc 04 §8)
	}
	weighted = clamp(weighted, 0, 10)

	score := int(math.Round(weighted * mExposure * mVerdict * mAsset * 10))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	factors := map[string]any{
		"cvss":              round2(base),
		"epss":              f.EPSS,
		"kev":               f.KEV,
		"exposure":          exposure,
		"asset_criticality": criticality,
		"exploit_verified":  f.ExploitVerified,
		"verdict":           verdict,
		"m_exploit":         mExploit,
		"m_exposure":        mExposure,
		"m_verdict":         mVerdict,
		"m_asset":           mAsset,
	}
	if f.IntelMirror != "" {
		factors["intel_mirror"] = f.IntelMirror
	}
	if f.IntelStale {
		factors["intel_stale"] = true
	}
	return Score{Score: score, Tier: TierFor(score), Factors: factors}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
