package model

// Confidence scoring (doc 02 §4.4):
//
//	confidence = clamp(Σ per-source weights, 0..1)
//
// weights: credentialed cloud API = 1.0, CT log = 0.9, passive DNS = 0.8,
// reputable aggregator = 0.7, permutation/bruteforce guess validated by live
// resolution = 0.6 (only when the active capability is granted), unvalidated
// guess = quarantined. Multi-source corroboration adds +0.1 each, capped at
// 1.0. Assets below 0.5 are exposed as `candidate` in the API.

// SourceWeight classes.
const (
	WeightCredentialedCloud = 1.0
	WeightCTLog             = 0.9
	WeightPassiveDNS        = 0.8
	WeightAggregator        = 0.7
	WeightValidatedGuess    = 0.6 // active-only; quarantined without the grant
	WeightUnvalidatedGuess  = 0.0 // ⇒ quarantine (UNVALIDATED_GUESS)
)

// CorroborationBonus is added per additional source beyond the first.
const CorroborationBonus = 0.1

// CandidateThreshold — below this, assets are exposed as `candidate`.
const CandidateThreshold = 0.5

// SourceWeightOf maps a connector source name to its doc 02 §4.4 weight.
// Unknown sources default to the aggregator weight (0.7).
func SourceWeightOf(source string) float64 {
	switch source {
	case "aws_resource_explorer", "aws_organizations", "azure_resource_graph", "gcp_cloud_asset_inventory":
		return WeightCredentialedCloud
	case "crt.sh", "censys_ct", "facebook_ct", "google_ct":
		return WeightCTLog
	case "securitytrails", "virustotal", "shodan_dns":
		return WeightPassiveDNS
	case "rapiddns", "wayback", "bgpview", "ripestat", "rdap", "censys":
		return WeightAggregator
	}
	return WeightAggregator
}

// Confidence computes the merged confidence for an asset observed by the
// given source weights: base = max weight, then +0.1 per additional source,
// clamped to [0,1] (doc 02 §4.4).
func Confidence(weights []float64) float64 {
	if len(weights) == 0 {
		return 0
	}
	max := 0.0
	for _, w := range weights {
		if w > max {
			max = w
		}
	}
	c := max + CorroborationBonus*float64(len(weights)-1)
	if c > 1.0 {
		c = 1.0
	}
	if c < 0 {
		c = 0
	}
	return c
}

// StatusForConfidence maps confidence to the exposure status (doc 02 §4.4:
// below 0.5 → candidate).
func StatusForConfidence(c float64) string {
	if c < CandidateThreshold {
		return AssetCandidate
	}
	return AssetActive
}
