package store

import "time"

// Asset kinds (doc 02 §4.1 type vocabulary).
const (
	AssetDomain        = "domain"
	AssetSubdomain     = "subdomain"
	AssetIP            = "ip"
	AssetNetblock      = "netblock"
	AssetCert          = "cert"
	AssetCloudResource = "cloud_resource"
)

// AssetKinds lists the valid asset types.
var AssetKinds = []string{
	AssetDomain, AssetSubdomain, AssetIP, AssetNetblock, AssetCert, AssetCloudResource,
}

// Asset statuses (CHECK constraint in db/migrations/000003).
const (
	StatusActive      = "active"
	StatusCandidate   = "candidate"
	StatusExpired     = "expired"
	StatusQuarantined = "quarantined"
)

// Finding modules (doc 09 §4.2: findings produced by Detect, AI red-team,
// DDoS-sim and Phish-Catcher rollups).
const (
	ModuleDetect       = "detect"
	ModuleAIRedteam    = "ai-redteam"
	ModuleDDoSSim      = "ddos-sim"
	ModulePhishCatcher = "phish-catcher"
)

// FindingModules lists the valid finding producer modules.
var FindingModules = []string{
	ModuleDetect, ModuleAIRedteam, ModuleDDoSSim, ModulePhishCatcher,
}

// OffensiveModules produce R1+ output: their ingest batches must carry a
// gatekeeper Scope Token (doc 09 §9.1). Phish-Catcher is R0 (client-side,
// verdict metadata only).
var OffensiveModules = map[string]bool{
	ModuleDetect:    true,
	ModuleAIRedteam: true,
	ModuleDDoSSim:   true,
}

// Severities (CHECK constraint in db/migrations/000003).
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Grant roles (CHECK constraint on tenancy.grants in db/migrations/000003).
var GrantRoles = []string{
	"admin", "analyst", "viewer", "service_discover", "service_monitor",
	"service_detect", "service_alert", "service_ddos", "service_redteam",
	"service_phish", "commander",
}

// IngestRoles may write via the Ingest API.
var IngestRoles = map[string]bool{
	"admin": true, "service_discover": true, "service_monitor": true,
	"service_detect": true, "service_ddos": true, "service_redteam": true,
	"service_phish": true,
}

// TransitionRoles may drive findings lifecycle transitions via REST.
var TransitionRoles = map[string]bool{
	"admin": true, "analyst": true, "service_detect": true, "commander": true,
}

// Asset is one dp.assets row (UUIDs rendered as text).
type Asset struct {
	AssetID    string         `json:"asset_id"`
	TenantID   string         `json:"tenant_id"`
	Type       string         `json:"type"`
	Value      string         `json:"value"`
	Attributes map[string]any `json:"attributes"`
	Confidence float64        `json:"confidence"`
	Status     string         `json:"status"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	RoeID      string         `json:"roe_id"`
}

// Edge is one dp.asset_edges row.
type Edge struct {
	EdgeID     string         `json:"edge_id"`
	TenantID   string         `json:"tenant_id"`
	Src        string         `json:"src"`
	Dst        string         `json:"dst"`
	Rel        string         `json:"rel"`
	Attributes map[string]any `json:"attributes"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// Finding is one dp.findings row.
type Finding struct {
	TenantID    string         `json:"tenant_id"`
	FindingID   string         `json:"finding_id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	AssetUID    string         `json:"asset_uid"`
	Module      string         `json:"module"`
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	State       string         `json:"state"`
	Fingerprint *string        `json:"fingerprint,omitempty"`
	Validation  map[string]any `json:"validation"`
	Risk        map[string]any `json:"risk"`
	EvidenceRef *string        `json:"evidence_ref,omitempty"`
	Occurrence  int            `json:"occurrence"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	TaskID      *string        `json:"task_id,omitempty"`
	Compliance  map[string]any `json:"compliance,omitempty"`
	LegalHold   bool           `json:"legal_hold"`
	Sensitive   bool           `json:"sensitive"`
}

// StateTransition is one dp.finding_state_transitions row.
type StateTransition struct {
	TenantID  string         `json:"tenant_id"`
	FindingID string         `json:"finding_id"`
	FromState *string        `json:"from_state,omitempty"`
	ToState   string         `json:"to_state"`
	Actor     map[string]any `json:"actor"`
	TaskID    *string        `json:"task_id,omitempty"`
	Note      *string        `json:"note,omitempty"`
	TS        time.Time      `json:"ts"`
}

// Actor identifies who caused a data-platform action (doc 09 §4.4).
type Actor struct {
	Type string `json:"type"` // commander|service|human|module
	ID   string `json:"id"`
}

// Grant is one tenancy.grants row.
type Grant struct {
	GrantID   string `json:"grant_id"`
	TenantID  string `json:"tenant_id"`
	Principal string `json:"principal"`
	Role      string `json:"role"`
}

// Tenant is one tenancy.tenants row.
type Tenant struct {
	TenantID           string  `json:"tenant_id"`
	Name               string  `json:"name"`
	Tier               string  `json:"tier"`
	DataRegion         string  `json:"data_region"`
	RetentionProfileID *string `json:"retention_profile_id,omitempty"`
	Status             string  `json:"status"`
}
