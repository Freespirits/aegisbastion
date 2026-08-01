// Package model defines the Discover module's wire contracts (doc 02 §3.2 —
// JSON messages versioned via schema_version) and its internal domain types:
// DiscoveryOrder, OrderStatus, Task, RawFinding, AssetChange, Asset.
//
// These are module-owned JSON contracts (doc 02 §3.2), NOT protos — the
// platform proto set (doc 01 §5) intentionally has no discover package;
// module events flow as versioned JSON on the hub.discover.* subjects
// (DISCOVER_EVENTS stream, deploy/jetstream-bootstrap).
package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the current contract version (doc 02 §3.2).
const SchemaVersion = "1.1"

// Techniques (doc 02 §3.2). The active two are accepted in the schema but not
// implemented at MVP — the planner drops them with ACTIVE_NOT_ALLOWED
// (doc 02 §8).
type Technique string

const (
	TechniquePassiveDNS        Technique = "passive_dns"
	TechniqueCT                Technique = "ct"
	TechniqueSubdomainPassive  Technique = "subdomain_passive"
	TechniqueIPNetblock        Technique = "ip_netblock"
	TechniqueCloudCredentialed Technique = "cloud_credentialed"
	TechniqueSubdomainActive   Technique = "subdomain_active"   // MVP: dropped, ACTIVE_NOT_ALLOWED
	TechniqueCloudPublicProbe  Technique = "cloud_public_probe" // MVP: dropped, ACTIVE_NOT_ALLOWED
)

// AllTechniques in declared order.
func AllTechniques() []Technique {
	return []Technique{
		TechniquePassiveDNS, TechniqueCT, TechniqueSubdomainPassive,
		TechniqueIPNetblock, TechniqueCloudCredentialed,
		TechniqueSubdomainActive, TechniqueCloudPublicProbe,
	}
}

// ParseTechnique validates a technique string.
func ParseTechnique(s string) (Technique, error) {
	t := Technique(s)
	switch t {
	case TechniquePassiveDNS, TechniqueCT, TechniqueSubdomainPassive,
		TechniqueIPNetblock, TechniqueCloudCredentialed,
		TechniqueSubdomainActive, TechniqueCloudPublicProbe:
		return t, nil
	}
	return "", fmt.Errorf("unknown technique %q", s)
}

// Active reports whether the technique is an active (R1) technique. Active
// techniques are out of MVP-A (doc 00 §4) — the planner drops them with
// ACTIVE_NOT_ALLOWED (doc 02 §8).
func (t Technique) Active() bool {
	return t == TechniqueSubdomainActive || t == TechniqueCloudPublicProbe
}

// Capability is the gatekeeper capability the technique maps to. Names match
// gatekeeper's capability registry (discover.passive.* / discover.cloud.* →
// R0; see services/gatekeeper internal/capreg).
func (t Technique) Capability() string {
	switch t {
	case TechniquePassiveDNS:
		return "discover.passive.dns"
	case TechniqueCT:
		return "discover.passive.ct"
	case TechniqueSubdomainPassive:
		return "discover.passive.subdomain"
	case TechniqueIPNetblock:
		return "discover.passive.ip_netblock"
	case TechniqueCloudCredentialed:
		return "discover.cloud.credentialed"
	case TechniqueSubdomainActive:
		return "discover.active.subdomain"
	case TechniqueCloudPublicProbe:
		return "discover.active.cloud_probe"
	}
	return ""
}

// Lane is the module-internal JetStream lane subject the technique's tasks
// are published on (doc 02 §2.2 queue-producer).
func (t Technique) Lane() string {
	switch t {
	case TechniquePassiveDNS, TechniqueSubdomainPassive, TechniqueIPNetblock:
		return LanePassive
	case TechniqueCT:
		return LaneCT
	case TechniqueCloudCredentialed, TechniqueCloudPublicProbe:
		return LaneCloud
	case TechniqueSubdomainActive:
		return LaneActive
	}
	return ""
}

// Module-internal lane subjects (stream DISCOVER_TASKS, workqueue).
const (
	LanePassive = "discover.tasks.passive"
	LaneCT      = "discover.tasks.ct"
	LaneCloud   = "discover.tasks.cloud"
	LaneActive  = "discover.tasks.active" // reserved; unused at MVP-A
	// SubjectResults is the worker → reducer results subject (workqueue).
	SubjectResults = "discover.results"
	// SubjectDLQ receives poison lane tasks after redelivery exhaustion.
	SubjectDLQ = "discover.dlq"
)

// Platform event subjects (DISCOVER_EVENTS stream, bootstrapped in Phase 0).
const (
	SubjectOrderStatusChanged = "hub.discover.order.status_changed"
	SubjectAssetChanged       = "hub.discover.asset.changed"
)

// Seed types (doc 02 §3.2).
type SeedType string

const (
	SeedDomain       SeedType = "domain"
	SeedCIDR         SeedType = "cidr"
	SeedASN          SeedType = "asn"
	SeedOrg          SeedType = "org"
	SeedCloudAccount SeedType = "cloud_account"
)

// Seed is one authorized starting point for enumeration.
type Seed struct {
	Type  SeedType `json:"type"`
	Value string   `json:"value"`
}

// Validate checks the seed shape (canonicalization happens separately).
func (s Seed) Validate() error {
	s.Value = strings.TrimSpace(s.Value)
	if s.Value == "" {
		return errors.New("seed value is empty")
	}
	switch s.Type {
	case SeedDomain, SeedCIDR, SeedASN, SeedOrg, SeedCloudAccount:
		return nil
	}
	return fmt.Errorf("unknown seed type %q", s.Type)
}

// RequestedBy identifies the commander principal behind an order.
type RequestedBy struct {
	Commander      string `json:"commander"` // cai|hexstrike
	AgentID        string `json:"agent_id"`
	HumanPrincipal string `json:"human_principal"`
}

// Authorization references the gatekeeper RoE record (scope/token are derived
// from it by gatekeeper — Discover never mints, Ruling B/C5).
type Authorization struct {
	ROEID     string `json:"roe_id"`
	TicketRef string `json:"ticket_ref,omitempty"`
}

// OrderOptions bound the work (doc 02 §2.4).
type OrderOptions struct {
	MaxDepth             int    `json:"max_depth"`
	MaxAssets            int    `json:"max_assets"`
	MaxTasks             int    `json:"max_tasks"`
	TimeBudgetSec        int    `json:"time_budget_sec"`
	Priority             string `json:"priority"` // normal|low
	CallbackURL          string `json:"callback_url,omitempty"`
	DedupAgainstExisting bool   `json:"dedup_against_existing"`
}

// DefaultOrderOptions are the doc 02 §2.4 defaults.
func DefaultOrderOptions() OrderOptions {
	return OrderOptions{
		MaxDepth:             2,
		MaxAssets:            50000,
		MaxTasks:             20000,
		TimeBudgetSec:        3600,
		Priority:             "normal",
		DedupAgainstExisting: true,
	}
}

// DiscoveryOrder is the commander → orchestrator order (doc 02 §3.2).
type DiscoveryOrder struct {
	SchemaVersion string        `json:"schema_version"`
	OrderID       string        `json:"order_id"` // server-assigned uuid
	TenantID      string        `json:"tenant_id"`
	RequestedBy   RequestedBy   `json:"requested_by"`
	Seeds         []Seed        `json:"seeds"`
	Techniques    []Technique   `json:"techniques"`
	Authorization Authorization `json:"authorization"`
	Options       OrderOptions  `json:"options"`
}

// Validate checks the order shape (schema, tenant, seeds, techniques).
// Gatekeeper authorization is a separate step (pepclient), not this function.
func (o *DiscoveryOrder) Validate() error {
	if o.SchemaVersion == "" {
		o.SchemaVersion = SchemaVersion
	}
	if o.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q (want %s)", o.SchemaVersion, SchemaVersion)
	}
	if _, err := ParseUUID(o.TenantID); err != nil {
		return fmt.Errorf("tenant_id: %w", err)
	}
	if o.RequestedBy.Commander != "" &&
		o.RequestedBy.Commander != "cai" && o.RequestedBy.Commander != "hexstrike" {
		return fmt.Errorf("requested_by.commander %q is not cai|hexstrike", o.RequestedBy.Commander)
	}
	if len(o.Seeds) == 0 {
		return errors.New("seeds: at least one seed is required")
	}
	seenSeeds := map[string]struct{}{}
	for i, s := range o.Seeds {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("seeds[%d]: %w", i, err)
		}
		key := string(s.Type) + "|" + strings.ToLower(strings.TrimSpace(s.Value))
		if _, dup := seenSeeds[key]; dup {
			return fmt.Errorf("seeds[%d]: duplicate seed %s %q", i, s.Type, s.Value)
		}
		seenSeeds[key] = struct{}{}
	}
	if len(o.Techniques) == 0 {
		return errors.New("techniques: at least one technique is required")
	}
	seenTech := map[Technique]struct{}{}
	for i, t := range o.Techniques {
		if _, err := ParseTechnique(string(t)); err != nil {
			return fmt.Errorf("techniques[%d]: %w", i, err)
		}
		if _, dup := seenTech[t]; dup {
			return fmt.Errorf("techniques[%d]: duplicate technique %q", i, t)
		}
		seenTech[t] = struct{}{}
	}
	if o.Authorization.ROEID == "" {
		return errors.New("authorization.roe_id is required (gatekeeper RoE record reference)")
	}
	switch o.Options.Priority {
	case "", "normal", "low":
	default:
		return fmt.Errorf("options.priority %q is not normal|low", o.Options.Priority)
	}
	return nil
}

// ApplyDefaults fills unset numeric options with doc 02 §2.4 defaults.
func (o *DiscoveryOrder) ApplyDefaults() {
	d := DefaultOrderOptions()
	if o.Options.MaxDepth <= 0 {
		o.Options.MaxDepth = d.MaxDepth
	}
	if o.Options.MaxAssets <= 0 {
		o.Options.MaxAssets = d.MaxAssets
	}
	if o.Options.MaxTasks <= 0 {
		o.Options.MaxTasks = d.MaxTasks
	}
	if o.Options.TimeBudgetSec <= 0 {
		o.Options.TimeBudgetSec = d.TimeBudgetSec
	}
	if o.Options.Priority == "" {
		o.Options.Priority = d.Priority
	}
}

// Order states (doc 02 §3.2 + discover.discovery_orders CHECK constraint).
const (
	OrderPending   = "PENDING"
	OrderRunning   = "RUNNING"
	OrderPartial   = "PARTIAL"
	OrderCompleted = "COMPLETED"
	OrderFailed    = "FAILED"
	OrderCancelled = "CANCELLED"
	OrderDenied    = "DENIED"
)

// Gate records the gatekeeper decision on the order (doc 02 §3.2).
type Gate struct {
	Decision   string   `json:"decision"` // allow|deny
	Reasons    []string `json:"reasons"`
	ROEID      string   `json:"roe_id"`
	DecisionID string   `json:"decision_id"`
	DecidedAt  string   `json:"decided_at"`
}

// Module-local reason codes (doc 02 §3.3); gatekeeper's stable enum
// (ROE_NOT_ACTIVE, TARGET_NOT_IN_SCOPE, CAPABILITY_NOT_ALLOWED,
// RATE_LIMITED, …) is surfaced verbatim.
const (
	ReasonActiveNotAllowed  = "ACTIVE_NOT_ALLOWED"
	ReasonBudgetExhausted   = "BUDGET_EXHAUSTED"
	ReasonSourceUnavailable = "SOURCE_UNAVAILABLE"
)

// Progress aggregates per-order counters (doc 02 §3.2).
type Progress struct {
	TasksTotal  int `json:"tasks_total"`
	Done        int `json:"done"`
	Failed      int `json:"failed"`
	AssetsFound int `json:"assets_found"`
	NewAssets   int `json:"new_assets"`
}

// OrderStatus is the queryable status record (doc 02 §3.2).
type OrderStatus struct {
	OrderID    string   `json:"order_id"`
	TenantID   string   `json:"tenant_id"`
	State      string   `json:"state"`
	Gate       *Gate    `json:"gate,omitempty"`
	Progress   Progress `json:"progress"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Error      *string  `json:"error"`
}

// Task is the orchestrator → worker unit (doc 02 §3.2): the smallest
// idempotent unit (technique, source, seed, shard?).
type Task struct {
	TaskID    string    `json:"task_id"`
	OrderID   string    `json:"order_id"`
	TenantID  string    `json:"tenant_id"`
	Technique Technique `json:"technique"`
	Source    string    `json:"source"`
	Seed      Seed      `json:"seed"`
	Depth     int       `json:"depth"`
	Attempt   int       `json:"attempt"`
	Deadline  time.Time `json:"deadline"`
	// ScopeToken is a gatekeeper Scope Token (EdDSA JWT; task-bound, seed ∈
	// manifest, technique ∈ capabilities, ≤15 min TTL) obtained from
	// gatekeeper token-service — set only for R1+ techniques (none at MVP-A;
	// R0 passive work carries no token, doc 11 §1). Workers verify it when
	// present (defense-in-depth, Ruling B) and refuse R1+ tasks without one.
	ScopeToken string `json:"scope_token,omitempty"`
	// ROEID is carried so the worker's refusal path can audit the RoE.
	ROEID string `json:"roe_id,omitempty"`
	// RiskClass is the gatekeeper-evaluated class ("R0" at MVP-A).
	RiskClass string `json:"risk_class"`
}

// RawFinding is the worker → reducer record (doc 02 §3.2).
type RawFinding struct {
	TaskID         string    `json:"task_id"`
	OrderID        string    `json:"order_id"`
	Asset          Asset     `json:"asset"`
	Source         string    `json:"source"`
	ObservedAt     time.Time `json:"observed_at"`
	EvidenceURI    string    `json:"evidence_uri,omitempty"`
	ConfidenceHint float64   `json:"confidence_hint"`
}

// ResultKind discriminates worker → reducer messages on discover.results.
type ResultKind string

const (
	ResultFinding ResultKind = "finding"
	ResultDone    ResultKind = "done" // task completed (counters attached)
)

// ResultMessage wraps findings and task-completion markers on discover.results.
type ResultMessage struct {
	SchemaVersion string      `json:"schema_version"`
	Kind          ResultKind  `json:"kind"`
	Finding       *RawFinding `json:"finding,omitempty"`
	Edges         []EdgeRef   `json:"edges,omitempty"`
	// Done markers:
	TaskID   string `json:"task_id,omitempty"`
	OrderID  string `json:"order_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Emitted  int    `json:"emitted,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Asset types (doc 02 §4.1).
type AssetType string

const (
	AssetDomain        AssetType = "domain"
	AssetSubdomain     AssetType = "subdomain"
	AssetIP            AssetType = "ip"
	AssetNetblock      AssetType = "netblock"
	AssetCert          AssetType = "cert"
	AssetCloudResource AssetType = "cloud_resource"
)

// Asset statuses (discover.assets CHECK constraint).
const (
	AssetActive      = "active"
	AssetCandidate   = "candidate"
	AssetExpired     = "expired"
	AssetQuarantined = "quarantined"
)

// Asset is the normalized, canonical record (doc 02 §4.1/§4.2).
type Asset struct {
	Type       AssetType      `json:"type"`
	Value      string         `json:"value"` // canonical (see canonical.go)
	Attributes map[string]any `json:"attributes,omitempty"`
}

// AssetChange kinds (doc 02 §3.2).
const (
	ChangeNew              = "new"
	ChangeReactivated      = "reactivated"
	ChangeAttributeChanged = "attribute_changed"
	ChangeExpired          = "expired"
)

// AssetChange is the reducer → Monitor/consumers event (doc 02 §3.2) on
// hub.discover.asset.changed.
type AssetChange struct {
	SchemaVersion string      `json:"schema_version"`
	TenantID      string      `json:"tenant_id"`
	AssetID       string      `json:"asset_id"`
	Kind          string      `json:"kind"`
	Asset         AssetRecord `json:"asset"`
	ChangedFields []string    `json:"changed_fields"`
	OrderID       string      `json:"order_id"`
	EmittedAt     time.Time   `json:"emitted_at"`
}

// AssetRecord is the stored asset row (discover.assets + edges target).
type AssetRecord struct {
	AssetID    string         `json:"asset_id"`
	TenantID   string         `json:"tenant_id"`
	Type       AssetType      `json:"type"`
	Value      string         `json:"value"`
	Attributes map[string]any `json:"attributes"`
	Confidence float64        `json:"confidence"`
	Status     string         `json:"status"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	ROEID      string         `json:"roe_id"`
}

// Edge relations (doc 02 §4.1).
const (
	RelResolvesTo   = "resolves_to"
	RelCNAMETo      = "cname_to"
	RelSANOf        = "san_of"
	RelHostedIn     = "hosted_in"
	RelBelongsToASN = "belongs_to_asn"
	RelCertFor      = "cert_for"
)

// EdgeRef is an inferred asset edge with endpoints as asset identities —
// the wire form on discover.results (the reducer upserts endpoints, then
// resolves ids into asset_edges rows).
type EdgeRef struct {
	Rel string `json:"rel"`
	Src Asset  `json:"src"`
	Dst Asset  `json:"dst"`
}

// Edge is one asset_edges row (ids resolved).
type Edge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	Rel string `json:"rel"`
}

// ParseUUID validates a uuid string (orders/tenants are uuids, doc 02 §3.2).
func ParseUUID(s string) (string, error) {
	if len(s) != 36 {
		return "", fmt.Errorf("not a uuid: %q", s)
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "", fmt.Errorf("not a uuid: %q", s)
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return "", fmt.Errorf("not a uuid: %q", s)
			}
		}
	}
	return strings.ToLower(s), nil
}
