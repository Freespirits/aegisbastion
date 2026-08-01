// Package store is the Postgres data layer for the platform schema (one DB
// "aegisbastion", schema-per-context; doc 01 §11). All task-state writes flow
// through Transition, which enforces the doc 01 §6.2 state machine and
// appends to the task_state_transitions log.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Risk classes (doc 01 §5.3).
const (
	RiskR0 = "R0"
	RiskR1 = "R1"
	RiskR2 = "R2"
	RiskR3 = "R3"
)

// RiskRank orders risk classes for ≤ comparisons.
func RiskRank(r string) int {
	switch r {
	case RiskR0:
		return 0
	case RiskR1:
		return 1
	case RiskR2:
		return 2
	case RiskR3:
		return 3
	}
	return -1
}

// Task states (doc 01 §6.2; matches the CHECK constraint in 000001).
const (
	TaskPending              = "PENDING"
	TaskValidating           = "VALIDATING"
	TaskQueued               = "QUEUED"
	TaskDispatched           = "DISPATCHED"
	TaskRunning              = "RUNNING"
	TaskReported             = "REPORTED"
	TaskValidated            = "VALIDATED"
	TaskCompleted            = "COMPLETED"
	TaskRejectedUnauthorized = "REJECTED_UNAUTHORIZED"
	TaskExpired              = "EXPIRED"
	TaskFailed               = "FAILED"
	TaskDead                 = "DEAD"
	TaskKilled               = "KILLED"
	TaskCancelled            = "CANCELLED"
)

// TerminalStates are states a task never leaves.
var TerminalStates = map[string]bool{
	TaskCompleted:            true,
	TaskRejectedUnauthorized: true,
	TaskExpired:              true,
	TaskDead:                 true,
	TaskKilled:               true,
	TaskCancelled:            true,
}

// Mission states (doc 01 §5.1).
const (
	MissionDraft           = "DRAFT"
	MissionActive          = "ACTIVE"
	MissionPaused          = "PAUSED"
	MissionCompleted       = "COMPLETED"
	MissionPlannerDegraded = "PLANNER_DEGRADED"
	MissionKilled          = "KILLED"
)

// Agent statuses (registry, doc 01 §5.8 + quarantine §10.5).
const (
	AgentOnline      = "ONLINE"
	AgentOffline     = "OFFLINE"
	AgentQuarantined = "QUARANTINED"
	AgentRevoked     = "REVOKED"
)

// Kill-switch scopes (doc 01 §10.5).
const (
	KillScopeGlobal  = "global"
	KillScopeMission = "mission"
	KillScopeAgent   = "agent"
)

// ErrInvalidTransition is returned when a state transition is attempted from
// a state the machine does not allow (or the row changed under us).
var ErrInvalidTransition = errors.New("invalid task state transition")

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Mission row (platform.missions).
type Mission struct {
	MissionID       string
	Name            string
	OwningCommander string // "cai" | "hexstrike"
	Objective       string
	RoeID           string
	RoeVersion      int
	Priority        string
	Labels          map[string]string
	CreatedBy       string
	State           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Plan row (platform.plans).
type Plan struct {
	PlanID         string
	MissionID      string
	SubmittedBy    string
	DelegatedBy    string
	IdempotencyKey string
	Verdict        string
	VerdictDetail  json.RawMessage
	CreatedAt      time.Time
}

// Task row (platform.tasks — the scheduler queue).
type Task struct {
	TaskID                string
	PlanID                string
	MissionID             string
	TaskKey               string
	Capability            string
	RiskClass             string
	Targets               []string
	Params                json.RawMessage
	DependsOn             []string
	TimeoutS              int
	MaxRetries            int
	Attempt               int
	State                 string
	RejectionReason       string
	AssignedAgentID       string
	AuthorizationTokenJTI string
	DecisionID            string
	ApprovalID            string
	Deadline              *time.Time
	DispatchedAt          *time.Time
	StartedAt             *time.Time
	FinishedAt            *time.Time
	ResultStatus          string
	ResultSummary         json.RawMessage
	ArtifactRefs          []string
	TargetsTouched        []string
	Err                   string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// Capability entry inside an agent manifest (doc 01 §5.8).
type Capability struct {
	Name          string `json:"name"`
	RiskClassMax  string `json:"risk_class_max"`
	SchemaVersion string `json:"schema_version"`
}

// Agent row (platform.agents).
type Agent struct {
	AgentID       string
	AgentType     string
	Version       string
	BuildHash     string
	Capabilities  []Capability
	SpiffeID      string
	MaxConcurrent int
	Region        string
	Sandboxed     bool
	Status        string
	LastHeartbeat *time.Time
	RegisteredAt  time.Time
	InFlightTasks int // populated by ListCapable
}

// Store wraps the connection pool.
type Store struct {
	Pool *pgxpool.Pool
}

// New connects and pins the schema search_path (DB_SEARCH_PATH, default
// "platform") on every pooled connection.
func New(ctx context.Context, databaseURL, searchPath string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if searchPath == "" {
		searchPath = "platform"
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET search_path TO "+pgx.Identifier{searchPath}.Sanitize()+", public")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

// ---------------------------------------------------------------------------
// Missions
// ---------------------------------------------------------------------------

// CreateMission inserts a mission row (state DRAFT).
func (s *Store) CreateMission(ctx context.Context, m *Mission) error {
	labels := m.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return s.Pool.QueryRow(ctx, `
		INSERT INTO platform.missions
		    (mission_id, name, owning_commander, objective, roe_id, roe_version,
		     priority, labels, created_by, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at, updated_at`,
		m.MissionID, m.Name, m.OwningCommander, m.Objective, m.RoeID, m.RoeVersion,
		m.Priority, labels, m.CreatedBy, m.State,
	).Scan(&m.CreatedAt, &m.UpdatedAt)
}

// GetMission fetches a mission by id.
func (s *Store) GetMission(ctx context.Context, missionID string) (*Mission, error) {
	m := &Mission{}
	err := s.Pool.QueryRow(ctx, `
		SELECT mission_id, name, owning_commander, objective, roe_id, roe_version,
		       priority, labels, created_by, state, created_at, updated_at
		FROM platform.missions WHERE mission_id = $1`, missionID,
	).Scan(&m.MissionID, &m.Name, &m.OwningCommander, &m.Objective, &m.RoeID, &m.RoeVersion,
		&m.Priority, &m.Labels, &m.CreatedBy, &m.State, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// SetMissionState transitions a mission, enforcing the allowed-from set.
func (s *Store) SetMissionState(ctx context.Context, missionID, to string, from ...string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE platform.missions SET state = $2, updated_at = now()
		WHERE mission_id = $1 AND state = ANY($3)`, missionID, to, from)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

// ListMissionsByROE returns mission ids bound to an RoE (kill on ROE-scope
// revocation).
func (s *Store) ListMissionsByROE(ctx context.Context, roeID string) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT mission_id FROM platform.missions WHERE roe_id = $1`, roeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TaskCountsByState returns task counts per state for a mission.
func (s *Store) TaskCountsByState(ctx context.Context, missionID string) (map[string]int, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT state, count(*) FROM platform.tasks WHERE mission_id = $1 GROUP BY state`, missionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

// InsertPlan inserts a plan row. When the idempotency key already exists the
// stored plan is returned with existed=true (doc 01 §5.2 idempotent intake).
func (s *Store) InsertPlan(ctx context.Context, p *Plan) (existed bool, err error) {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO platform.plans (plan_id, mission_id, submitted_by, delegated_by, idempotency_key)
		VALUES ($1,$2,$3,NULLIF($4,''),$5)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		p.PlanID, p.MissionID, p.SubmittedBy, p.DelegatedBy, p.IdempotencyKey)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return false, nil
	}
	stored, err := s.GetPlanByIdempotencyKey(ctx, p.IdempotencyKey)
	if err != nil {
		return false, err
	}
	*p = *stored
	return true, nil
}

// GetPlanByIdempotencyKey fetches a stored plan by its idempotency key.
func (s *Store) GetPlanByIdempotencyKey(ctx context.Context, key string) (*Plan, error) {
	p := &Plan{}
	err := s.Pool.QueryRow(ctx, `
		SELECT plan_id, mission_id, submitted_by, COALESCE(delegated_by,''), idempotency_key,
		       COALESCE(verdict,''), verdict_detail, created_at
		FROM platform.plans WHERE idempotency_key = $1`, key,
	).Scan(&p.PlanID, &p.MissionID, &p.SubmittedBy, &p.DelegatedBy, &p.IdempotencyKey,
		&p.Verdict, &p.VerdictDetail, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// SavePlanVerdict records the PlanVerdict (decision + per-task reasons).
func (s *Store) SavePlanVerdict(ctx context.Context, planID, verdict string, detail json.RawMessage) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE platform.plans SET verdict = $2, verdict_detail = $3 WHERE plan_id = $1`,
		planID, verdict, detail)
	return err
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

// InsertTask inserts a task row (state PENDING).
func (s *Store) InsertTask(ctx context.Context, t *Task) error {
	params := t.Params
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	targets := t.Targets
	if targets == nil {
		targets = []string{}
	}
	deps := t.DependsOn
	if deps == nil {
		deps = []string{}
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO platform.tasks
		    (task_id, plan_id, mission_id, task_key, capability, risk_class, targets,
		     params, depends_on, timeout_s, max_retries, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		t.TaskID, t.PlanID, t.MissionID, t.TaskKey, t.Capability, t.RiskClass, targets,
		params, deps, t.TimeoutS, t.MaxRetries, t.State,
	)
	return err
}

const taskCols = `
	task_id, plan_id, mission_id, task_key, capability, risk_class, targets, params,
	depends_on, timeout_s, max_retries, attempt, state, COALESCE(rejection_reason,''),
	COALESCE(assigned_agent_id,''), COALESCE(authorization_token_jti,''),
	COALESCE(decision_id,''), COALESCE(approval_id,''),
	deadline, dispatched_at, started_at, finished_at,
	COALESCE(result_status,''), result_summary, artifact_refs, targets_touched,
	COALESCE(error,''), created_at, updated_at`

func scanTask(row pgx.Row) (*Task, error) {
	t := &Task{}
	err := row.Scan(&t.TaskID, &t.PlanID, &t.MissionID, &t.TaskKey, &t.Capability, &t.RiskClass,
		&t.Targets, &t.Params, &t.DependsOn, &t.TimeoutS, &t.MaxRetries, &t.Attempt, &t.State,
		&t.RejectionReason, &t.AssignedAgentID, &t.AuthorizationTokenJTI, &t.DecisionID,
		&t.ApprovalID, &t.Deadline, &t.DispatchedAt, &t.StartedAt, &t.FinishedAt,
		&t.ResultStatus, &t.ResultSummary, &t.ArtifactRefs, &t.TargetsTouched, &t.Err,
		&t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// GetTask fetches a task by id.
func (s *Store) GetTask(ctx context.Context, taskID string) (*Task, error) {
	return scanTask(s.Pool.QueryRow(ctx,
		`SELECT `+taskCols+` FROM platform.tasks WHERE task_id = $1`, taskID))
}

// TaskField is an optional column update applied by Transition.
type TaskField struct {
	Column string
	Value  any
}

// Transition moves a task between states (doc 01 §6.2: transitions are DB
// writes by the Orchestrator only). The update is conditional on the current
// state being in fromStates (optimistic concurrency across replicas), and
// every successful transition is appended to task_state_transitions in the
// same transaction.
func (s *Store) Transition(ctx context.Context, taskID string, fromStates []string, to, actor, reason string, fields ...TaskField) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	set := "state = $2, updated_at = now()"
	args := []any{taskID, to}
	for _, f := range fields {
		set += fmt.Sprintf(", %s = $%d", f.Column, len(args)+1)
		args = append(args, f.Value)
	}
	args = append(args, fromStates)
	tag, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE platform.tasks SET %s
		WHERE task_id = $1 AND state = ANY($%d)`, set, len(args)), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	var fromState *string
	if len(fromStates) > 0 {
		fromState = &fromStates[0]
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.task_state_transitions (task_id, from_state, to_state, actor, reason)
		VALUES ($1, $2, $3, $4, NULLIF($5,''))`, taskID, fromState, to, actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PickQueuedTasks returns up to limit QUEUED tasks whose dependencies are all
// COMPLETED, locked FOR UPDATE SKIP LOCKED (doc 01 §12: the tasks table IS
// the queue). Mission state/priority join orders by mission priority then
// task deadline/creation.
func (s *Store) PickQueuedTasks(ctx context.Context, limit int) ([]*Task, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+taskCols+` FROM platform.tasks t
		WHERE t.state = 'QUEUED'
		  AND NOT EXISTS (
		      SELECT 1 FROM platform.tasks d
		      WHERE d.plan_id = t.plan_id
		        AND d.task_key IN (SELECT jsonb_array_elements_text(t.depends_on))
		        AND d.state <> 'COMPLETED'
		  )
		ORDER BY t.created_at ASC
		LIMIT $1
		FOR UPDATE OF t SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// HasFailedDependency reports whether any dependency of t is in a terminal
// non-success state (such tasks are cancelled — their DAG can never run).
func (s *Store) HasFailedDependency(ctx context.Context, t *Task) (bool, string, error) {
	if len(t.DependsOn) == 0 {
		return false, "", nil
	}
	var failedKey string
	err := s.Pool.QueryRow(ctx, `
		SELECT d.task_key FROM platform.tasks d
		WHERE d.plan_id = $1
		  AND d.task_key IN (SELECT jsonb_array_elements_text($2::jsonb))
		  AND d.state IN ('DEAD','KILLED','REJECTED_UNAUTHORIZED','CANCELLED','EXPIRED')
		LIMIT 1`, t.PlanID, mustJSON(t.DependsOn)).Scan(&failedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, failedKey, nil
}

// StaleDispatched returns DISPATCHED tasks that missed the ACK window
// (doc 01 §9 item 3: ACK within 10 s or redelivery).
func (s *Store) StaleDispatched(ctx context.Context, ackTimeout time.Duration) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE state = 'DISPATCHED' AND dispatched_at < now() - $1::interval`,
		fmt.Sprintf("%f seconds", ackTimeout.Seconds()))
}

// ExpiredRunning returns RUNNING tasks past their hard deadline (doc 01 §6.3:
// Orchestrator enforces deadline; timeout → KILLED).
func (s *Store) ExpiredRunning(ctx context.Context) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE state = 'RUNNING' AND deadline IS NOT NULL AND deadline < now()`)
}

// StaleQueued returns QUEUED tasks older than the queue TTL (→ EXPIRED).
func (s *Store) StaleQueued(ctx context.Context, ttl time.Duration) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE state = 'QUEUED' AND created_at < now() - $1::interval`,
		fmt.Sprintf("%f seconds", ttl.Seconds()))
}

// InFlightTasksForAgent returns DISPATCHED/RUNNING tasks assigned to an agent
// (requeue when the agent goes OFFLINE).
func (s *Store) InFlightTasksForAgent(ctx context.Context, agentID string) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE assigned_agent_id = $1 AND state IN ('DISPATCHED','RUNNING')`, agentID)
}

// InFlightTasksForMission returns DISPATCHED/RUNNING/QUEUED tasks of a
// mission (kill switch drain).
func (s *Store) InFlightTasksForMission(ctx context.Context, missionID string) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE mission_id = $1 AND state IN ('QUEUED','DISPATCHED','RUNNING')`, missionID)
}

// InFlightTasksMatching returns in-flight (DISPATCHED/RUNNING) tasks matching
// a capability or containing a target (target/capability revocation scopes).
func (s *Store) InFlightTasksMatching(ctx context.Context, capability, target string) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks
		WHERE state IN ('DISPATCHED','RUNNING')
		  AND ( ($1 <> '' AND capability = $1)
		     OR ($2 <> '' AND targets @> $3::jsonb) )`,
		capability, target, mustJSON([]string{target}))
}

// AllInFlightTasks returns every DISPATCHED/RUNNING task (global kill).
func (s *Store) AllInFlightTasks(ctx context.Context) ([]*Task, error) {
	return s.tasksWhere(ctx, `
		SELECT `+taskCols+` FROM platform.tasks WHERE state IN ('DISPATCHED','RUNNING')`)
}

// CountInFlightByCommander counts non-terminal tasks across all missions
// owned by a commander (doc 01 §4.2 rule 4 quota).
func (s *Store) CountInFlightByCommander(ctx context.Context, commander string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM platform.tasks t
		JOIN platform.missions m ON m.mission_id = t.mission_id
		WHERE m.owning_commander = $1
		  AND t.state IN ('QUEUED','DISPATCHED','RUNNING','REPORTED','VALIDATED')`, commander).Scan(&n)
	return n, err
}

// CountIntrusiveInFlightByROE counts in-flight R2/R3 tasks under an RoE
// (per-RoE max_concurrent_intrusive bucket, doc 01 §6.4).
func (s *Store) CountIntrusiveInFlightByROE(ctx context.Context, roeID string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM platform.tasks t
		JOIN platform.missions m ON m.mission_id = t.mission_id
		WHERE m.roe_id = $1
		  AND t.risk_class IN ('R2','R3')
		  AND t.state IN ('DISPATCHED','RUNNING')`, roeID).Scan(&n)
	return n, err
}

func (s *Store) tasksWhere(ctx context.Context, query string, args ...any) ([]*Task, error) {
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
