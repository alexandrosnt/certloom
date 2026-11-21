package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/jackc/pgx/v5"
)

// ---------- enrollment ----------

const enrollPrefix = "certloomenr_"

// ParseEnrollOrg extracts the org id from an enrollment token.
func ParseEnrollOrg(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, enrollPrefix)
	if !ok {
		return "", false
	}
	org, _, ok := strings.Cut(rest, ".")
	return org, ok && ids.HasPrefix(org, ids.Org)
}

// CreateEnrollmentToken creates a one-time token.
func (tx *Tx) CreateEnrollmentToken(ctx context.Context, nameHint, createdBy string, ttl time.Duration) (string, secret.Value, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", secret.Value{}, err
	}
	plain := enrollPrefix + tx.OrgID + "." + base64.RawURLEncoding.EncodeToString(b)
	id := ids.New("enr")
	_, err := tx.Exec(ctx, `INSERT INTO enrollment_tokens (id, org_id, token_hash, name_hint, created_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, tx.OrgID, hashToken(plain), nameHint, createdBy, time.Now().Add(ttl))
	return id, secret.FromString(plain), err
}

// ConsumeEnrollmentToken marks a valid, unused token as used (single use).
func (tx *Tx) ConsumeEnrollmentToken(ctx context.Context, plain, agentID string) (nameHint string, err error) {
	err = tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at = now(), agent_id = $2
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING name_hint`, hashToken(plain), agentID).Scan(&nameHint)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidToken
	}
	return nameHint, err
}

// ---------- agents ----------

// Agent is an enrolled agent.
type Agent struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	State         string               `json:"state"`
	Hostname      string               `json:"hostname"`
	Version       string               `json:"version"`
	CertSerial    string               `json:"cert_serial"`
	CertNotAfter  time.Time            `json:"cert_not_after"`
	Capabilities  agentproto.Heartbeat `json:"capabilities"`
	LastHeartbeat *time.Time           `json:"last_heartbeat,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	RevokedAt     *time.Time           `json:"revoked_at,omitempty"`
}

// Health derives liveness from the last heartbeat (domain model: stale > 3 intervals).
func (a *Agent) Health(now time.Time) string {
	switch {
	case a.State == "revoked":
		return "revoked"
	case a.LastHeartbeat == nil:
		return "never-seen"
	case now.Sub(*a.LastHeartbeat) > 24*time.Hour:
		return "offline"
	case now.Sub(*a.LastHeartbeat) > 90*time.Second:
		return "stale"
	}
	return "active"
}

const agentCols = `id, name, state, hostname, version, cert_serial, cert_not_after, capabilities, last_heartbeat, created_at, revoked_at`

func scanAgent(r pgx.Row) (*Agent, error) {
	a := &Agent{}
	var caps []byte
	if err := r.Scan(&a.ID, &a.Name, &a.State, &a.Hostname, &a.Version, &a.CertSerial, &a.CertNotAfter, &caps, &a.LastHeartbeat,
		&a.CreatedAt, &a.RevokedAt); err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal(caps, &a.Capabilities)
	return a, nil
}

// CreateAgent inserts an enrolled agent.
func (tx *Tx) CreateAgent(ctx context.Context, id, name, hostname, serial string, notAfter time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO agents (id, org_id, name, hostname, cert_serial, cert_not_after) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, tx.OrgID, name, hostname, serial, notAfter)
	return conflict(err)
}

// GetAgent returns an agent by id or name.
func (tx *Tx) GetAgent(ctx context.Context, ref string) (*Agent, error) {
	return scanAgent(tx.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE id = $1 OR name = $1`, ref))
}

// ListAgents lists agents.
func (tx *Tx) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := tx.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RecordHeartbeat stores liveness and capabilities.
func (tx *Tx) RecordHeartbeat(ctx context.Context, agentID string, hb agentproto.Heartbeat) error {
	b, _ := json.Marshal(hb)
	_, err := tx.Exec(ctx, `UPDATE agents SET last_heartbeat = now(), version = $2, hostname = $3, capabilities = $4 WHERE id = $1`,
		agentID, hb.Version, hb.Hostname, b)
	return err
}

// RotateAgentCert records a renewed identity certificate.
func (tx *Tx) RotateAgentCert(ctx context.Context, agentID, serial string, notAfter time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE agents SET cert_serial = $2, cert_not_after = $3 WHERE id = $1 AND state = 'active'`, agentID, serial, notAfter)
	return err
}

// RevokeAgent revokes an agent; pending tasks are expired.
func (tx *Tx) RevokeAgent(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE agents SET state = 'revoked', revoked_at = now() WHERE id = $1 AND state = 'active'`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_tasks SET state = 'expired', error = 'agent revoked' WHERE agent_id = $1 AND state IN ('pending','delivered')`, id)
	return err
}

// ---------- tasks ----------

// AgentTask is a stored task.
type AgentTask struct {
	ID          string              `json:"id"`
	AgentID     string              `json:"agent_id"`
	RunID       *string             `json:"run_id,omitempty"`
	Type        string              `json:"type"`
	Envelope    agentproto.Envelope `json:"-"`
	NotAfter    time.Time           `json:"not_after"`
	State       string              `json:"state"`
	Result      json.RawMessage     `json:"result,omitempty"`
	Error       string              `json:"error,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	CompletedAt *time.Time          `json:"completed_at,omitempty"`
}

// InsertTask stores a signed task.
func (tx *Tx) InsertTask(ctx context.Context, t agentproto.Task, env agentproto.Envelope, runID *string) error {
	b, _ := json.Marshal(env)
	_, err := tx.Exec(ctx, `INSERT INTO agent_tasks (id, org_id, agent_id, run_id, type, envelope, not_after) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		t.ID, tx.OrgID, t.AgentID, runID, t.Type, b, t.NotAfter)
	return err
}

// PendingTasks returns undelivered or unacknowledged tasks for an agent and
// marks them delivered. Delivered-but-unanswered tasks are re-sent: the agent
// dedupes by task id, so redelivery after a lost response is safe.
func (tx *Tx) PendingTasks(ctx context.Context, agentID string) ([]agentproto.Envelope, error) {
	if _, err := tx.Exec(ctx, `UPDATE agent_tasks SET state = 'expired', error = 'not completed before not_after'
		WHERE agent_id = $1 AND state IN ('pending','delivered') AND not_after <= now()`, agentID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `UPDATE agent_tasks SET state = 'delivered', delivered_at = now()
		WHERE agent_id = $1 AND state IN ('pending','delivered') RETURNING envelope`, agentID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (agentproto.Envelope, error) {
		var b []byte
		var e agentproto.Envelope
		if err := r.Scan(&b); err != nil {
			return e, err
		}
		return e, json.Unmarshal(b, &e)
	})
}

// CompleteTask records a result. It is idempotent: a second result for a
// finished task is ignored. Returns the task's run id (if any).
func (tx *Tx) CompleteTask(ctx context.Context, agentID, taskID string, res agentproto.Result) (*string, bool, error) {
	state := "succeeded"
	if !res.OK {
		state = "failed"
	}
	out := res.Output
	if len(out) == 0 {
		out = json.RawMessage("null")
	}
	var runID *string
	err := tx.QueryRow(ctx, `UPDATE agent_tasks SET state = $3, result = $4, error = $5, completed_at = now()
		WHERE id = $1 AND agent_id = $2 AND state IN ('pending','delivered') RETURNING run_id`,
		taskID, agentID, state, []byte(out), res.Error).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return runID, true, err
}

// GetTask returns a task.
func (tx *Tx) GetTask(ctx context.Context, id string) (*AgentTask, error) {
	t := &AgentTask{}
	var env, res []byte
	err := tx.QueryRow(ctx, `SELECT id, agent_id, run_id, type, envelope, not_after, state, result, error, created_at, completed_at
		FROM agent_tasks WHERE id = $1`, id).Scan(&t.ID, &t.AgentID, &t.RunID, &t.Type, &env, &t.NotAfter, &t.State, &res, &t.Error, &t.CreatedAt, &t.CompletedAt)
	if err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal(env, &t.Envelope)
	t.Result = res
	return t, nil
}

// ---------- issuers ----------

// Issuer is an ACME CA configuration.
type Issuer struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	DirectoryURL string    `json:"directory_url"`
	Email        string    `json:"email,omitempty"`
	AgreeTOS     bool      `json:"agree_tos"`
	Profile      string    `json:"profile,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// EABMode is none, reusable or single_use (ADR-0019).
	EABMode      string     `json:"eab_mode"`
	EABKID       string     `json:"eab_kid,omitempty"`
	HasEABHMAC   bool       `json:"has_eab_hmac,omitempty"`
	EABUpdatedAt *time.Time `json:"eab_updated_at,omitempty"`

	EABHMACCiphertext []byte `json:"-"`
}

const issuerCols = `id, name, kind, directory_url, email, agree_tos, profile, created_at, eab_mode, eab_kid, eab_hmac_ciphertext, eab_updated_at`

func scanIssuer(r pgx.Row) (*Issuer, error) {
	i := &Issuer{}
	err := r.Scan(&i.ID, &i.Name, &i.Kind, &i.DirectoryURL, &i.Email, &i.AgreeTOS, &i.Profile, &i.CreatedAt,
		&i.EABMode, &i.EABKID, &i.EABHMACCiphertext, &i.EABUpdatedAt)
	i.HasEABHMAC = len(i.EABHMACCiphertext) > 0
	return i, err
}

// CreateIssuer inserts an issuer.
func (tx *Tx) CreateIssuer(ctx context.Context, i *Issuer, createdBy string) error {
	i.ID, i.Kind = ids.New("iss"), "acme"
	return conflict(tx.QueryRow(ctx, `INSERT INTO issuers (id, org_id, name, kind, directory_url, email, agree_tos, profile, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at, eab_mode`, i.ID, tx.OrgID, i.Name, i.Kind, i.DirectoryURL, i.Email, i.AgreeTOS, i.Profile, createdBy).
		Scan(&i.CreatedAt, &i.EABMode))
}

// GetIssuer returns an issuer by id or name.
func (tx *Tx) GetIssuer(ctx context.Context, ref string) (*Issuer, error) {
	i, err := scanIssuer(tx.QueryRow(ctx, `SELECT `+issuerCols+` FROM issuers WHERE id = $1 OR name = $1`, ref))
	return i, notFound(err)
}

// ListIssuers lists issuers.
func (tx *Tx) ListIssuers(ctx context.Context) ([]Issuer, error) {
	rows, err := tx.Query(ctx, `SELECT `+issuerCols+` FROM issuers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Issuer, error) {
		i, err := scanIssuer(r)
		return *i, err
	})
}

// ---------- deployments ----------

// Deployment binds a lineage to an agent target and an issuer.
type Deployment struct {
	ID          string     `json:"id"`
	LineageID   string     `json:"lineage_id"`
	AgentID     string     `json:"agent_id"`
	Target      string     `json:"target"`
	IssuerID    string     `json:"issuer_id"`
	EndpointID  *string    `json:"endpoint_id,omitempty"`
	SANs        []string   `json:"sans"`
	TargetSeq   int64      `json:"target_seq"`
	RenewAt     *time.Time `json:"renew_at,omitempty"`
	RenewReason string     `json:"renew_reason,omitempty"`
	ARINextAt   *time.Time `json:"ari_next_check,omitempty"`
	Enabled     bool       `json:"enabled"`
	// MaintenanceWindow limits when the certificate may be activated (empty: any time).
	MaintenanceWindow string `json:"maintenance_window,omitempty"`
	// WindowEmergency is "block" or "renew_outside_window".
	WindowEmergency string `json:"window_emergency"`
	// Approval is "pending", "approved", "denied" or "revoked"; see
	// DeploymentSpec and ApprovalCovers.
	Approval string `json:"approval"`
	// ApprovedSpecSHA256 is the spec digest that was approved (nil: created
	// before approvals existed).
	ApprovedSpecSHA256 *string `json:"approved_spec_sha256,omitempty"`
	// KeyAlgorithm is the key the agent generates (only "ecdsa-p256" so far).
	KeyAlgorithm string `json:"key_algorithm"`
	// Challenge is "http-01" or "dns-01".
	Challenge string `json:"challenge"`
	// TemplateID is the template the deployment follows (ADR-0020).
	TemplateID *string   `json:"template_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

const deploymentCols = `id, lineage_id, agent_id, target, issuer_id, endpoint_id, sans, target_seq, renew_at, renew_reason, ari_next_check, enabled, created_at, maintenance_window, window_emergency, approval, approved_spec_sha256, key_algorithm, challenge, template_id`

func scanDeployment(r pgx.Row) (*Deployment, error) {
	d := &Deployment{}
	err := r.Scan(&d.ID, &d.LineageID, &d.AgentID, &d.Target, &d.IssuerID, &d.EndpointID, &d.SANs, &d.TargetSeq, &d.RenewAt, &d.RenewReason,
		&d.ARINextAt, &d.Enabled, &d.CreatedAt, &d.MaintenanceWindow, &d.WindowEmergency, &d.Approval, &d.ApprovedSpecSHA256, &d.KeyAlgorithm, &d.Challenge, &d.TemplateID)
	return d, notFound(err)
}

// CreateDeployment inserts a deployment.
func (tx *Tx) CreateDeployment(ctx context.Context, d *Deployment, createdBy string) error {
	d.ID, d.Enabled = ids.New("dep"), true
	if d.WindowEmergency == "" {
		d.WindowEmergency = "block"
	}
	if d.Approval == "" {
		d.Approval = "approved"
	}
	if d.KeyAlgorithm == "" {
		d.KeyAlgorithm = "ecdsa-p256"
	}
	if d.Challenge == "" {
		d.Challenge = "http-01"
	}
	return conflict(tx.QueryRow(ctx, `INSERT INTO deployments (id, org_id, lineage_id, agent_id, target, issuer_id, endpoint_id, sans, created_by,
		maintenance_window, window_emergency, approval, approved_spec_sha256, key_algorithm, challenge, template_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING created_at`, d.ID, tx.OrgID, d.LineageID, d.AgentID, d.Target, d.IssuerID, d.EndpointID, d.SANs, createdBy,
		d.MaintenanceWindow, d.WindowEmergency, d.Approval, d.ApprovedSpecSHA256, d.KeyAlgorithm, d.Challenge, d.TemplateID).
		Scan(&d.CreatedAt))
}

// SetDeploymentWindow changes a deployment's maintenance window settings.
func (tx *Tx) SetDeploymentWindow(ctx context.Context, id, spec, emergency string) error {
	tag, err := tx.Exec(ctx, `UPDATE deployments SET maintenance_window = $2, window_emergency = $3, version = version + 1 WHERE id = $1`,
		id, spec, emergency)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GetDeployment returns a deployment by id, optionally locking it.
func (tx *Tx) GetDeployment(ctx context.Context, id string, forUpdate bool) (*Deployment, error) {
	q := `SELECT ` + deploymentCols + ` FROM deployments WHERE id = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanDeployment(tx.QueryRow(ctx, q, id))
}

// ListDeployments lists deployments.
func (tx *Tx) ListDeployments(ctx context.Context) ([]*Deployment, error) {
	rows, err := tx.Query(ctx, `SELECT `+deploymentCols+` FROM deployments ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// NextTargetSeq increments and returns the deployment's task sequence.
func (tx *Tx) NextTargetSeq(ctx context.Context, deploymentID string) (int64, error) {
	var s int64
	err := tx.QueryRow(ctx, `UPDATE deployments SET target_seq = target_seq + 1 WHERE id = $1 RETURNING target_seq`, deploymentID).Scan(&s)
	return s, err
}

// SetRenewal sets when the deployment should next renew, and why.
func (tx *Tx) SetRenewal(ctx context.Context, id string, at time.Time, reason string, ariNext *time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE deployments SET renew_at = $2, renew_reason = $3, ari_next_check = COALESCE($4, ari_next_check), ari_checked_at = CASE WHEN $4::timestamptz IS NULL THEN ari_checked_at ELSE now() END
		WHERE id = $1`, id, at, reason, ariNext)
	return err
}

// ---------- workflow runs ----------

// Run states (docs/domain-model.md).
const (
	RunPlanned        = "planned"
	RunIssuing        = "issuing"
	RunIssued         = "issued"
	RunDeploying      = "deploying"
	RunVerifying      = "verifying"
	RunVerified       = "verified"
	RunRollingBack    = "rolling_back"
	RunRolledBack     = "rolled_back"
	RunRetryScheduled = "retry_scheduled"
	RunFailed         = "failed"
	// RunWaitingWindow: issued, waiting for the maintenance window to deploy.
	RunWaitingWindow = "waiting_window"
	// RunBlocked: no maintenance window is left before the safety deadline.
	RunBlocked   = "blocked"
	RunCancelled = "cancelled"
)

// Terminal reports whether a run state is final.
func Terminal(state string) bool {
	switch state {
	case RunVerified, RunFailed, RunRolledBack, RunCancelled:
		return true
	}
	return false
}

// Run is a renewal workflow execution.
type Run struct {
	ID             string  `json:"id"`
	DeploymentID   string  `json:"deployment_id"`
	State          string  `json:"state"`
	Reason         string  `json:"reason"`
	Attempt        int     `json:"attempt"`
	CurrentTaskID  *string `json:"current_task_id,omitempty"`
	PreviousSHA256 *string `json:"previous_sha256,omitempty"`
	IssuedSHA256   *string `json:"issued_sha256,omitempty"`
	// SpecSHA256 is the approved deployment spec the run was started for.
	SpecSHA256    *string    `json:"spec_sha256,omitempty"`
	Error         string     `json:"error,omitempty"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Steps         []RunStep  `json:"steps,omitempty"`
}

// RunStep is one entry in a run's timeline.
type RunStep struct {
	State  string    `json:"state"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

const runCols = `id, deployment_id, state, reason, attempt, current_task_id, previous_sha256, issued_sha256, error, created_by, created_at, updated_at, next_attempt_at, completed_at, spec_sha256`

func scanRun(r pgx.Row) (*Run, error) {
	x := &Run{}
	err := r.Scan(&x.ID, &x.DeploymentID, &x.State, &x.Reason, &x.Attempt, &x.CurrentTaskID, &x.PreviousSHA256, &x.IssuedSHA256, &x.Error,
		&x.CreatedBy, &x.CreatedAt, &x.UpdatedAt, &x.NextAttemptAt, &x.CompletedAt, &x.SpecSHA256)
	return x, notFound(err)
}

// ErrRunActive is returned when a deployment already has an active run.
var ErrRunActive = errors.New("deployment already has an active renewal run")

// CreateRun starts a run (one active run per deployment, enforced by index).
func (tx *Tx) CreateRun(ctx context.Context, deploymentID, reason, createdBy string, previous *string, spec string) (*Run, error) {
	r := &Run{ID: ids.New("run"), DeploymentID: deploymentID, State: RunPlanned, Reason: reason, Attempt: 1, CreatedBy: createdBy, PreviousSHA256: previous,
		SpecSHA256: &spec}
	err := tx.QueryRow(ctx, `INSERT INTO workflow_runs (id, org_id, deployment_id, state, reason, created_by, previous_sha256, spec_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at, updated_at`, r.ID, tx.OrgID, deploymentID, r.State, reason, createdBy, previous, spec).Scan(&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(conflict(err), ErrConflict) {
			return nil, ErrRunActive
		}
		return nil, err
	}
	return r, tx.AddStep(ctx, r.ID, RunPlanned, reason)
}

// GetRun returns a run, optionally locked, with its steps.
func (tx *Tx) GetRun(ctx context.Context, id string, forUpdate bool) (*Run, error) {
	q := `SELECT ` + runCols + ` FROM workflow_runs WHERE id = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	r, err := scanRun(tx.QueryRow(ctx, q, id))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT state, detail, at FROM workflow_steps WHERE run_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	r.Steps, err = pgx.CollectRows(rows, func(rr pgx.CollectableRow) (RunStep, error) {
		var s RunStep
		err := rr.Scan(&s.State, &s.Detail, &s.At)
		return s, err
	})
	return r, err
}

// ListRuns lists recent runs.
func (tx *Tx) ListRuns(ctx context.Context, limit int) ([]*Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := tx.Query(ctx, `SELECT `+runCols+` FROM workflow_runs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRun persists state transitions and appends a timeline step.
func (tx *Tx) UpdateRun(ctx context.Context, r *Run, detail string) error {
	var completed *time.Time
	if Terminal(r.State) {
		now := time.Now()
		completed = &now
	}
	if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET state=$2, attempt=$3, current_task_id=$4, issued_sha256=$5, error=$6,
		next_attempt_at=$7, completed_at=$8, updated_at=now() WHERE id=$1`,
		r.ID, r.State, r.Attempt, r.CurrentTaskID, r.IssuedSHA256, r.Error, r.NextAttemptAt, completed); err != nil {
		return err
	}
	r.CompletedAt = completed
	return tx.AddStep(ctx, r.ID, r.State, detail)
}

// AddStep appends a timeline entry.
func (tx *Tx) AddStep(ctx context.Context, runID, state, detail string) error {
	_, err := tx.Exec(ctx, `INSERT INTO workflow_steps (org_id, run_id, state, detail) VALUES ($1,$2,$3,$4)`, tx.OrgID, runID, state, detail)
	return err
}

// ActiveRunFor returns the active run for a deployment, if any.
func (tx *Tx) ActiveRunFor(ctx context.Context, deploymentID string) (*Run, error) {
	return scanRun(tx.QueryRow(ctx, `SELECT `+runCols+` FROM workflow_runs WHERE deployment_id = $1
		AND state NOT IN ('verified','failed','rolled_back','cancelled')`, deploymentID))
}
