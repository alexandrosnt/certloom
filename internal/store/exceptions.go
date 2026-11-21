package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// Exception states.
const (
	ExceptionRequested = "requested"
	ExceptionActive    = "active"
	ExceptionDenied    = "denied"
	ExceptionExpired   = "expired"
	ExceptionRevoked   = "revoked"
)

// Exception is approved, time-bound acceptance of one condition: a check, at
// a check version, with a fingerprint, on one subject. While active it
// suppresses the alert for that condition up to MaxSeverity; the finding
// itself stays open and visible and keeps counting in metrics.
type Exception struct {
	ID                   string     `json:"id"`
	SubjectType          string     `json:"subject_type"`
	SubjectID            string     `json:"subject_id"`
	Check                string     `json:"check"`
	CheckVersion         int        `json:"check_version"`
	Fingerprint          string     `json:"fingerprint"`
	MaxSeverity          string     `json:"max_severity"`
	Rationale            string     `json:"rationale"`
	CompensatingControls string     `json:"compensating_controls,omitempty"`
	RiskOwner            string     `json:"risk_owner"`
	RemediationOwner     string     `json:"remediation_owner,omitempty"`
	RemediationDue       *time.Time `json:"remediation_due,omitempty"`
	TrackingRef          string     `json:"tracking_ref,omitempty"`
	// Evidence is the finding as it was when the exception was requested.
	Evidence    json.RawMessage `json:"evidence"`
	ExpiresAt   time.Time       `json:"expires_at"`
	State       string          `json:"state"`
	RequestedBy string          `json:"requested_by"`
	CreatedAt   time.Time       `json:"created_at"`
	ApprovedBy  *string         `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time      `json:"approved_at,omitempty"`
	EndedAt     *time.Time      `json:"ended_at,omitempty"`
	EndedBy     *string         `json:"ended_by,omitempty"`
	EndReason   string          `json:"end_reason,omitempty"`
}

// ExceptionSpec is what an approval of an exception covers: everything the
// requester asked for, including the evidence the approver saw.
type ExceptionSpec struct {
	V                    int             `json:"v"`
	SubjectType          string          `json:"subject_type"`
	SubjectID            string          `json:"subject_id"`
	Check                string          `json:"check"`
	CheckVersion         int             `json:"check_version"`
	Fingerprint          string          `json:"fingerprint"`
	MaxSeverity          string          `json:"max_severity"`
	Rationale            string          `json:"rationale"`
	CompensatingControls string          `json:"compensating_controls"`
	RiskOwner            string          `json:"risk_owner"`
	RemediationOwner     string          `json:"remediation_owner"`
	RemediationDue       string          `json:"remediation_due"`
	TrackingRef          string          `json:"tracking_ref"`
	Evidence             json.RawMessage `json:"evidence"`
	ExpiresAt            time.Time       `json:"expires_at"`
}

// Spec returns the exception's approvable spec.
func (e *Exception) Spec() ExceptionSpec {
	due := ""
	if e.RemediationDue != nil {
		due = e.RemediationDue.Format(time.DateOnly)
	}
	// Re-encode the evidence so the digest does not depend on how the
	// database spaces its JSON.
	var ev any
	_ = json.Unmarshal(e.Evidence, &ev)
	evidence, _ := json.Marshal(ev)
	return ExceptionSpec{V: 1, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Check: e.Check, CheckVersion: e.CheckVersion,
		Fingerprint: e.Fingerprint, MaxSeverity: e.MaxSeverity, Rationale: e.Rationale, CompensatingControls: e.CompensatingControls,
		RiskOwner: e.RiskOwner, RemediationOwner: e.RemediationOwner, RemediationDue: due, TrackingRef: e.TrackingRef,
		Evidence: evidence, ExpiresAt: e.ExpiresAt.UTC().Truncate(time.Second)}
}

// SHA256 is the hex digest of the spec's JSON encoding.
func (s ExceptionSpec) SHA256() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const exceptionCols = `id, subject_type, subject_id, check_id, check_version, fingerprint, max_severity, rationale, compensating_controls,
	risk_owner, remediation_owner, remediation_due, tracking_ref, evidence, expires_at, state,
	requested_by, created_at, approved_by, approved_at, ended_at, ended_by, end_reason`

func scanException(r pgx.Row) (*Exception, error) {
	e := &Exception{}
	err := r.Scan(&e.ID, &e.SubjectType, &e.SubjectID, &e.Check, &e.CheckVersion, &e.Fingerprint, &e.MaxSeverity, &e.Rationale,
		&e.CompensatingControls, &e.RiskOwner, &e.RemediationOwner, &e.RemediationDue, &e.TrackingRef, &e.Evidence, &e.ExpiresAt,
		&e.State, &e.RequestedBy, &e.CreatedAt, &e.ApprovedBy, &e.ApprovedAt, &e.EndedAt, &e.EndedBy, &e.EndReason)
	return e, notFound(err)
}

// CreateException inserts a requested exception (ErrConflict if one is
// already requested or active for the same subject and check).
func (tx *Tx) CreateException(ctx context.Context, e *Exception) error {
	e.ID, e.State = ids.New("exc"), ExceptionRequested
	e.ExpiresAt = e.ExpiresAt.UTC().Truncate(time.Second)
	return conflict(tx.QueryRow(ctx, `INSERT INTO policy_exceptions (id, org_id, subject_type, subject_id, check_id, check_version,
		fingerprint, max_severity, rationale, compensating_controls, risk_owner, remediation_owner, remediation_due, tracking_ref,
		evidence, expires_at, requested_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING created_at`,
		e.ID, tx.OrgID, e.SubjectType, e.SubjectID, e.Check, e.CheckVersion, e.Fingerprint, e.MaxSeverity, e.Rationale,
		e.CompensatingControls, e.RiskOwner, e.RemediationOwner, e.RemediationDue, e.TrackingRef, e.Evidence, e.ExpiresAt, e.RequestedBy).
		Scan(&e.CreatedAt))
}

// GetException returns an exception, optionally locking it.
func (tx *Tx) GetException(ctx context.Context, id string, forUpdate bool) (*Exception, error) {
	q := `SELECT ` + exceptionCols + ` FROM policy_exceptions WHERE id = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanException(tx.QueryRow(ctx, q, id))
}

// ListExceptions lists exceptions, newest first; state "" means all.
func (tx *Tx) ListExceptions(ctx context.Context, state string, limit int) ([]*Exception, error) {
	rows, err := tx.Query(ctx, `SELECT `+exceptionCols+` FROM policy_exceptions WHERE ($1 = '' OR state = $1)
		ORDER BY created_at DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Exception
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ActivateException records the approval and suppresses matching alerts.
func (tx *Tx) ActivateException(ctx context.Context, id, approvedBy string) error {
	tag, err := tx.Exec(ctx, `UPDATE policy_exceptions SET state = 'active', approved_by = $2, approved_at = now()
		WHERE id = $1 AND state = 'requested' AND expires_at > now()`, id, approvedBy)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return tx.applyExceptions(ctx, "", "")
}

// EndException moves a requested or active exception to a final state
// (denied, expired or revoked) and returns the ids of findings whose alerts
// were suppressed by it and are now open again.
func (tx *Tx) EndException(ctx context.Context, id, state, by, reason string) ([]string, error) {
	tag, err := tx.Exec(ctx, `UPDATE policy_exceptions SET state = $2, ended_at = now(), ended_by = NULLIF($3, ''), end_reason = $4
		WHERE id = $1 AND state IN ('requested','active')`, id, state, by, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return tx.reopenUnexcepted(ctx, "", "")
}

// DueExceptions returns active exceptions past expiry, and those within
// remindBefore of it that have not been reminded yet (marking them reminded).
func (tx *Tx) DueExceptions(ctx context.Context, remindBefore time.Duration) (expired, remind []*Exception, err error) {
	rows, err := tx.Query(ctx, `SELECT `+exceptionCols+` FROM policy_exceptions WHERE state = 'active' AND expires_at <= now()`)
	if err != nil {
		return nil, nil, err
	}
	if expired, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Exception, error) { return scanException(r) }); err != nil {
		return nil, nil, err
	}
	rows, err = tx.Query(ctx, `UPDATE policy_exceptions SET reminded_at = now()
		WHERE state = 'active' AND reminded_at IS NULL AND expires_at > now() AND expires_at <= now() + LEAST($1::interval, (expires_at - approved_at) / 2)
		RETURNING `+exceptionCols, remindBefore)
	if err != nil {
		return nil, nil, err
	}
	remind, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Exception, error) { return scanException(r) })
	return expired, remind, err
}

// ExpireRequestedExceptions closes requests whose approval request expired,
// or that would already be over.
func (tx *Tx) ExpireRequestedExceptions(ctx context.Context) error {
	_, err := tx.Exec(ctx, `UPDATE policy_exceptions e SET state = 'expired', ended_at = now(), end_reason = 'not approved in time'
		WHERE e.state = 'requested' AND (e.expires_at <= now() OR NOT EXISTS (
		  SELECT 1 FROM approvals a WHERE a.resource_type = 'exception' AND a.resource_id = e.id AND a.state = 'requested'))`)
	return err
}

// severityRank orders severities in SQL the same way checks.Severity.Rank does.
const severityRank = `CASE %s WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END`

func rank(col string) string { return fmt.Sprintf(severityRank, col) }

// ExceptionCoversFinding is the SQL condition for "exception e covers finding f"
// (aliases e and f), shared by suppression, listings and metrics.
var ExceptionCoversFinding = `e.state = 'active' AND e.expires_at > now()
	AND e.subject_type = f.subject_type AND e.subject_id = f.subject_id AND e.check_id = f.check_id
	AND e.check_version = f.check_version AND e.fingerprint = f.fingerprint
	AND ` + rank("f.severity") + ` <= ` + rank("e.max_severity")

// applyExceptions suppresses alerts whose finding is covered by an active
// exception, until that exception expires (also moving suppressed_until when a
// new exception replaces an old one). An empty subject
// means all subjects.
func (tx *Tx) applyExceptions(ctx context.Context, subjectType, subjectID string) error {
	_, err := tx.Exec(ctx, `UPDATE alerts a SET state = 'suppressed', suppressed_until = e.expires_at
		FROM findings f, policy_exceptions e
		WHERE f.id = a.finding_id AND f.resolved_at IS NULL AND a.state IN ('open','acked','suppressed')
		  AND ($1 = '' OR (f.subject_type = $1 AND f.subject_id = $2)) AND `+ExceptionCoversFinding, subjectType, subjectID)
	return err
}

// reopenUnexcepted reopens suppressed alerts that no active exception covers
// any more (it ended, or the finding got worse than it accepts) and returns
// their finding ids. The alert counts as new for escalation.
func (tx *Tx) reopenUnexcepted(ctx context.Context, subjectType, subjectID string) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE alerts a SET state = 'open', suppressed_until = NULL, created_at = now(),
		  escalation_level = 0, last_escalated_at = NULL
		FROM findings f
		WHERE f.id = a.finding_id AND a.state = 'suppressed' AND f.resolved_at IS NULL
		  AND ($1 = '' OR (f.subject_type = $1 AND f.subject_id = $2))
		  AND NOT EXISTS (SELECT 1 FROM policy_exceptions e WHERE `+ExceptionCoversFinding+`)
		RETURNING a.finding_id`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// exceptionFor returns the id of the active exception covering a finding.
func (tx *Tx) exceptionFor(ctx context.Context, f *Finding) (*string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT e.id FROM policy_exceptions e, (SELECT $1::text AS subject_type, $2::text AS subject_id,
		$3::text AS check_id, $4::text AS severity, $5::int AS check_version, $6::text AS fingerprint) f WHERE `+ExceptionCoversFinding,
		f.SubjectType, f.SubjectID, f.Check, f.Severity, f.CheckVersion, f.Fingerprint).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &id, err
}

// ReopenUncovered reopens every suppressed alert that no active, unexpired
// exception covers.
func (tx *Tx) ReopenUncovered(ctx context.Context) error {
	_, err := tx.reopenUnexcepted(ctx, "", "")
	return err
}
