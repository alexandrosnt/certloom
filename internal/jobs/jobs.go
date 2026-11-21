// Package jobs is the durable, Postgres-backed job queue.
//
// Guarantees: at-least-once execution; at most one live lease per job; a
// worker whose lease expired cannot commit results (lease_epoch fencing);
// dedupe of active jobs by (kind, dedupe_key); exponential backoff with full
// jitter; global and per-org pause switches checked at claim time.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job is a claimed unit of work.
type Job struct {
	ID          int64
	OrgID       string
	Kind        string
	DedupeKey   string
	Payload     json.RawMessage
	Attempts    int // including the current attempt
	MaxAttempts int
	Epoch       int64 // fencing token for this lease
}

// ErrLeaseLost is returned when a fenced write finds the lease was taken over.
var ErrLeaseLost = errors.New("jobs: lease lost (fenced)")

// Enqueue adds a job in tx unless an active job with the same kind and
// dedupe key exists. It returns true if a job was inserted.
func Enqueue(ctx context.Context, tx pgx.Tx, orgID, kind, dedupeKey string, payload any, runAt time.Time) (bool, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if runAt.IsZero() {
		runAt = time.Now()
	}
	tag, err := tx.Exec(ctx, `INSERT INTO jobs (org_id, kind, dedupe_key, payload, run_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (kind, dedupe_key) WHERE state IN ('pending','running') DO NOTHING`, orgID, kind, dedupeKey, b, runAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Queue claims and settles jobs.
type Queue struct {
	Pool     *pgxpool.Pool
	WorkerID string
	LeaseTTL time.Duration // default 2m
}

func (q *Queue) ttl() time.Duration {
	if q.LeaseTTL <= 0 {
		return 2 * time.Minute
	}
	return q.LeaseTTL
}

// Claim leases up to n runnable jobs of the given kinds. A job is runnable if
// it is pending and due, or running with an expired lease (crashed worker).
// Jobs for paused orgs, or all jobs while globally paused, are skipped.
func (q *Queue) Claim(ctx context.Context, kinds []string, n int) ([]Job, error) {
	rows, err := q.Pool.Query(ctx, `
		WITH paused AS (
		  SELECT scope FROM automation_switches WHERE paused
		), cand AS (
		  SELECT id FROM jobs
		  WHERE kind = ANY($1)
		    AND ((state = 'pending' AND run_at <= now()) OR (state = 'running' AND lease_until < now()))
		    AND NOT EXISTS (SELECT 1 FROM paused WHERE scope = 'global' OR scope = 'org:' || jobs.org_id)
		  ORDER BY run_at
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED
		)
		UPDATE jobs j SET state = 'running', lease_owner = $3, lease_until = now() + $4::interval,
		  lease_epoch = j.lease_epoch + 1, attempts = j.attempts + 1, updated_at = now()
		FROM cand WHERE j.id = cand.id
		RETURNING j.id, j.org_id, j.kind, j.dedupe_key, j.payload, j.attempts, j.max_attempts, j.lease_epoch`,
		kinds, n, q.WorkerID, fmt.Sprintf("%d milliseconds", q.ttl().Milliseconds()))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Job, error) {
		var j Job
		var p []byte
		err := r.Scan(&j.ID, &j.OrgID, &j.Kind, &j.DedupeKey, &p, &j.Attempts, &j.MaxAttempts, &j.Epoch)
		j.Payload = p
		return j, err
	})
}

// Fence must be called inside the handler's transaction before committing
// results; it fails with ErrLeaseLost if another worker has taken the job.
func Fence(ctx context.Context, tx pgx.Tx, j Job) error {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT true FROM jobs WHERE id = $1 AND lease_epoch = $2 AND state = 'running' FOR UPDATE`, j.ID, j.Epoch).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	return err
}

// Complete marks the job done in tx (fenced).
func Complete(ctx context.Context, tx pgx.Tx, j Job) error {
	tag, err := tx.Exec(ctx, `UPDATE jobs SET state = 'done', lease_owner = NULL, lease_until = NULL, last_error = '', updated_at = now()
		WHERE id = $1 AND lease_epoch = $2 AND state = 'running'`, j.ID, j.Epoch)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return err
}

// Fail records a failed attempt (fenced). It reschedules with backoff unless
// attempts are exhausted or permanent is true, in which case the job fails.
// retryAfter, if > 0, overrides the computed backoff (e.g. Retry-After).
func (q *Queue) Fail(ctx context.Context, j Job, cause error, permanent bool, retryAfter time.Duration) error {
	msg := cause.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	if permanent || j.Attempts >= j.MaxAttempts {
		tag, err := q.Pool.Exec(ctx, `UPDATE jobs SET state = 'failed', last_error = $3, lease_owner = NULL, lease_until = NULL, updated_at = now()
			WHERE id = $1 AND lease_epoch = $2 AND state = 'running'`, j.ID, j.Epoch, msg)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrLeaseLost
		}
		return err
	}
	delay := retryAfter
	if delay <= 0 {
		delay = Backoff(j.Attempts, time.Minute, 6*time.Hour)
	}
	tag, err := q.Pool.Exec(ctx, `UPDATE jobs SET state = 'pending', last_error = $3, run_at = now() + $4::interval,
		lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE id = $1 AND lease_epoch = $2 AND state = 'running'`, j.ID, j.Epoch, msg, fmt.Sprintf("%d milliseconds", delay.Milliseconds()))
	if err == nil && tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return err
}

// Backoff returns an exponential delay with full jitter: uniform in
// [0, min(cap, base*2^(attempt-1))], with a floor of base/2.
func Backoff(attempt int, base, maxDelay time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := base
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	j := time.Duration(rand.Int64N(int64(d) + 1))
	return max(j, base/2)
}

// SetPaused sets a kill switch: scope is "global" or "org:<id>".
func SetPaused(ctx context.Context, db Execer, scope string, paused bool, reason string) error {
	_, err := db.Exec(ctx, `INSERT INTO automation_switches (scope, paused, reason) VALUES ($1,$2,$3)
		ON CONFLICT (scope) DO UPDATE SET paused = EXCLUDED.paused, reason = EXCLUDED.reason, updated_at = now()`, scope, paused, reason)
	return err
}

// Execer is satisfied by *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}
