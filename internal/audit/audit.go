// Package audit writes hash-chained, append-only audit events.
// Events are written inside the caller's transaction, so an audited change
// and its audit record commit or roll back together.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Event is one audit record. Detail must contain only non-secret fields;
// callers build it from explicit allowlists, never by dumping request bodies.
type Event struct {
	OrgID        string         `json:"org_id"`
	Seq          int64          `json:"seq"`
	At           time.Time      `json:"at"`
	Actor        string         `json:"actor"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	RequestID    string         `json:"request_id,omitempty"`
	Result       string         `json:"result"` // success, denied, failed
	Detail       map[string]any `json:"detail,omitempty"`
	PrevHash     []byte         `json:"prev_hash"`
	Hash         []byte         `json:"hash"`
}

// canonical returns the bytes that are hashed: every field except Hash,
// with PrevHash included, in a fixed JSON encoding.
func canonical(e *Event) ([]byte, error) {
	type c struct {
		OrgID        string         `json:"org_id"`
		Seq          int64          `json:"seq"`
		At           string         `json:"at"`
		Actor        string         `json:"actor"`
		Action       string         `json:"action"`
		ResourceType string         `json:"resource_type"`
		ResourceID   string         `json:"resource_id"`
		RequestID    string         `json:"request_id"`
		Result       string         `json:"result"`
		Detail       map[string]any `json:"detail"`
		PrevHash     []byte         `json:"prev_hash"`
	}
	d := e.Detail
	if d == nil {
		d = map[string]any{}
	}
	// encoding/json sorts map keys, so this is deterministic.
	return json.Marshal(c{e.OrgID, e.Seq, e.At.UTC().Format(time.RFC3339Nano), e.Actor, e.Action,
		e.ResourceType, e.ResourceID, e.RequestID, e.Result, d, e.PrevHash})
}

// ComputeHash returns SHA-256(canonical(event)), which already includes PrevHash.
func ComputeHash(e *Event) ([]byte, error) {
	b, err := canonical(e)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// Write appends e to the org's chain inside tx. It locks the org's chain head
// row, so concurrent writers serialize per org. At is set if zero, and is
// truncated to microseconds to match Postgres precision.
func Write(ctx context.Context, tx pgx.Tx, e *Event) error {
	if e.OrgID == "" || e.Actor == "" || e.Action == "" {
		return errors.New("audit: org, actor and action are required")
	}
	if e.Result == "" {
		e.Result = "success"
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = e.At.UTC().Truncate(time.Microsecond)

	var seq int64
	var prev []byte
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE org_id = $1 FOR UPDATE`, e.OrgID).Scan(&seq, &prev)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		seq, prev = 0, make([]byte, sha256.Size)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_heads (org_id, seq, hash) VALUES ($1, 0, $2)`, e.OrgID, prev); err != nil {
			return fmt.Errorf("audit: init chain: %w", err)
		}
	case err != nil:
		return fmt.Errorf("audit: lock chain: %w", err)
	}
	e.Seq, e.PrevHash = seq+1, prev
	h, err := ComputeHash(e)
	if err != nil {
		return err
	}
	e.Hash = h
	detail, err := json.Marshal(nonNil(e.Detail))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events
		(org_id, seq, at, actor, action, resource_type, resource_id, request_id, result, detail, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.OrgID, e.Seq, e.At, e.Actor, e.Action, e.ResourceType, e.ResourceID, e.RequestID, e.Result, detail, e.PrevHash, e.Hash); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_heads SET seq = $2, hash = $3 WHERE org_id = $1`, e.OrgID, e.Seq, e.Hash); err != nil {
		return fmt.Errorf("audit: advance chain: %w", err)
	}
	return nil
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// Query lists events for the org visible in tx, newest first.
func Query(ctx context.Context, tx pgx.Tx, orgID string, afterSeq int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := tx.Query(ctx, `SELECT org_id, seq, at, actor, action, resource_type, resource_id, request_id, result, detail, prev_hash, hash
		FROM audit_events WHERE org_id = $1 AND seq > $2 ORDER BY seq LIMIT $3`, orgID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var detail []byte
		if err := rows.Scan(&e.OrgID, &e.Seq, &e.At, &e.Actor, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.RequestID, &e.Result, &detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(detail, &e.Detail); err != nil {
			return nil, err
		}
		if len(e.Detail) == 0 {
			e.Detail = nil
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	Checked     int64  `json:"checked"`
	OK          bool   `json:"ok"`
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Verify recomputes the org's whole chain. Note: a successful
// verification shows internal consistency only; someone able to rewrite the
// table could also recompute hashes. The external export is the real control.
func Verify(ctx context.Context, tx pgx.Tx, orgID string) (VerifyResult, error) {
	prev := make([]byte, sha256.Size)
	var after, n int64
	for {
		batch, err := Query(ctx, tx, orgID, after, 1000)
		if err != nil {
			return VerifyResult{}, err
		}
		if len(batch) == 0 {
			break
		}
		for i := range batch {
			e := &batch[i]
			n++
			if e.Seq != after+1 {
				return VerifyResult{Checked: n, BrokenAtSeq: after + 1, Reason: "missing event"}, nil
			}
			if !bytes.Equal(e.PrevHash, prev) {
				return VerifyResult{Checked: n, BrokenAtSeq: e.Seq, Reason: "prev_hash does not match previous event"}, nil
			}
			h, err := ComputeHash(e)
			if err != nil {
				return VerifyResult{}, err
			}
			if !bytes.Equal(h, e.Hash) {
				return VerifyResult{Checked: n, BrokenAtSeq: e.Seq, Reason: "event content does not match its hash"}, nil
			}
			prev, after = e.Hash, e.Seq
		}
	}
	var headSeq int64
	var headHash []byte
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE org_id = $1`, orgID).Scan(&headSeq, &headHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return VerifyResult{}, err
	}
	if err == nil && (headSeq != after || !bytes.Equal(headHash, prev)) {
		return VerifyResult{Checked: n, BrokenAtSeq: after + 1, Reason: "chain head does not match last event (events deleted?)"}, nil
	}
	return VerifyResult{Checked: n, OK: true}, nil
}
