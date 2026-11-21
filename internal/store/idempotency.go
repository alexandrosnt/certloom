package store

import (
	"bytes"
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Idempotency outcomes.
var (
	ErrIdempotencyInProgress = errors.New("a request with this Idempotency-Key is still in progress")
	ErrIdempotencyMismatch   = errors.New("this Idempotency-Key was used with a different request")
	// ErrPrecondition signals an If-Match version mismatch (HTTP 412).
	ErrPrecondition = errors.New("resource was modified (If-Match does not match current version)")
)

// IdempotentResponse is a stored response for replay.
type IdempotentResponse struct {
	Status      int
	Body        []byte
	ContentType string
}

// BeginIdempotent claims key for this request. It returns a stored response
// to replay, or nil if the caller should execute the request and then call
// FinishIdempotent (or AbortIdempotent on a server error).
func (db *DB) BeginIdempotent(ctx context.Context, org, key, actor string, reqHash []byte) (*IdempotentResponse, error) {
	var out *IdempotentResponse
	err := db.WithOrg(ctx, org, func(tx *Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO idempotency_keys (org_id, key, actor, request_hash) VALUES ($1,$2,$3,$4)
			ON CONFLICT (org_id, key) DO NOTHING`, org, key, actor, reqHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var gotActor string
		var gotHash, body []byte
		var status int
		var ctype string
		if err := tx.QueryRow(ctx, `SELECT actor, request_hash, status, response, content_type FROM idempotency_keys
			WHERE org_id = $1 AND key = $2`, org, key).Scan(&gotActor, &gotHash, &status, &body, &ctype); err != nil {
			if errors.Is(err, pgx.ErrNoRows) { // deleted concurrently (aborted); treat as in progress
				return ErrIdempotencyInProgress
			}
			return err
		}
		switch {
		case gotActor != actor || !bytes.Equal(gotHash, reqHash):
			return ErrIdempotencyMismatch
		case status == 0:
			return ErrIdempotencyInProgress
		}
		out = &IdempotentResponse{Status: status, Body: body, ContentType: ctype}
		return nil
	})
	return out, err
}

// FinishIdempotent stores the response for replay.
func (db *DB) FinishIdempotent(ctx context.Context, org, key string, r IdempotentResponse) error {
	return db.WithOrg(ctx, org, func(tx *Tx) error {
		_, err := tx.Exec(ctx, `UPDATE idempotency_keys SET status = $3, response = $4, content_type = $5 WHERE org_id = $1 AND key = $2`,
			org, key, r.Status, r.Body, r.ContentType)
		return err
	})
}

// AbortIdempotent releases a key after a server error so the client may retry.
func (db *DB) AbortIdempotent(ctx context.Context, org, key string) error {
	return db.WithOrg(ctx, org, func(tx *Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM idempotency_keys WHERE org_id = $1 AND key = $2 AND status = 0`, org, key)
		return err
	})
}
