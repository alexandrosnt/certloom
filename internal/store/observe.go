package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SaveAgentInventory replaces the agent's last reported inventory.
func (tx *Tx) SaveAgentInventory(ctx context.Context, agentID string, data any, at time.Time) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_inventories (agent_id, org_id, data, reported_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (agent_id) DO UPDATE SET data = EXCLUDED.data, reported_at = EXCLUDED.reported_at`, agentID, tx.OrgID, b, at)
	return err
}

// AgentInventory returns the last inventory of an agent; nil if none yet.
func (tx *Tx) AgentInventory(ctx context.Context, agentID string) (json.RawMessage, *time.Time, error) {
	var data json.RawMessage
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT data, reported_at FROM agent_inventories WHERE agent_id = $1`, agentID).Scan(&data, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return data, &at, nil
}

// OpenFindingSubjects lists subjects of a type with open findings whose id
// starts with prefix.
func (tx *Tx) OpenFindingSubjects(ctx context.Context, subjectType, prefix string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT subject_id FROM findings
		WHERE subject_type = $1 AND resolved_at IS NULL AND starts_with(subject_id, $2)`, subjectType, prefix)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// AgentsDueInventory lists active, recently seen agents that asked for a
// periodic inventory and have not been sent one within their interval.
func (tx *Tx) AgentsDueInventory(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM agents
		WHERE state = 'active'
		  AND last_heartbeat > $1::timestamptz - interval '10 minutes'
		  AND COALESCE((capabilities->>'inventory_seconds')::int, 0) > 0
		  AND (inventory_requested_at IS NULL
		       OR inventory_requested_at < $1::timestamptz - make_interval(secs => (capabilities->>'inventory_seconds')::int))
		ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// MarkInventoryRequested records that an inventory task was queued.
func (tx *Tx) MarkInventoryRequested(ctx context.Context, agentID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE agents SET inventory_requested_at = $2 WHERE id = $1`, agentID, at)
	return err
}
