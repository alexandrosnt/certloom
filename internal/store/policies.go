package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/jackc/pgx/v5"
)

// PolicyVersion is a stored policy.
type PolicyVersion struct {
	Version   int              `json:"version"` // 0 = built-in defaults
	Document  *policy.Document `json:"document"`
	Source    string           `json:"source,omitempty"`
	CreatedBy string           `json:"created_by,omitempty"`
	CreatedAt *time.Time       `json:"created_at,omitempty"`
}

// ActivePolicy returns the latest policy version, or the defaults (version 0).
func (tx *Tx) ActivePolicy(ctx context.Context) (*PolicyVersion, error) {
	pv := &PolicyVersion{}
	var doc []byte
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT version, document, source, created_by, created_at FROM policies
		WHERE org_id = $1 ORDER BY version DESC LIMIT 1`, tx.OrgID).Scan(&pv.Version, &doc, &pv.Source, &pv.CreatedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return &PolicyVersion{Document: policy.Default()}, nil
	}
	if err != nil {
		return nil, err
	}
	pv.CreatedAt = &at
	// Re-parse (not just unmarshal) so stored documents are re-validated and defaulted.
	d, err := policy.Parse(doc)
	if err != nil {
		return nil, err
	}
	pv.Document = d
	return pv, nil
}

// InsertPolicy stores a new version and returns its number.
func (tx *Tx) InsertPolicy(ctx context.Context, d *policy.Document, source, actor string) (int, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return 0, err
	}
	var v int
	err = tx.QueryRow(ctx, `INSERT INTO policies (org_id, version, document, source, created_by)
		SELECT $1, COALESCE(max(version),0)+1, $2, $3, $4 FROM policies WHERE org_id = $1 RETURNING version`,
		tx.OrgID, b, source, actor).Scan(&v)
	return v, conflict(err)
}
