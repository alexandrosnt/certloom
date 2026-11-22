package store

import (
	"context"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// TrustBundle is a named, versioned set of trust anchors (ADR-0030).
type TrustBundle struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	TeamID         *string   `json:"team_id,omitempty"`
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
}

// TrustBundleVersion is one immutable anchor set.
type TrustBundleVersion struct {
	BundleID    string    `json:"bundle_id"`
	Version     int       `json:"version"`
	Anchors     []string  `json:"anchors"` // certificate sha256, sorted
	Digest      string    `json:"digest"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	ForceReason string    `json:"force_reason,omitempty"`
}

// TrustAssignment binds a bundle to one agent trust store.
type TrustAssignment struct {
	ID               string     `json:"id"`
	BundleID         string     `json:"bundle_id"`
	BundleName       string     `json:"bundle"`
	AgentID          string     `json:"agent_id"`
	AgentName        string     `json:"agent"`
	Store            string     `json:"store"`
	CurrentVersion   int        `json:"current_version"`
	ConfirmedVersion int        `json:"confirmed_version"`
	ConfirmedAt      *time.Time `json:"confirmed_at,omitempty"`
	SentVersion      int        `json:"sent_version"`
	SentAt           *time.Time `json:"sent_at,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
}

const trustBundleCols = `id, name, team_id, current_version, created_at`

func scanTrustBundle(r pgx.Row) (*TrustBundle, error) {
	b := &TrustBundle{}
	if err := r.Scan(&b.ID, &b.Name, &b.TeamID, &b.CurrentVersion, &b.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return b, nil
}

// GetTrustBundle finds a bundle by id or name; forUpdate locks it.
func (tx *Tx) GetTrustBundle(ctx context.Context, ref string, forUpdate bool) (*TrustBundle, error) {
	q := `SELECT ` + trustBundleCols + ` FROM trust_bundles WHERE id = $1 OR name = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanTrustBundle(tx.QueryRow(ctx, q, ref))
}

// CreateTrustBundle inserts a bundle without versions.
func (tx *Tx) CreateTrustBundle(ctx context.Context, name string, teamID *string) (*TrustBundle, error) {
	return scanTrustBundle(tx.QueryRow(ctx, `INSERT INTO trust_bundles (id, org_id, name, team_id) VALUES ($1,$2,$3,$4)
		RETURNING `+trustBundleCols, ids.New("tb"), tx.OrgID, name, teamID))
}

// ListTrustBundles returns all bundles by name.
func (tx *Tx) ListTrustBundles(ctx context.Context) ([]*TrustBundle, error) {
	rows, err := tx.Query(ctx, `SELECT `+trustBundleCols+` FROM trust_bundles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TrustBundle{}
	for rows.Next() {
		b, err := scanTrustBundle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteTrustBundle removes a bundle with its versions and assignments.
func (tx *Tx) DeleteTrustBundle(ctx context.Context, id string) error {
	return deleted(tx.Exec(ctx, `DELETE FROM trust_bundles WHERE id = $1`, id))
}

// AddTrustBundleVersion stores the next version and makes it current.
func (tx *Tx) AddTrustBundleVersion(ctx context.Context, v *TrustBundleVersion) error {
	if _, err := tx.Exec(ctx, `INSERT INTO trust_bundle_versions (org_id, bundle_id, version, anchors, digest, created_by, force_reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tx.OrgID, v.BundleID, v.Version, v.Anchors, v.Digest, v.CreatedBy, v.ForceReason); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE trust_bundles SET current_version = $2 WHERE id = $1`, v.BundleID, v.Version)
	return err
}

// GetTrustBundleVersion returns one version.
func (tx *Tx) GetTrustBundleVersion(ctx context.Context, bundleID string, version int) (*TrustBundleVersion, error) {
	v := &TrustBundleVersion{}
	err := tx.QueryRow(ctx, `SELECT bundle_id, version, anchors, digest, created_by, created_at, force_reason
		FROM trust_bundle_versions WHERE bundle_id = $1 AND version = $2`, bundleID, version).
		Scan(&v.BundleID, &v.Version, &v.Anchors, &v.Digest, &v.CreatedBy, &v.CreatedAt, &v.ForceReason)
	return v, notFound(err)
}

const trustAssignmentQuery = `SELECT a.id, a.bundle_id, b.name, a.agent_id, g.name, a.store, b.current_version, a.confirmed_version,
	a.confirmed_at, a.sent_version, a.sent_at, a.last_error
	FROM trust_assignments a JOIN trust_bundles b ON b.id = a.bundle_id JOIN agents g ON g.id = a.agent_id`

func (tx *Tx) queryTrustAssignments(ctx context.Context, where string, args ...any) ([]*TrustAssignment, error) {
	rows, err := tx.Query(ctx, trustAssignmentQuery+` `+where+` ORDER BY b.name, g.name, a.store`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TrustAssignment{}
	for rows.Next() {
		a := &TrustAssignment{}
		if err := rows.Scan(&a.ID, &a.BundleID, &a.BundleName, &a.AgentID, &a.AgentName, &a.Store, &a.CurrentVersion, &a.ConfirmedVersion,
			&a.ConfirmedAt, &a.SentVersion, &a.SentAt, &a.LastError); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TrustAssignments lists the stores of one bundle, or all when bundleID is empty.
func (tx *Tx) TrustAssignments(ctx context.Context, bundleID string) ([]*TrustAssignment, error) {
	if bundleID == "" {
		return tx.queryTrustAssignments(ctx, "")
	}
	return tx.queryTrustAssignments(ctx, "WHERE a.bundle_id = $1", bundleID)
}

// TrustAssignmentFor returns the assignment of an agent's store.
func (tx *Tx) TrustAssignmentFor(ctx context.Context, agentID, storeName string) (*TrustAssignment, error) {
	as, err := tx.queryTrustAssignments(ctx, "WHERE a.agent_id = $1 AND a.store = $2", agentID, storeName)
	if err != nil {
		return nil, err
	}
	if len(as) == 0 {
		return nil, ErrNotFound
	}
	return as[0], nil
}

// TrustAssignmentsDue returns assignments whose current version was never
// sent, or was sent before resendAfter without being confirmed.
func (tx *Tx) TrustAssignmentsDue(ctx context.Context, resendBefore time.Time) ([]*TrustAssignment, error) {
	return tx.queryTrustAssignments(ctx, `WHERE b.current_version > 0 AND a.confirmed_version <> b.current_version
		AND (a.sent_version <> b.current_version OR a.sent_at < $1)`, resendBefore)
}

// AddTrustAssignment binds a store to a bundle.
func (tx *Tx) AddTrustAssignment(ctx context.Context, bundleID, agentID, storeName string) error {
	_, err := tx.Exec(ctx, `INSERT INTO trust_assignments (id, org_id, bundle_id, agent_id, store) VALUES ($1,$2,$3,$4,$5)`,
		ids.New("tba"), tx.OrgID, bundleID, agentID, storeName)
	return conflict(err)
}

// DeleteTrustAssignment unbinds a store.
func (tx *Tx) DeleteTrustAssignment(ctx context.Context, id string) error {
	return deleted(tx.Exec(ctx, `DELETE FROM trust_assignments WHERE id = $1`, id))
}

// MarkTrustSent records that a version was queued for a store.
func (tx *Tx) MarkTrustSent(ctx context.Context, id string, version int, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE trust_assignments SET sent_version = $2, sent_at = $3 WHERE id = $1`, id, version, at)
	return err
}

// ConfirmTrust records the agent's answer to trust.apply.
func (tx *Tx) ConfirmTrust(ctx context.Context, agentID, storeName string, version int, errMsg string, at time.Time) error {
	if errMsg != "" {
		_, err := tx.Exec(ctx, `UPDATE trust_assignments SET last_error = $3 WHERE agent_id = $1 AND store = $2`, agentID, storeName, errMsg)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE trust_assignments SET confirmed_version = GREATEST(confirmed_version, $3), confirmed_at = $4, last_error = ''
		WHERE agent_id = $1 AND store = $2`, agentID, storeName, version, at)
	return err
}

// PrivateAnchors returns the DER of every anchor in a current bundle version.
func (tx *Tx) PrivateAnchors(ctx context.Context) ([][]byte, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT c.der FROM trust_bundles b
		JOIN trust_bundle_versions v ON v.bundle_id = b.id AND v.version = b.current_version
		JOIN certificates c ON c.sha256 = ANY(v.anchors)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var der []byte
		if err := rows.Scan(&der); err != nil {
			return nil, err
		}
		out = append(out, der)
	}
	return out, rows.Err()
}

// AnchorsInBundles returns every anchor hash of any current bundle version.
func (tx *Tx) AnchorsInBundles(ctx context.Context) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT unnest(v.anchors) FROM trust_bundles b
		JOIN trust_bundle_versions v ON v.bundle_id = b.id AND v.version = b.current_version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out[s] = true
	}
	return out, rows.Err()
}
