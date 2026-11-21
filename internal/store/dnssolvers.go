package store

import (
	"context"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// DNSSolver is a DNS-01 solver defined in the control plane (ADR-0018).
// The secret ciphertext is never part of the JSON form.
type DNSSolver struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Provider        string         `json:"provider"` // rfc2136, cloudflare, plugin
	Plugin          string         `json:"plugin,omitempty"`
	PluginSHA256    string         `json:"plugin_sha256,omitempty"`
	Zones           []string       `json:"zones"`
	Config          map[string]any `json:"config"`
	Credential      string         `json:"credential"` // stored or ambient
	HasSecret       bool           `json:"has_secret"`
	SecretUpdatedAt *time.Time     `json:"secret_updated_at,omitempty"`
	Agents          []string       `json:"agents"`
	Version         int64          `json:"version"`
	CreatedAt       time.Time      `json:"created_at"`

	SecretCiphertext []byte `json:"-"`
}

const dnsSolverCols = `s.id, s.name, s.provider, s.plugin, s.plugin_sha256, s.zones, s.config, s.credential,
	s.secret_ciphertext, s.secret_updated_at, s.version, s.created_at,
	COALESCE((SELECT array_agg(agent_id ORDER BY agent_id) FROM dns_solver_agents a WHERE a.solver_id = s.id), '{}')`

func scanDNSSolver(r pgx.Row) (*DNSSolver, error) {
	s := &DNSSolver{}
	err := r.Scan(&s.ID, &s.Name, &s.Provider, &s.Plugin, &s.PluginSHA256, &s.Zones, &s.Config, &s.Credential,
		&s.SecretCiphertext, &s.SecretUpdatedAt, &s.Version, &s.CreatedAt, &s.Agents)
	s.HasSecret = len(s.SecretCiphertext) > 0
	return s, err
}

// NewDNSSolverID returns an id for a solver about to be created; the secret
// is encrypted with the id as associated data before the row exists.
func NewDNSSolverID() string { return ids.New("dns") }

// CreateDNSSolver inserts a solver whose ID is already set.
func (tx *Tx) CreateDNSSolver(ctx context.Context, s *DNSSolver, createdBy string) error {
	var updated *time.Time
	if len(s.SecretCiphertext) > 0 {
		now := time.Now()
		updated = &now
	}
	if s.Config == nil {
		s.Config = map[string]any{}
	}
	return conflict(tx.QueryRow(ctx, `INSERT INTO dns_solvers (id, org_id, name, provider, plugin, plugin_sha256, zones, config,
		credential, secret_ciphertext, secret_updated_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING created_at, version`,
		s.ID, tx.OrgID, s.Name, s.Provider, s.Plugin, s.PluginSHA256, s.Zones, s.Config, s.Credential,
		s.SecretCiphertext, updated, createdBy).Scan(&s.CreatedAt, &s.Version))
}

// GetDNSSolver returns a solver by id or name, including its ciphertext.
func (tx *Tx) GetDNSSolver(ctx context.Context, ref string) (*DNSSolver, error) {
	s, err := scanDNSSolver(tx.QueryRow(ctx, `SELECT `+dnsSolverCols+` FROM dns_solvers s WHERE s.id = $1 OR s.name = $1`, ref))
	return s, notFound(err)
}

// ListDNSSolvers lists solvers; agentID limits it to those assigned to one agent.
func (tx *Tx) ListDNSSolvers(ctx context.Context, agentID string) ([]*DNSSolver, error) {
	q := `SELECT ` + dnsSolverCols + ` FROM dns_solvers s`
	args := []any{}
	if agentID != "" {
		q += ` WHERE EXISTS (SELECT 1 FROM dns_solver_agents a WHERE a.solver_id = s.id AND a.agent_id = $1)`
		args = append(args, agentID)
	}
	rows, err := tx.Query(ctx, q+` ORDER BY s.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DNSSolver
	for rows.Next() {
		s, err := scanDNSSolver(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SetDNSSolverSecret replaces a solver's stored secret.
func (tx *Tx) SetDNSSolverSecret(ctx context.Context, id string, ciphertext []byte) error {
	tag, err := tx.Exec(ctx, `UPDATE dns_solvers SET secret_ciphertext = $2, secret_updated_at = now(), version = version + 1
		WHERE id = $1 AND credential = 'stored'`, id, ciphertext)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// AssignDNSSolver makes a solver available to an agent (idempotent).
func (tx *Tx) AssignDNSSolver(ctx context.Context, solverID, agentID string) error {
	_, err := tx.Exec(ctx, `INSERT INTO dns_solver_agents (org_id, solver_id, agent_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		tx.OrgID, solverID, agentID)
	return err
}

// UnassignDNSSolver removes a solver from an agent.
func (tx *Tx) UnassignDNSSolver(ctx context.Context, solverID, agentID string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM dns_solver_agents WHERE solver_id = $1 AND agent_id = $2`, solverID, agentID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteDNSSolver deletes a solver and its assignments.
func (tx *Tx) DeleteDNSSolver(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM dns_solvers WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
