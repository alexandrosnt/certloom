package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alexandrosnt/certloom/internal/certtemplate"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// Template is a certificate template at its current version (ADR-0020).
type Template struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     int                    `json:"version"`
	Document    *certtemplate.Document `json:"document"`
	Source      string                 `json:"source"`
	UpdatedBy   string                 `json:"updated_by"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedAt   time.Time              `json:"created_at"`
	Deployments int                    `json:"deployments"`
}

const templateQuery = `SELECT t.id, t.name, t.current_version, v.document, v.source, v.created_by, v.created_at, t.created_at,
	(SELECT count(*) FROM deployments d WHERE d.template_id = t.id)
	FROM templates t JOIN template_versions v ON v.template_id = t.id AND v.version = t.current_version`

func scanTemplate(r pgx.Row) (*Template, error) {
	t := &Template{}
	var doc []byte
	if err := r.Scan(&t.ID, &t.Name, &t.Version, &doc, &t.Source, &t.UpdatedBy, &t.UpdatedAt, &t.CreatedAt, &t.Deployments); err != nil {
		return nil, err
	}
	t.Document = &certtemplate.Document{}
	return t, json.Unmarshal(doc, t.Document)
}

// GetTemplate returns a template by id or name.
func (tx *Tx) GetTemplate(ctx context.Context, ref string) (*Template, error) {
	t, err := scanTemplate(tx.QueryRow(ctx, templateQuery+` WHERE t.id = $1 OR t.name = $1`, ref))
	return t, notFound(err)
}

// ListTemplates lists templates at their current versions.
func (tx *Tx) ListTemplates(ctx context.Context) ([]*Template, error) {
	rows, err := tx.Query(ctx, templateQuery+` ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Template, error) { return scanTemplate(r) })
}

// SaveTemplate stores doc as a new version of the named template, creating
// it if needed, and returns the template id and version.
func (tx *Tx) SaveTemplate(ctx context.Context, doc *certtemplate.Document, source, actor string) (string, int, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", 0, err
	}
	var id string
	var v int
	err = tx.QueryRow(ctx, `INSERT INTO templates (id, org_id, name, current_version) VALUES ($1, $2, $3, 1)
		ON CONFLICT (org_id, name) DO UPDATE SET current_version = templates.current_version + 1
		RETURNING id, current_version`, ids.New("tpl"), tx.OrgID, doc.Metadata.Name).Scan(&id, &v)
	if err != nil {
		return "", 0, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO template_versions (template_id, org_id, version, document, source, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, tx.OrgID, v, b, source, actor)
	return id, v, err
}

// DeleteTemplate removes a template that no deployment uses.
func (tx *Tx) DeleteTemplate(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM templates t WHERE t.id = $1
		AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.template_id = t.id)`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// LockTemplate serializes applies of one template name, including its first.
func (tx *Tx) LockTemplate(ctx context.Context, name string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('template:' || $1 || ':' || $2, 0))`, tx.OrgID, name)
	return err
}

// DeploymentsUsingTemplate lists deployments that follow a template, locked.
func (tx *Tx) DeploymentsUsingTemplate(ctx context.Context, templateID string) ([]*Deployment, error) {
	rows, err := tx.Query(ctx, `SELECT `+deploymentCols+` FROM deployments WHERE template_id = $1 ORDER BY id FOR UPDATE`, templateID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Deployment, error) { return scanDeployment(r) })
}

// SetDeploymentResolved stores the values a deployment takes from its template.
func (tx *Tx) SetDeploymentResolved(ctx context.Context, id, issuerID, challenge, keyAlgorithm string) error {
	tag, err := tx.Exec(ctx, `UPDATE deployments SET issuer_id = $2, challenge = $3, key_algorithm = $4, version = version + 1
		WHERE id = $1`, id, issuerID, challenge, keyAlgorithm)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SupersedeApprovals closes open requests for a resource whose spec changed;
// approving them could no longer succeed.
func (tx *Tx) SupersedeApprovals(ctx context.Context, resourceType, resourceID, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE approvals SET state = 'expired', decided_at = now(), reason = $3
		WHERE resource_type = $1 AND resource_id = $2 AND state = 'requested'`, resourceType, resourceID, reason)
	return err
}
