package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrConflict signals a uniqueness violation.
var ErrConflict = errors.New("already exists")

// ErrInUse signals that a row cannot be deleted because others reference it.
var ErrInUse = errors.New("in use")

func conflict(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	return err
}

// deleted maps the result of a DELETE: foreign-key violations become
// ErrInUse naming the referencing table, and no rows become ErrNotFound.
func deleted(tag pgconn.CommandTag, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		return fmt.Errorf("%w: still referenced by %s", ErrInUse, pe.TableName)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Organization is a tenant.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateOrg inserts an organization (system operation; no org scope needed).
func (db *DB) CreateOrg(ctx context.Context, name string) (*Organization, error) {
	o := &Organization{ID: ids.New(ids.Org), Name: name}
	err := db.Pool.QueryRow(ctx, `INSERT INTO organizations (id, name) VALUES ($1,$2) RETURNING created_at`, o.ID, name).Scan(&o.CreatedAt)
	if err != nil {
		return nil, conflict(err)
	}
	return o, nil
}

// OrgByName looks up an organization.
func (db *DB) OrgByName(ctx context.Context, name string) (*Organization, error) {
	o := &Organization{}
	err := db.Pool.QueryRow(ctx, `SELECT id, name, created_at FROM organizations WHERE name = $1`, name).Scan(&o.ID, &o.Name, &o.CreatedAt)
	return o, notFound(err)
}

// Team is an ownership boundary.
type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Contact   string    `json:"contact,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTeam inserts a team.
func (tx *Tx) CreateTeam(ctx context.Context, name, contact string) (*Team, error) {
	t := &Team{ID: ids.New(ids.Team), Name: name, Contact: contact}
	err := tx.QueryRow(ctx, `INSERT INTO teams (id, org_id, name, contact) VALUES ($1,$2,$3,$4) RETURNING created_at`,
		t.ID, tx.OrgID, name, contact).Scan(&t.CreatedAt)
	return t, conflict(err)
}

// ListTeams returns all teams.
func (tx *Tx) ListTeams(ctx context.Context) ([]Team, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, contact, created_at FROM teams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Team, error) {
		var t Team
		err := r.Scan(&t.ID, &t.Name, &t.Contact, &t.CreatedAt)
		return t, err
	})
}

// TeamByRef resolves a team by id or name.
func (tx *Tx) TeamByRef(ctx context.Context, ref string) (*Team, error) {
	t := &Team{}
	err := tx.QueryRow(ctx, `SELECT id, name, contact, created_at FROM teams WHERE id = $1 OR name = $1`, ref).
		Scan(&t.ID, &t.Name, &t.Contact, &t.CreatedAt)
	return t, notFound(err)
}

// UpdateTeam changes a team's name and contact.
func (tx *Tx) UpdateTeam(ctx context.Context, t *Team) error {
	tag, err := tx.Exec(ctx, `UPDATE teams SET name = $2, contact = $3 WHERE id = $1`, t.ID, t.Name, t.Contact)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return conflict(err)
}

// DeleteTeam removes a team that no lineage or endpoint references.
func (tx *Tx) DeleteTeam(ctx context.Context, id string) error {
	return deleted(tx.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id))
}

// CertificateRow is a stored certificate plus inventory context.
type CertificateRow struct {
	*certparse.Certificate
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
}

// UpsertCertificate stores c if new. It returns true if the row was inserted.
func (tx *Tx) UpsertCertificate(ctx context.Context, c *certparse.Certificate, source string) (bool, error) {
	meta, err := json.Marshal(c)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO certificates
		(org_id, sha256, der, serial, subject, issuer, common_name, ski, aki, dns_names, ip_addresses,
		 not_before, not_after, key_algorithm, key_bits, is_ca, self_signed, metadata, source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (org_id, sha256) DO NOTHING`,
		tx.OrgID, c.SHA256, c.DER, c.Serial, c.Subject, c.Issuer, c.CommonName, c.SubjectKeyID, c.AuthorityKeyID,
		nonNilS(c.DNSNames), nonNilS(c.IPAddresses), c.NotBefore, c.NotAfter, c.KeyAlgorithm, c.KeyBits, c.IsCA, c.SelfSigned, meta, source)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func scanCert(r pgx.Row) (*CertificateRow, error) {
	var der []byte
	var src string
	var first time.Time
	if err := r.Scan(&der, &src, &first); err != nil {
		return nil, notFound(err)
	}
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pc, err := certparse.FromX509(x)
	if err != nil {
		return nil, err
	}
	return &CertificateRow{Certificate: pc, Source: src, FirstSeen: first}, nil
}

// GetCertificate returns a certificate by full SHA-256 or a unique prefix (>= 8 hex chars).
func (tx *Tx) GetCertificate(ctx context.Context, fp string) (*CertificateRow, error) {
	if len(fp) < 8 {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT der, source, first_seen FROM certificates WHERE sha256 LIKE $1 || '%' LIMIT 2`, fp)
	if err != nil {
		return nil, err
	}
	var out []*CertificateRow
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(out) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return out[0], nil
	}
	return nil, errors.New("fingerprint prefix is ambiguous; use more characters")
}

// CertFilter narrows ListCertificates.
type CertFilter struct {
	Search        string    // substring of subject/common name/SAN
	ExpiresBefore time.Time // zero = no filter
	IncludeCA     bool
	AfterNotAfter time.Time // cursor: (not_after, sha256)
	AfterSHA256   string
	Limit         int
}

// ListCertificates returns certificates ordered by expiry (soonest first).
func (tx *Tx) ListCertificates(ctx context.Context, f CertFilter) ([]*CertificateRow, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q := `SELECT der, source, first_seen FROM certificates WHERE true`
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		q += " AND " + replaceN(cond, len(args))
	}
	if !f.IncludeCA {
		q += " AND NOT is_ca"
	}
	if f.Search != "" {
		add(`(common_name ILIKE '%' || $N || '%' OR subject ILIKE '%' || $N || '%' OR EXISTS (SELECT 1 FROM unnest(dns_names) d WHERE d ILIKE '%' || $N || '%'))`, f.Search)
	}
	if !f.ExpiresBefore.IsZero() {
		add(`not_after < $N`, f.ExpiresBefore)
	}
	if f.AfterSHA256 != "" {
		args = append(args, f.AfterNotAfter, f.AfterSHA256)
		q += " AND (not_after, sha256) > ($" + itoa(len(args)-1) + ", $" + itoa(len(args)) + ")"
	}
	args = append(args, f.Limit)
	q += " ORDER BY not_after, sha256 LIMIT $" + itoa(len(args))
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CertificateRow
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// KnownIntermediates returns non-root CA certificates held in the inventory,
// used to distinguish "incomplete chain" from "untrusted" (certparse.Verify).
func (tx *Tx) KnownIntermediates(ctx context.Context) ([]*x509.Certificate, error) {
	rows, err := tx.Query(ctx, `SELECT der FROM certificates WHERE is_ca AND NOT self_signed AND not_after > now() LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*x509.Certificate
	for rows.Next() {
		var der []byte
		if err := rows.Scan(&der); err != nil {
			return nil, err
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// Lineage is the logical slot successive certificates fill.
type Lineage struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	TeamID          *string   `json:"team_id,omitempty"`
	CurrentSHA256   *string   `json:"current_sha256,omitempty"`
	ManagementLevel string    `json:"management_level"`
	CreatedAt       time.Time `json:"created_at"`
	// Version increments on every change; exposed as the HTTP ETag.
	Version int64 `json:"version"`
}

// CreateLineage inserts a lineage, optionally with a current certificate.
func (tx *Tx) CreateLineage(ctx context.Context, name string, teamID, current *string) (*Lineage, error) {
	l := &Lineage{ID: ids.New(ids.Lineage), Name: name, TeamID: teamID, CurrentSHA256: current, ManagementLevel: "monitored", Version: 1}
	if teamID != nil {
		l.ManagementLevel = "owned"
	}
	err := tx.QueryRow(ctx, `INSERT INTO lineages (id, org_id, name, team_id, current_sha256, management_level)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`, l.ID, tx.OrgID, name, teamID, current, l.ManagementLevel).Scan(&l.CreatedAt)
	if err != nil {
		return nil, conflict(err)
	}
	if current != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO lineage_members (org_id, lineage_id, sha256, reason) VALUES ($1,$2,$3,'initial')`,
			tx.OrgID, l.ID, *current); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LineageByRef resolves a lineage by id or name.
func (tx *Tx) LineageByRef(ctx context.Context, ref string) (*Lineage, error) {
	l := &Lineage{}
	err := tx.QueryRow(ctx, `SELECT id, name, team_id, current_sha256, management_level, created_at, version
		FROM lineages WHERE id = $1 OR name = $1`, ref).Scan(&l.ID, &l.Name, &l.TeamID, &l.CurrentSHA256, &l.ManagementLevel, &l.CreatedAt, &l.Version)
	return l, notFound(err)
}

// versioned runs an UPDATE whose WHERE clause ends with "AND ($N::bigint IS NULL
// OR version = $N)" and maps "no row" to ErrNotFound or ErrPrecondition.
func (tx *Tx) versioned(ctx context.Context, table, id string, sql string, args ...any) error {
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil || tag.RowsAffected() > 0 {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrPrecondition
	}
	return ErrNotFound
}

// SetLineageCurrent records a replacement certificate for the lineage.
func (tx *Tx) SetLineageCurrent(ctx context.Context, lineageID, sha string, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE lineages SET current_sha256 = $2, version = version + 1 WHERE id = $1`, lineageID, sha); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO lineage_members (org_id, lineage_id, sha256, reason) VALUES ($1,$2,$3,$4)
		ON CONFLICT DO NOTHING`, tx.OrgID, lineageID, sha, reason)
	return err
}

// AssignLineageTeam sets the owning team and raises the management level to "owned".
// ifVersion, if non-nil, must equal the current version (If-Match).
func (tx *Tx) AssignLineageTeam(ctx context.Context, lineageID, teamID string, ifVersion *int64) error {
	return tx.versioned(ctx, "lineages", lineageID, `UPDATE lineages SET team_id = $2, version = version + 1,
		management_level = CASE WHEN management_level IN ('discovered','monitored') THEN 'owned' ELSE management_level END
		WHERE id = $1 AND ($3::bigint IS NULL OR version = $3)`, lineageID, teamID, ifVersion)
}

// ListLineages returns all lineages.
func (tx *Tx) ListLineages(ctx context.Context) ([]Lineage, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, team_id, current_sha256, management_level, created_at, version FROM lineages ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Lineage, error) {
		var l Lineage
		err := r.Scan(&l.ID, &l.Name, &l.TeamID, &l.CurrentSHA256, &l.ManagementLevel, &l.CreatedAt, &l.Version)
		return l, err
	})
}
