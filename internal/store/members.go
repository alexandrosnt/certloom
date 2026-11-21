package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/jackc/pgx/v5"
)

// Member grants a verified OIDC identity a role in an org.
//
// The members table has no RLS: sign-in must look up memberships before the
// org is known. Every org-scoped method below therefore filters on tx.OrgID
// explicitly; keep it that way.
type Member struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Issuer    string    `json:"issuer"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

const memberCols = `id, org_id, issuer, email, role, created_by, created_at`

func scanMember(r pgx.CollectableRow) (Member, error) {
	var m Member
	err := r.Scan(&m.ID, &m.OrgID, &m.Issuer, &m.Email, &m.Role, &m.CreatedBy, &m.CreatedAt)
	return m, err
}

// NormalizeEmail lowercases and trims an email for matching.
func NormalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// MembershipsFor returns every org membership of a verified identity (system query).
func (db *DB) MembershipsFor(ctx context.Context, issuer, email string) ([]Member, error) {
	rows, err := db.Pool.Query(ctx, `SELECT `+memberCols+` FROM members WHERE issuer = $1 AND email = $2 ORDER BY created_at`,
		issuer, NormalizeEmail(email))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanMember)
}

// CreateMember adds a member to the tx's org.
func (tx *Tx) CreateMember(ctx context.Context, issuer, email, role, createdBy string) (*Member, error) {
	if !ValidRole(role) {
		return nil, errors.New("invalid role")
	}
	m := &Member{ID: ids.New("mbr"), OrgID: tx.OrgID, Issuer: issuer, Email: NormalizeEmail(email), Role: role, CreatedBy: createdBy}
	err := tx.QueryRow(ctx, `INSERT INTO members (id, org_id, issuer, email, role, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
		m.ID, m.OrgID, m.Issuer, m.Email, role, createdBy).Scan(&m.CreatedAt)
	return m, conflict(err)
}

// ListMembers lists the tx's org members.
func (tx *Tx) ListMembers(ctx context.Context) ([]Member, error) {
	rows, err := tx.Query(ctx, `SELECT `+memberCols+` FROM members WHERE org_id = $1 ORDER BY email`, tx.OrgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanMember)
}

// DeleteMember removes a member (and, by cascade, their sessions).
func (tx *Tx) DeleteMember(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM members WHERE id = $1 AND org_id = $2`, id, tx.OrgID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Session token format: "certlooms_<org id>.<random>" (org id lets lookup run under RLS).
const sessionPrefix = "certlooms_"

// ParseSessionOrg extracts the org id from a session token.
func ParseSessionOrg(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, sessionPrefix)
	if !ok {
		return "", false
	}
	org, _, ok := strings.Cut(rest, ".")
	if !ok || !ids.HasPrefix(org, ids.Org) {
		return "", false
	}
	return org, true
}

// CreateSession issues a session for a member of the tx's org.
func (tx *Tx) CreateSession(ctx context.Context, memberID string, ttl time.Duration) (secret.Value, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return secret.Value{}, err
	}
	plain := sessionPrefix + tx.OrgID + "." + base64.RawURLEncoding.EncodeToString(b)
	_, err := tx.Exec(ctx, `INSERT INTO sessions (id, org_id, member_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		ids.New("ses"), tx.OrgID, memberID, hashToken(plain), time.Now().Add(ttl))
	if err != nil {
		return secret.Value{}, err
	}
	return secret.FromString(plain), nil
}

// AuthenticateSession validates a session and returns the member's current role.
func (tx *Tx) AuthenticateSession(ctx context.Context, plain string) (*Member, error) {
	rows, err := tx.Query(ctx, `SELECT m.id, m.org_id, m.issuer, m.email, m.role, m.created_by, m.created_at
		FROM sessions s JOIN members m ON m.id = s.member_id AND m.org_id = $2
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()`, hashToken(plain), tx.OrgID)
	if err != nil {
		return nil, err
	}
	m, err := pgx.CollectExactlyOneRow(rows, scanMember)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	return &m, err
}

// RevokeSession ends a session (logout).
func (tx *Tx) RevokeSession(ctx context.Context, plain string) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hashToken(plain))
	return err
}
