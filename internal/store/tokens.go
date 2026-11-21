package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/jackc/pgx/v5"
)

// Roles.
const (
	RoleOwner              = "owner"
	RoleOperator           = "operator"
	RoleViewer             = "viewer"
	RoleAuditor            = "auditor"
	RoleRequester          = "requester"
	RoleApprover           = "approver"
	RoleDeploymentOperator = "deployment_operator"
	RoleIssuerAdmin        = "issuer_admin"
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool {
	switch r {
	case RoleOwner, RoleOperator, RoleViewer, RoleAuditor, RoleRequester, RoleApprover, RoleDeploymentOperator, RoleIssuerAdmin:
		return true
	}
	return false
}

// APIToken is a stored token (never the token value itself).
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Token format: "certloom_<org id>.<43 chars base64url random>". The org id is not
// secret; embedding it lets authentication run inside the org's RLS scope.
const tokenPrefix = "certloom_"

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// ParseTokenOrg extracts the org id from a token without validating it.
func ParseTokenOrg(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return "", false
	}
	org, _, ok := strings.Cut(rest, ".")
	if !ok || !ids.HasPrefix(org, ids.Org) {
		return "", false
	}
	return org, true
}

// CreateToken creates a token and returns its one-time plaintext value.
func (tx *Tx) CreateToken(ctx context.Context, name, role, createdBy string, ttl time.Duration) (*APIToken, secret.Value, error) {
	if !ValidRole(role) {
		return nil, secret.Value{}, errors.New("invalid role")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, secret.Value{}, err
	}
	plain := tokenPrefix + tx.OrgID + "." + base64.RawURLEncoding.EncodeToString(b)
	t := &APIToken{ID: ids.New(ids.Token), Name: name, Role: role, CreatedBy: createdBy}
	if ttl > 0 {
		exp := time.Now().Add(ttl).UTC()
		t.ExpiresAt = &exp
	}
	err := tx.QueryRow(ctx, `INSERT INTO api_tokens (id, org_id, name, token_hash, role, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, t.ID, tx.OrgID, name, hashToken(plain), role, createdBy, t.ExpiresAt).Scan(&t.CreatedAt)
	if err != nil {
		return nil, secret.Value{}, conflict(err)
	}
	return t, secret.FromString(plain), nil
}

// ErrInvalidToken is returned for unknown, expired or revoked tokens.
var ErrInvalidToken = errors.New("invalid or expired token")

// AuthenticateToken validates a token and returns it. Must run in the token's org.
func (tx *Tx) AuthenticateToken(ctx context.Context, plain string) (*APIToken, error) {
	t := &APIToken{}
	err := tx.QueryRow(ctx, `UPDATE api_tokens SET last_used_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		RETURNING id, name, role, created_by, created_at, expires_at, revoked_at, last_used_at`, hashToken(plain)).
		Scan(&t.ID, &t.Name, &t.Role, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	return t, err
}

// ListTokens returns tokens (metadata only).
func (tx *Tx) ListTokens(ctx context.Context) ([]APIToken, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, role, created_by, created_at, expires_at, revoked_at, last_used_at FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIToken, error) {
		var t APIToken
		err := r.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
		return t, err
	})
}

// RevokeToken revokes a token by id.
func (tx *Tx) RevokeToken(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TokenCreatedBy returns who created a token, revoked or not.
func (tx *Tx) TokenCreatedBy(ctx context.Context, id string) (string, error) {
	var by string
	err := tx.QueryRow(ctx, `SELECT created_by FROM api_tokens WHERE id = $1`, id).Scan(&by)
	return by, notFound(err)
}
