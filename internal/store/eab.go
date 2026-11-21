package store

import (
	"context"
	"errors"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// EAB modes of an issuer (ADR-0019).
const (
	EABNone      = "none"
	EABReusable  = "reusable"
	EABSingleUse = "single_use"
)

// SetIssuerEAB sets an issuer's EAB mode and its reusable key. ciphertext nil
// keeps the stored HMAC (changing only the mode), unless clear is set.
func (tx *Tx) SetIssuerEAB(ctx context.Context, id, mode, kid string, ciphertext []byte, clear bool) error {
	tag, err := tx.Exec(ctx, `UPDATE issuers SET eab_mode = $2, eab_kid = $3,
		eab_hmac_ciphertext = CASE WHEN $5 THEN NULL WHEN $4::bytea IS NULL THEN eab_hmac_ciphertext ELSE $4 END,
		eab_updated_at = now() WHERE id = $1`, id, mode, kid, ciphertext, clear)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// EABKey is a single-use key in an issuer's pool. The HMAC is never part of
// the JSON form.
type EABKey struct {
	ID        string     `json:"id"`
	IssuerID  string     `json:"issuer_id"`
	KID       string     `json:"kid"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	State     string     `json:"state"` // available, claimed, consumed, failed
	AgentID   *string    `json:"agent_id,omitempty"`
	ClaimedAt *time.Time `json:"claimed_at,omitempty"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`

	HMACCiphertext []byte `json:"-"`
}

const eabKeyCols = `id, issuer_id, kid, expires_at, state, agent_id, claimed_at, done_at, created_at, hmac_ciphertext`

func scanEABKey(r pgx.Row) (*EABKey, error) {
	k := &EABKey{}
	err := r.Scan(&k.ID, &k.IssuerID, &k.KID, &k.ExpiresAt, &k.State, &k.AgentID, &k.ClaimedAt, &k.DoneAt, &k.CreatedAt, &k.HMACCiphertext)
	return k, err
}

// NewEABKeyID returns an id for a key about to be added; the HMAC is
// encrypted with the id as associated data before the row exists.
func NewEABKeyID() string { return ids.New("eab") }

// AddEABKey inserts a key whose ID is already set.
func (tx *Tx) AddEABKey(ctx context.Context, k *EABKey, createdBy string) error {
	k.State = "available"
	return conflict(tx.QueryRow(ctx, `INSERT INTO eab_keys (id, org_id, issuer_id, kid, hmac_ciphertext, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, k.ID, tx.OrgID, k.IssuerID, k.KID, k.HMACCiphertext, k.ExpiresAt, createdBy).
		Scan(&k.CreatedAt))
}

// ListEABKeys lists an issuer's pool, newest first.
func (tx *Tx) ListEABKeys(ctx context.Context, issuerID string) ([]*EABKey, error) {
	rows, err := tx.Query(ctx, `SELECT `+eabKeyCols+` FROM eab_keys WHERE issuer_id = $1 ORDER BY created_at DESC, id`, issuerID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*EABKey, error) { return scanEABKey(r) })
}

// DeleteEABKey removes a key that no agent holds (available or failed).
func (tx *Tx) DeleteEABKey(ctx context.Context, issuerID, ref string) (*EABKey, error) {
	k, err := scanEABKey(tx.QueryRow(ctx, `DELETE FROM eab_keys WHERE issuer_id = $1 AND (id = $2 OR kid = $2)
		AND state IN ('available','failed') RETURNING `+eabKeyCols, issuerID, ref))
	return k, notFound(err)
}

// ClaimEABKey returns the key an agent already holds for an issuer, or claims
// the oldest available one that is still valid at notBefore. It returns nil
// when the pool has none. SKIP LOCKED keeps concurrent claims apart.
func (tx *Tx) ClaimEABKey(ctx context.Context, issuerID, agentID string, notBefore time.Time) (*EABKey, error) {
	k, err := scanEABKey(tx.QueryRow(ctx, `SELECT `+eabKeyCols+` FROM eab_keys
		WHERE issuer_id = $1 AND agent_id = $2 AND state = 'claimed'`, issuerID, agentID))
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	k, err = scanEABKey(tx.QueryRow(ctx, `UPDATE eab_keys SET state = 'claimed', agent_id = $2, claimed_at = now()
		WHERE id = (SELECT id FROM eab_keys WHERE issuer_id = $1 AND state = 'available'
			AND (expires_at IS NULL OR expires_at > $3) ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+eabKeyCols, issuerID, agentID, notBefore))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// FinishEABClaim moves an agent's claimed key for an issuer to state
// (consumed or failed). It returns nil when the agent held no claim.
func (tx *Tx) FinishEABClaim(ctx context.Context, issuerID, agentID, state string) (*EABKey, error) {
	k, err := scanEABKey(tx.QueryRow(ctx, `UPDATE eab_keys SET state = $3, done_at = now()
		WHERE issuer_id = $1 AND agent_id = $2 AND state = 'claimed' RETURNING `+eabKeyCols, issuerID, agentID, state))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// EABPool summarises an issuer's single-use pool for the pool findings.
type EABPool struct {
	Available int
	// Waiting are agents with a deployment on the issuer that have no account
	// yet, no claimed key and no host-local EAB.
	Waiting int
	// ExpiringClaims are claimed keys expiring before the given time.
	ExpiringClaims []*EABKey
}

// EABPoolStatus reads the pool state of a single-use issuer. Agent details
// come from heartbeats, so they are filtered by the caller-supplied needsKey.
func (tx *Tx) EABPoolStatus(ctx context.Context, iss *Issuer, now, soon time.Time, needsKey func(*Agent) bool) (*EABPool, error) {
	p := &EABPool{}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM eab_keys WHERE issuer_id = $1 AND state = 'available'
		AND (expires_at IS NULL OR expires_at > $2)`, iss.ID, now).Scan(&p.Available); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT d.agent_id FROM deployments d WHERE d.issuer_id = $1 AND d.enabled
		AND NOT EXISTS (SELECT 1 FROM eab_keys k WHERE k.issuer_id = $1 AND k.agent_id = d.agent_id AND k.state IN ('claimed','consumed'))`, iss.ID)
	if err != nil {
		return nil, err
	}
	agentIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, id := range agentIDs {
		a, err := tx.GetAgent(ctx, id)
		if err != nil {
			return nil, err
		}
		if needsKey(a) {
			p.Waiting++
		}
	}
	rows, err = tx.Query(ctx, `SELECT `+eabKeyCols+` FROM eab_keys WHERE issuer_id = $1 AND state = 'claimed'
		AND expires_at IS NOT NULL AND expires_at < $2 ORDER BY expires_at`, iss.ID, soon)
	if err != nil {
		return nil, err
	}
	p.ExpiringClaims, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (*EABKey, error) { return scanEABKey(r) })
	return p, err
}

// EABKeyConsumed reports whether an agent has used up a single-use key of
// the issuer, i.e. registered its account, even before its next heartbeat.
func (tx *Tx) EABKeyConsumed(ctx context.Context, issuerID, agentID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM eab_keys WHERE issuer_id = $1 AND agent_id = $2 AND state = 'consumed')`,
		issuerID, agentID).Scan(&ok)
	return ok, err
}
