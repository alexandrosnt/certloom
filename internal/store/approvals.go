package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// Approval states.
const (
	ApprovalRequested = "requested"
	ApprovalApproved  = "approved"
	ApprovalDenied    = "denied"
	ApprovalExpired   = "expired"
	ApprovalRevoked   = "revoked"
)

// SpecVersion is the version of the DeploymentSpec encoding. Any change to
// what goes into the spec changes every digest and voids every approval, so
// it must come with a new version and a plan for existing approvals.
//
// Version 2 added the challenge type. HTTP-01 specs are still encoded as
// version 1 (no challenge field), so approvals made before it stay valid.
const SpecVersion = 2

// DeploymentSpec is what an approval covers: everything that decides what
// gets issued, by which CA and where it goes, resolved through references
// (an issuer's directory URL, not just its id) so that editing a referenced
// record also voids the approval. Secrets and operational settings such as
// the maintenance window are not part of it.
type DeploymentSpec struct {
	V       int        `json:"v"`
	Lineage string     `json:"lineage"`
	SANs    []string   `json:"sans"`
	Purpose string     `json:"purpose"` // what the certificate is for
	Key     SpecKey    `json:"key"`
	Issuer  SpecIssuer `json:"issuer"`
	Target  SpecTarget `json:"target"`
	// Challenge is set only for DNS-01 (version 2).
	Challenge string `json:"challenge,omitempty"`
}

// SpecKey describes the key the agent generates.
type SpecKey struct {
	Algorithm string `json:"algorithm"`
}

// SpecIssuer is the effective CA configuration.
type SpecIssuer struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	DirectoryURL string `json:"directory_url"`
	Profile      string `json:"profile"`
}

// SpecTarget is where the certificate is installed. Attributes holds
// connector-specific identity such as a cloud account or cluster id.
type SpecTarget struct {
	Agent      string            `json:"agent"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// PurposeTLSServer is the only purpose so far.
const PurposeTLSServer = "tls-server"

// BuildDeploymentSpec resolves a deployment's spec from the deployment, its
// issuer and its agent (whose last heartbeat reports the target's type).
func BuildDeploymentSpec(d *Deployment, iss *Issuer, a *Agent) DeploymentSpec {
	sans := make([]string, 0, len(d.SANs))
	for _, s := range d.SANs {
		sans = append(sans, strings.ToLower(strings.TrimSuffix(s, ".")))
	}
	slices.Sort(sans)
	tgt := SpecTarget{Agent: a.ID, Name: d.Target}
	for _, t := range a.Capabilities.Targets {
		if t.Name == d.Target {
			tgt.Type = t.Type
			if t.Type == agentproto.TargetIIS {
				// Which site and bindings get the certificate is part of what is approved.
				b := make([]string, 0, len(t.Bindings))
				for _, x := range t.Bindings {
					b = append(b, strings.ToLower(x))
				}
				slices.Sort(b)
				tgt.Attributes = map[string]string{"site": strings.ToLower(t.Site), "bindings": strings.Join(b, ",")}
			}
		}
	}
	spec := DeploymentSpec{V: 1, Lineage: d.LineageID, SANs: slices.Compact(sans), Purpose: PurposeTLSServer,
		Key:    SpecKey{Algorithm: d.KeyAlgorithm},
		Issuer: SpecIssuer{ID: iss.ID, Kind: iss.Kind, DirectoryURL: iss.DirectoryURL, Profile: iss.Profile},
		Target: tgt}
	if d.Challenge == "dns-01" {
		spec.V, spec.Challenge = SpecVersion, d.Challenge
	}
	return spec
}

// SHA256 is the hex digest of the spec's JSON encoding. Struct fields encode
// in declaration order and map keys sorted, so the encoding is stable.
func (s DeploymentSpec) SHA256() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ApprovalCovers reports whether the deployment's approval covers the spec
// with this digest. A deployment from before approvals existed has no digest
// and counts only while approvals are not required.
func (d *Deployment) ApprovalCovers(digest string, required bool) bool {
	if d.Approval != ApprovalApproved {
		return false
	}
	if d.ApprovedSpecSHA256 == nil {
		return !required
	}
	return *d.ApprovedSpecSHA256 == digest
}

// Approval is a request for someone else to approve a spec.
type Approval struct {
	ID           string          `json:"id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	SpecSHA256   string          `json:"spec_sha256"`
	Spec         json.RawMessage `json:"spec"`
	State        string          `json:"state"`
	RequestedBy  string          `json:"requested_by"`
	RequestedAt  time.Time       `json:"requested_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	DecidedBy    *string         `json:"decided_by,omitempty"`
	DecidedAt    *time.Time      `json:"decided_at,omitempty"`
	Reason       string          `json:"reason,omitempty"`
	RevokedBy    *string         `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time      `json:"revoked_at,omitempty"`
	RevokeReason string          `json:"revoke_reason,omitempty"`
}

const approvalCols = `id, resource_type, resource_id, spec_sha256, spec, state, requested_by, requested_at, expires_at, decided_by, decided_at, reason, revoked_by, revoked_at, revoke_reason`

func scanApproval(r pgx.Row) (*Approval, error) {
	a := &Approval{}
	err := r.Scan(&a.ID, &a.ResourceType, &a.ResourceID, &a.SpecSHA256, &a.Spec, &a.State, &a.RequestedBy, &a.RequestedAt,
		&a.ExpiresAt, &a.DecidedBy, &a.DecidedAt, &a.Reason, &a.RevokedBy, &a.RevokedAt, &a.RevokeReason)
	return a, notFound(err)
}

// Spec is something an approval can cover: a stable JSON encoding and its digest.
type Spec interface{ SHA256() string }

// CreateApproval opens a request for a spec. Only one request per resource
// can be open (ErrConflict otherwise).
func (tx *Tx) CreateApproval(ctx context.Context, resourceType, resourceID string, spec Spec, requestedBy string, ttl time.Duration) (*Approval, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	a := &Approval{ID: ids.New("apr"), ResourceType: resourceType, ResourceID: resourceID, SpecSHA256: spec.SHA256(), Spec: b,
		State: ApprovalRequested, RequestedBy: requestedBy}
	err = tx.QueryRow(ctx, `INSERT INTO approvals (id, org_id, resource_type, resource_id, spec_sha256, spec, requested_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now() + $8::interval) RETURNING requested_at, expires_at`,
		a.ID, tx.OrgID, a.ResourceType, a.ResourceID, a.SpecSHA256, a.Spec, requestedBy, ttl).Scan(&a.RequestedAt, &a.ExpiresAt)
	return a, conflict(err)
}

// GetApproval returns an approval, optionally locking it.
func (tx *Tx) GetApproval(ctx context.Context, id string, forUpdate bool) (*Approval, error) {
	q := `SELECT ` + approvalCols + ` FROM approvals WHERE id = $1`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanApproval(tx.QueryRow(ctx, q, id))
}

// ListApprovals lists approvals, newest first; state "" means all.
func (tx *Tx) ListApprovals(ctx context.Context, state string, limit int) ([]*Approval, error) {
	rows, err := tx.Query(ctx, `SELECT `+approvalCols+` FROM approvals WHERE ($1 = '' OR state = $1)
		ORDER BY requested_at DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideApproval records a decision on an open request.
func (tx *Tx) DecideApproval(ctx context.Context, id, state, decidedBy, reason string) error {
	tag, err := tx.Exec(ctx, `UPDATE approvals SET state = $2, decided_by = $3, decided_at = now(), reason = $4
		WHERE id = $1 AND state = 'requested'`, id, state, decidedBy, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// ExpireApprovals closes requests past their expiry and returns their ids.
func (tx *Tx) ExpireApprovals(ctx context.Context) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE approvals SET state = 'expired', decided_at = now(), reason = 'not decided before expiry'
		WHERE state = 'requested' AND expires_at <= now() RETURNING id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetDeploymentApproval records the approval outcome on a deployment.
func (tx *Tx) SetDeploymentApproval(ctx context.Context, id, approval string, specSHA256 *string) error {
	tag, err := tx.Exec(ctx, `UPDATE deployments SET approval = $2, approved_spec_sha256 = COALESCE($3, approved_spec_sha256), version = version + 1
		WHERE id = $1`, id, approval, specSHA256)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RevokeApproval marks the deployment's latest approved request revoked,
// if there is one (deployments from before approvals have none).
func (tx *Tx) RevokeApproval(ctx context.Context, deploymentID, by, reason string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `UPDATE approvals SET state = 'revoked', revoked_by = $2, revoked_at = now(), revoke_reason = $3
		WHERE id = (SELECT id FROM approvals WHERE resource_type = 'deployment' AND resource_id = $1 AND state = 'approved'
		            ORDER BY decided_at DESC LIMIT 1)
		RETURNING id`, deploymentID, by, reason).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}
