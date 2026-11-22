package store

import (
	"bytes"
	"context"
	"crypto/x509"
	"time"

	"github.com/alexandrosnt/certloom/internal/cagraph"
)

// Bounds for one link step; a subject with more CA copies than this is
// not a real hierarchy.
const (
	maxIssuerCandidates = 64
	maxRelinkChildren   = 10000
)

// linkCertificate records the authority key of a stored CA certificate and
// the authority that signed c, for rows stored before the CA inventory.
func (tx *Tx) linkCertificate(ctx context.Context, sha string, c *x509.Certificate) error {
	issuer, err := tx.findIssuer(ctx, c)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE certificates SET ca_key = $2, issuer_ca_key = $3, issuer_link_pending = false WHERE sha256 = $1`,
		sha, caKeyOf(c), issuer); err != nil {
		return err
	}
	return tx.linkChildren(ctx, sha, c)
}

// linkInserted links a row UpsertCertificate just inserted with its ca_key.
func (tx *Tx) linkInserted(ctx context.Context, sha string, c *x509.Certificate) error {
	issuer, err := tx.findIssuer(ctx, c)
	if err != nil {
		return err
	}
	if issuer != nil {
		if _, err := tx.Exec(ctx, `UPDATE certificates SET issuer_ca_key = $2 WHERE sha256 = $1`, sha, *issuer); err != nil {
			return err
		}
	}
	return tx.linkChildren(ctx, sha, c)
}

func caKeyOf(c *x509.Certificate) *string {
	if !c.IsCA {
		return nil
	}
	k := cagraph.Key(c)
	return &k
}

// linkChildren links the certificates that were waiting for CA c.
func (tx *Tx) linkChildren(ctx context.Context, sha string, c *x509.Certificate) error {
	if !c.IsCA {
		return nil
	}
	delete(tx.caCandidates, c.Subject.String())
	rows, err := tx.Query(ctx, `SELECT sha256, der FROM certificates WHERE issuer_ca_key IS NULL AND issuer = $1 AND sha256 <> $2 LIMIT $3`,
		c.Subject.String(), sha, maxRelinkChildren)
	if err != nil {
		return err
	}
	var children []string
	for rows.Next() {
		var s string
		var der []byte
		if err := rows.Scan(&s, &der); err != nil {
			rows.Close()
			return err
		}
		if child, err := x509.ParseCertificate(der); err == nil && signedBy(child, c) {
			children = append(children, s)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(children) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `UPDATE certificates SET issuer_ca_key = $1 WHERE sha256 = ANY($2)`, cagraph.Key(c), children)
	return err
}

// findIssuer returns the key of the authority whose key verifies c's
// signature, or nil when no such CA is stored yet. Candidates are cached
// for the transaction: a bulk import repeats the same few issuers.
func (tx *Tx) findIssuer(ctx context.Context, c *x509.Certificate) (*string, error) {
	if c.IsCA && bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
		k := cagraph.Key(c)
		return &k, nil
	}
	name := c.Issuer.String()
	cands, ok := tx.caCandidates[name]
	if !ok {
		var err error
		if cands, err = tx.loadCandidates(ctx, name); err != nil {
			return nil, err
		}
		if tx.caCandidates == nil {
			tx.caCandidates = map[string][]*x509.Certificate{}
		}
		tx.caCandidates[name] = cands
	}
	for _, p := range cands {
		if signedBy(c, p) {
			k := cagraph.Key(p)
			return &k, nil
		}
	}
	return nil, nil
}

func (tx *Tx) loadCandidates(ctx context.Context, subject string) ([]*x509.Certificate, error) {
	rows, err := tx.Query(ctx, `SELECT der FROM certificates WHERE is_ca AND subject = $1 LIMIT $2`, subject, maxIssuerCandidates)
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
		if p, err := x509.ParseCertificate(der); err == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

func signedBy(c, parent *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
		return false
	}
	if len(c.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, parent.SubjectKeyId) {
		return false
	}
	return c.CheckSignatureFrom(parent) == nil
}

// LinkPendingCertificates links up to limit certificates stored before the
// CA inventory existed, CAs first. It returns how many it processed.
func (tx *Tx) LinkPendingCertificates(ctx context.Context, limit int) (int, error) {
	rows, err := tx.Query(ctx, `SELECT sha256, der FROM certificates WHERE issuer_link_pending ORDER BY is_ca DESC, sha256 LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type pending struct {
		sha string
		der []byte
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.sha, &p.der); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, p := range todo {
		c, err := x509.ParseCertificate(p.der)
		if err != nil {
			if _, err := tx.Exec(ctx, `UPDATE certificates SET issuer_link_pending = false WHERE sha256 = $1`, p.sha); err != nil {
				return 0, err
			}
			continue
		}
		if err := tx.linkCertificate(ctx, p.sha, c); err != nil {
			return 0, err
		}
	}
	return len(todo), nil
}

// AuthorityGraph loads every CA certificate of the organization.
func (tx *Tx) AuthorityGraph(ctx context.Context) (*cagraph.Graph, error) {
	rows, err := tx.Query(ctx, `SELECT sha256, ca_key, coalesce(issuer_ca_key, ''), subject, issuer, not_before, not_after, self_signed
		FROM certificates WHERE ca_key IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []cagraph.Cert
	for rows.Next() {
		var c cagraph.Cert
		if err := rows.Scan(&c.SHA256, &c.Key, &c.IssuerKey, &c.Subject, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.SelfSigned); err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cagraph.Build(certs), nil
}

// LeafLink is a non-CA certificate and the authority that signed it.
type LeafLink struct {
	SHA256      string    `json:"sha256"`
	IssuerKey   string    `json:"issuer_key"`
	CommonName  string    `json:"common_name,omitempty"`
	NotAfter    time.Time `json:"not_after"`
	LineageID   string    `json:"lineage_id,omitempty"`
	LineageName string    `json:"lineage_name,omitempty"`
}

// LeafIssuers maps unexpired, linked non-CA certificates to their issuing
// authority.
func (tx *Tx) LeafIssuers(ctx context.Context, now time.Time) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT sha256, issuer_ca_key FROM certificates
		WHERE NOT is_ca AND issuer_ca_key IS NOT NULL AND not_after > $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var s, k string
		if err := rows.Scan(&s, &k); err != nil {
			return nil, err
		}
		out[s] = k
	}
	return out, rows.Err()
}

// AuthoritiesInUse returns the authorities that directly sign a lineage's
// current certificate or the leaf last seen on an enabled endpoint.
func (tx *Tx) AuthoritiesInUse(ctx context.Context) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT c.issuer_ca_key FROM certificates c
		WHERE c.issuer_ca_key IS NOT NULL AND (
		  c.sha256 IN (SELECT current_sha256 FROM lineages WHERE current_sha256 IS NOT NULL)
		  OR c.sha256 IN (SELECT last_leaf_sha256 FROM endpoints WHERE enabled AND last_leaf_sha256 IS NOT NULL))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// LineagesUnder returns the lineages whose current certificate was signed
// by one of keys.
func (tx *Tx) LineagesUnder(ctx context.Context, keys []string) ([]LeafLink, error) {
	rows, err := tx.Query(ctx, `SELECT c.sha256, c.issuer_ca_key, c.common_name, c.not_after, l.id, l.name
		FROM lineages l JOIN certificates c ON c.sha256 = l.current_sha256
		WHERE c.issuer_ca_key = ANY($1) ORDER BY c.not_after, l.name`, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LeafLink
	for rows.Next() {
		var l LeafLink
		if err := rows.Scan(&l.SHA256, &l.IssuerKey, &l.CommonName, &l.NotAfter, &l.LineageID, &l.LineageName); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// EndpointLink is an endpoint whose last served leaf chains to an authority.
type EndpointLink struct {
	EndpointID string    `json:"endpoint_id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SNI        string    `json:"sni,omitempty"`
	LeafSHA256 string    `json:"leaf_sha256"`
	IssuerKey  string    `json:"issuer_key"`
	NotAfter   time.Time `json:"not_after"`
}

// EndpointsUnder returns enabled endpoints whose last leaf was signed by one
// of keys.
func (tx *Tx) EndpointsUnder(ctx context.Context, keys []string) ([]EndpointLink, error) {
	rows, err := tx.Query(ctx, `SELECT e.id, e.host, e.port, e.sni, c.sha256, c.issuer_ca_key, c.not_after
		FROM endpoints e JOIN certificates c ON c.sha256 = e.last_leaf_sha256
		WHERE e.enabled AND c.issuer_ca_key = ANY($1) ORDER BY e.host, e.port`, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointLink
	for rows.Next() {
		var e EndpointLink
		if err := rows.Scan(&e.EndpointID, &e.Host, &e.Port, &e.SNI, &e.LeafSHA256, &e.IssuerKey, &e.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountLeavesUnder counts unexpired non-CA certificates signed by each key.
func (tx *Tx) CountLeavesUnder(ctx context.Context, now time.Time) (map[string]int, error) {
	rows, err := tx.Query(ctx, `SELECT issuer_ca_key, count(*) FROM certificates
		WHERE NOT is_ca AND issuer_ca_key IS NOT NULL AND not_after > $1 GROUP BY issuer_ca_key`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// OpenAuthorityFindings returns the authorities that have open findings.
func (tx *Tx) OpenAuthorityFindings(ctx context.Context) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT subject_id FROM findings WHERE subject_type = 'authority' AND resolved_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// LineageDeploy is a deployment of a lineage, as impact reports show it.
type LineageDeploy struct {
	ID       string `json:"id"`
	IssuerID string `json:"issuer_id"`
	AgentID  string `json:"agent_id"`
	Enabled  bool   `json:"enabled"`
}

// DeploymentsForLineages groups the deployments of the given lineages.
func (tx *Tx) DeploymentsForLineages(ctx context.Context, lineageIDs []string) (map[string][]LineageDeploy, error) {
	out := map[string][]LineageDeploy{}
	if len(lineageIDs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT id, lineage_id, issuer_id, agent_id, enabled FROM deployments
		WHERE lineage_id = ANY($1) ORDER BY id`, lineageIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d LineageDeploy
		var lineage string
		if err := rows.Scan(&d.ID, &lineage, &d.IssuerID, &d.AgentID, &d.Enabled); err != nil {
			return nil, err
		}
		out[lineage] = append(out[lineage], d)
	}
	return out, rows.Err()
}
