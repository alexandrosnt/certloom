package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/jackc/pgx/v5"
)

// ScopeConfig is the stored, JSON form of probe.Scope.
type ScopeConfig struct {
	AllowCIDRs     []string `json:"allow_cidrs,omitempty"`
	AllowHosts     []string `json:"allow_hosts,omitempty"`
	AllowLoopback  bool     `json:"allow_loopback,omitempty"`
	AllowPrivate   bool     `json:"allow_private,omitempty"`
	AllowLinkLocal bool     `json:"allow_link_local,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
}

// ProbeScope is a stored scope.
type ProbeScope struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Config    ScopeConfig `json:"config"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
}

// ToProbe converts to the prober's representation, validating CIDRs.
func (s *ProbeScope) ToProbe() (*probe.Scope, error) {
	ps := &probe.Scope{Name: s.Name, AllowHosts: s.Config.AllowHosts, AllowLoopback: s.Config.AllowLoopback,
		AllowPrivate: s.Config.AllowPrivate, AllowLinkLocal: s.Config.AllowLinkLocal, Ports: s.Config.Ports}
	for _, c := range s.Config.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		ps.AllowCIDRs = append(ps.AllowCIDRs, p)
	}
	return ps, nil
}

// CreateScope inserts a probe scope.
func (tx *Tx) CreateScope(ctx context.Context, name string, cfg ScopeConfig) (*ProbeScope, error) {
	s := &ProbeScope{ID: ids.New(ids.Scope), Name: name, Config: cfg, Enabled: true}
	if _, err := s.ToProbe(); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(cfg)
	err := tx.QueryRow(ctx, `INSERT INTO probe_scopes (id, org_id, name, config) VALUES ($1,$2,$3,$4) RETURNING created_at`,
		s.ID, tx.OrgID, name, b).Scan(&s.CreatedAt)
	return s, conflict(err)
}

func scanScope(r pgx.Row) (*ProbeScope, error) {
	s := &ProbeScope{}
	var b []byte
	if err := r.Scan(&s.ID, &s.Name, &b, &s.Enabled, &s.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return s, json.Unmarshal(b, &s.Config)
}

// ScopeByRef resolves a scope by id or name.
func (tx *Tx) ScopeByRef(ctx context.Context, ref string) (*ProbeScope, error) {
	return scanScope(tx.QueryRow(ctx, `SELECT id, name, config, enabled, created_at FROM probe_scopes WHERE id = $1 OR name = $1`, ref))
}

// ListScopes returns all scopes.
func (tx *Tx) ListScopes(ctx context.Context) ([]*ProbeScope, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, config, enabled, created_at FROM probe_scopes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProbeScope
	for rows.Next() {
		s, err := scanScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Endpoint is a configured probe target.
type Endpoint struct {
	ID                  string     `json:"id"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	SNI                 string     `json:"sni,omitempty"`
	ScopeID             string     `json:"scope_id"`
	LineageID           *string    `json:"lineage_id,omitempty"`
	TeamID              *string    `json:"team_id,omitempty"`
	IntervalSeconds     int        `json:"interval_seconds"`
	Enabled             bool       `json:"enabled"`
	LastLeafSHA256      *string    `json:"last_leaf_sha256,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastObservedAt      *time.Time `json:"last_observed_at,omitempty"`
	NextProbeAt         time.Time  `json:"next_probe_at"`
	Version             int64      `json:"version"` // configuration version; the HTTP ETag
	CreatedAt           time.Time  `json:"created_at"`
}

// Name is the hostname clients use for this endpoint.
func (e *Endpoint) Name() string {
	if e.SNI != "" {
		return e.SNI
	}
	return e.Host
}

const endpointCols = `id, host, port, sni, scope_id, lineage_id, team_id, interval_seconds, enabled, last_leaf_sha256,
	consecutive_failures, last_observed_at, next_probe_at, created_at, version`

func scanEndpoint(r pgx.Row) (*Endpoint, error) {
	e := &Endpoint{}
	err := r.Scan(&e.ID, &e.Host, &e.Port, &e.SNI, &e.ScopeID, &e.LineageID, &e.TeamID, &e.IntervalSeconds, &e.Enabled,
		&e.LastLeafSHA256, &e.ConsecutiveFailures, &e.LastObservedAt, &e.NextProbeAt, &e.CreatedAt, &e.Version)
	return e, notFound(err)
}

// CreateEndpoint inserts an endpoint, due for probing immediately.
func (tx *Tx) CreateEndpoint(ctx context.Context, e *Endpoint) error {
	e.ID = ids.New(ids.Endpoint)
	if e.IntervalSeconds == 0 {
		e.IntervalSeconds = 6 * 3600
	}
	e.Enabled, e.Version = true, 1
	err := tx.QueryRow(ctx, `INSERT INTO endpoints (id, org_id, host, port, sni, scope_id, lineage_id, team_id, interval_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING next_probe_at, created_at`,
		e.ID, tx.OrgID, e.Host, e.Port, e.SNI, e.ScopeID, e.LineageID, e.TeamID, e.IntervalSeconds).Scan(&e.NextProbeAt, &e.CreatedAt)
	return conflict(err)
}

// GetEndpoint returns an endpoint by id.
func (tx *Tx) GetEndpoint(ctx context.Context, id string) (*Endpoint, error) {
	return scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE id = $1`, id))
}

// ListEndpoints returns all endpoints.
func (tx *Tx) ListEndpoints(ctx context.Context) ([]*Endpoint, error) {
	rows, err := tx.Query(ctx, `SELECT `+endpointCols+` FROM endpoints ORDER BY host, port, sni`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Endpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetEndpointLineage binds an endpoint to a lineage (or unbinds with nil).
// ifVersion, if non-nil, must equal the current version (If-Match).
func (tx *Tx) SetEndpointLineage(ctx context.Context, endpointID string, lineageID *string, ifVersion *int64) error {
	return tx.versioned(ctx, "endpoints", endpointID, `UPDATE endpoints SET lineage_id = $2, version = version + 1
		WHERE id = $1 AND ($3::bigint IS NULL OR version = $3)`, endpointID, lineageID, ifVersion)
}

// ProbeNow makes an endpoint due immediately.
func (tx *Tx) ProbeNow(ctx context.Context, endpointID string) error {
	tag, err := tx.Exec(ctx, `UPDATE endpoints SET next_probe_at = now() WHERE id = $1`, endpointID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RecordObservation stores an observation and updates the endpoint's state.
// next is when the endpoint should next be probed.
func (tx *Tx) RecordObservation(ctx context.Context, e *Endpoint, o *probe.Observation, next time.Time) error {
	var leaf *string
	chain := make([]string, 0, len(o.Chain))
	for _, c := range o.Chain {
		chain = append(chain, c.SHA256)
	}
	if l := o.Leaf(); l != nil {
		leaf = &l.SHA256
	}
	if _, err := tx.Exec(ctx, `INSERT INTO observations (org_id, endpoint_id, observed_at, address, leaf_sha256, chain_sha256,
		tls_version, cipher, alpn, latency_ms, error_class, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		tx.OrgID, e.ID, o.ObservedAt, o.Address, leaf, chain, o.TLSVersion, o.Cipher, o.ALPN, o.LatencyMS, o.ErrorClass, o.Error); err != nil {
		return err
	}
	if o.ErrorClass != "" {
		_, err := tx.Exec(ctx, `UPDATE endpoints SET consecutive_failures = consecutive_failures + 1,
			last_observed_at = $2, next_probe_at = $3 WHERE id = $1`, e.ID, o.ObservedAt, next)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE endpoints SET consecutive_failures = 0, last_leaf_sha256 = $2,
		last_observed_at = $3, next_probe_at = $4 WHERE id = $1`, e.ID, leaf, o.ObservedAt, next)
	return err
}

// Observation is a stored probe result.
type Observation struct {
	ObservedAt  time.Time `json:"observed_at"`
	Address     string    `json:"address,omitempty"`
	LeafSHA256  *string   `json:"leaf_sha256,omitempty"`
	ChainSHA256 []string  `json:"chain_sha256,omitempty"`
	TLSVersion  string    `json:"tls_version,omitempty"`
	Cipher      string    `json:"cipher,omitempty"`
	LatencyMS   int64     `json:"latency_ms"`
	ErrorClass  string    `json:"error_class,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ListObservations returns recent observations for an endpoint, newest first.
func (tx *Tx) ListObservations(ctx context.Context, endpointID string, limit int) ([]Observation, error) {
	if limit <= 0 || limit > 500 {
		limit = 20
	}
	rows, err := tx.Query(ctx, `SELECT observed_at, address, leaf_sha256, chain_sha256, tls_version, cipher, latency_ms, error_class, error
		FROM observations WHERE endpoint_id = $1 ORDER BY observed_at DESC LIMIT $2`, endpointID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Observation, error) {
		var o Observation
		err := r.Scan(&o.ObservedAt, &o.Address, &o.LeafSHA256, &o.ChainSHA256, &o.TLSVersion, &o.Cipher, &o.LatencyMS, &o.ErrorClass, &o.Error)
		return o, err
	})
}

// EndpointsServing returns endpoints whose last observed leaf is sha.
func (tx *Tx) EndpointsServing(ctx context.Context, sha string) ([]*Endpoint, error) {
	rows, err := tx.Query(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE last_leaf_sha256 = $1 ORDER BY host`, sha)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Endpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Finding is a stored check result.
type Finding struct {
	ID          string     `json:"id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	Check       string     `json:"check"`
	Severity    string     `json:"severity"`
	Message     string     `json:"message"`
	Remediation string     `json:"remediation,omitempty"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// SyncResult reports what SyncFindings changed.
type SyncResult struct {
	Opened    []Finding // newly opened findings
	Escalated []Finding // existing findings whose severity increased
	Resolved  []Finding
}

// SyncFindings makes the open findings for a subject equal to current:
// new checks are opened, existing ones refreshed (escalations reported),
// and checks no longer present are resolved. Alerts for warning/critical
// findings are opened and resolved accordingly, in the same transaction.
func (tx *Tx) SyncFindings(ctx context.Context, subjectType, subjectID string, current []checks.Finding, now time.Time) (*SyncResult, error) {
	res := &SyncResult{}
	rows, err := tx.Query(ctx, `SELECT id, check_id, severity, message, remediation, first_seen, last_seen
		FROM findings WHERE subject_type = $1 AND subject_id = $2 AND resolved_at IS NULL`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	open := map[string]Finding{}
	for rows.Next() {
		f := Finding{SubjectType: subjectType, SubjectID: subjectID}
		if err := rows.Scan(&f.ID, &f.Check, &f.Severity, &f.Message, &f.Remediation, &f.FirstSeen, &f.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		open[f.Check] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, c := range current {
		if seen[c.Check] { // keep the first (most specific) per check
			continue
		}
		seen[c.Check] = true
		if f, ok := open[c.Check]; ok {
			oldRank, newRank := checks.Severity(f.Severity).Rank(), c.Severity.Rank()
			if _, err := tx.Exec(ctx, `UPDATE findings SET severity = $2, message = $3, remediation = $4, last_seen = $5 WHERE id = $1`,
				f.ID, string(c.Severity), c.Message, c.Remediation, now); err != nil {
				return nil, err
			}
			f.Severity, f.Message, f.Remediation, f.LastSeen = string(c.Severity), c.Message, c.Remediation, now
			switch {
			case newRank > oldRank:
				if err := tx.upsertAlert(ctx, &f); err != nil {
					return nil, err
				}
				res.Escalated = append(res.Escalated, f)
			case newRank < oldRank && c.Severity == checks.Info:
				// De-escalated to info: info findings carry no alert.
				if _, err := tx.Exec(ctx, `UPDATE alerts SET state = 'resolved', resolved_at = $2 WHERE finding_id = $1 AND state <> 'resolved'`, f.ID, now); err != nil {
					return nil, err
				}
			case newRank < oldRank:
				if _, err := tx.Exec(ctx, `UPDATE alerts SET severity = $2 WHERE finding_id = $1`, f.ID, f.Severity); err != nil {
					return nil, err
				}
			}
			continue
		}
		f := Finding{ID: ids.New(ids.Finding), SubjectType: subjectType, SubjectID: subjectID, Check: c.Check,
			Severity: string(c.Severity), Message: c.Message, Remediation: c.Remediation, FirstSeen: now, LastSeen: now}
		if _, err := tx.Exec(ctx, `INSERT INTO findings (id, org_id, subject_type, subject_id, check_id, severity, message, remediation, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, f.ID, tx.OrgID, subjectType, subjectID, c.Check, f.Severity, c.Message, c.Remediation, now); err != nil {
			return nil, err
		}
		if err := tx.upsertAlert(ctx, &f); err != nil {
			return nil, err
		}
		res.Opened = append(res.Opened, f)
	}
	for check, f := range open {
		if seen[check] {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET resolved_at = $2 WHERE id = $1`, f.ID, now); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET state = 'resolved', resolved_at = $2 WHERE finding_id = $1 AND state <> 'resolved'`, f.ID, now); err != nil {
			return nil, err
		}
		f.ResolvedAt = &now
		res.Resolved = append(res.Resolved, f)
	}
	return res, nil
}

func (tx *Tx) upsertAlert(ctx context.Context, f *Finding) error {
	if f.Severity == string(checks.Info) {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO alerts (id, org_id, finding_id, severity) VALUES ($1,$2,$3,$4)
		ON CONFLICT (finding_id) DO UPDATE SET severity = EXCLUDED.severity,
		  state = CASE WHEN alerts.state = 'acked' THEN 'open' ELSE alerts.state END`,
		ids.New(ids.Alert), tx.OrgID, f.ID, f.Severity)
	return err
}

// FindingFilter narrows ListFindings.
type FindingFilter struct {
	SubjectType, SubjectID string
	MinSeverity            string
	IncludeResolved        bool
	Limit                  int
}

// ListFindings returns findings, most severe and most recent first.
func (tx *Tx) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT id, subject_type, subject_id, check_id, severity, message, remediation, first_seen, last_seen, resolved_at
		FROM findings WHERE true`
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		q += " AND " + replaceN(cond, len(args))
	}
	if !f.IncludeResolved {
		q += " AND resolved_at IS NULL"
	}
	if f.SubjectType != "" {
		add("subject_type = $N", f.SubjectType)
	}
	if f.SubjectID != "" {
		add("subject_id = $N", f.SubjectID)
	}
	switch f.MinSeverity {
	case "critical":
		q += " AND severity = 'critical'"
	case "warning":
		q += " AND severity IN ('warning','critical')"
	}
	args = append(args, f.Limit)
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_seen DESC LIMIT $` + itoa(len(args))
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Finding, error) {
		var x Finding
		err := r.Scan(&x.ID, &x.SubjectType, &x.SubjectID, &x.Check, &x.Severity, &x.Message, &x.Remediation, &x.FirstSeen, &x.LastSeen, &x.ResolvedAt)
		return x, err
	})
}

// Alert is a notification state for a finding.
type Alert struct {
	ID         string     `json:"id"`
	FindingID  string     `json:"finding_id"`
	State      string     `json:"state"`
	Severity   string     `json:"severity"`
	CreatedAt  time.Time  `json:"created_at"`
	AckedBy    *string    `json:"acked_by,omitempty"`
	AckedAt    *time.Time `json:"acked_at,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Finding    *Finding   `json:"finding,omitempty"`
}

// ListAlerts returns alerts in the given states (all if empty), with their findings.
func (tx *Tx) ListAlerts(ctx context.Context, states []string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if len(states) == 0 {
		states = []string{"open", "acked", "resolved", "suppressed"}
	}
	rows, err := tx.Query(ctx, `SELECT a.id, a.finding_id, a.state, a.severity, a.created_at, a.acked_by, a.acked_at, a.resolved_at,
		f.subject_type, f.subject_id, f.check_id, f.message, f.remediation, f.first_seen, f.last_seen
		FROM alerts a JOIN findings f ON f.id = a.finding_id
		WHERE a.state = ANY($1)
		ORDER BY CASE a.state WHEN 'open' THEN 0 WHEN 'acked' THEN 1 ELSE 2 END,
		         CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END, a.created_at DESC LIMIT $2`, states, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		a := Alert{Finding: &Finding{}}
		err := r.Scan(&a.ID, &a.FindingID, &a.State, &a.Severity, &a.CreatedAt, &a.AckedBy, &a.AckedAt, &a.ResolvedAt,
			&a.Finding.SubjectType, &a.Finding.SubjectID, &a.Finding.Check, &a.Finding.Message, &a.Finding.Remediation,
			&a.Finding.FirstSeen, &a.Finding.LastSeen)
		a.Finding.ID, a.Finding.Severity = a.FindingID, a.Severity
		return a, err
	})
}

// AckAlert acknowledges an open alert.
func (tx *Tx) AckAlert(ctx context.Context, id, actor string) error {
	tag, err := tx.Exec(ctx, `UPDATE alerts SET state = 'acked', acked_by = $2, acked_at = now() WHERE id = $1 AND state = 'open'`, id, actor)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GetFinding returns one finding by id.
func (tx *Tx) GetFinding(ctx context.Context, id string) (*Finding, error) {
	f := &Finding{}
	err := tx.QueryRow(ctx, `SELECT id, subject_type, subject_id, check_id, severity, message, remediation, first_seen, last_seen, resolved_at
		FROM findings WHERE id = $1`, id).Scan(&f.ID, &f.SubjectType, &f.SubjectID, &f.Check, &f.Severity, &f.Message, &f.Remediation,
		&f.FirstSeen, &f.LastSeen, &f.ResolvedAt)
	return f, notFound(err)
}
