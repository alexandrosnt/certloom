package app

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/auditexport"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func mustAddr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }

// jitter returns d +/- 10 %.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := int64(d) / 5
	return d - time.Duration(spread/2) + time.Duration(rand.Int64N(spread+1)) //nolint:gosec // schedule jitter, not a secret
}

// ---------- Certificates ----------

// ListCertificates lists certificates, soonest expiry first.
func (s *Service) ListCertificates(ctx context.Context, p authz.Principal, f store.CertFilter) (out []*store.CertificateRow, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListCertificates(ctx, f); return err })
	return out, err
}

// CertificateDetail is a certificate with where it is served and its findings.
type CertificateDetail struct {
	*store.CertificateRow
	ServedBy []*store.Endpoint `json:"served_by"`
	Findings []store.Finding   `json:"findings"`
}

// GetCertificate returns certificate detail by fingerprint (or unique prefix).
func (s *Service) GetCertificate(ctx context.Context, p authz.Principal, fp string) (*CertificateDetail, error) {
	var d CertificateDetail
	err := s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) (err error) {
		if d.CertificateRow, err = tx.GetCertificate(ctx, strings.ToLower(fp)); err != nil {
			return err
		}
		if d.ServedBy, err = tx.EndpointsServing(ctx, d.SHA256); err != nil {
			return err
		}
		d.Findings, err = tx.ListFindings(ctx, store.FindingFilter{SubjectType: "certificate", SubjectID: d.SHA256})
		return err
	})
	return &d, err
}

// ---------- Overview ----------

// Metric is a dashboard number with its definition and denominator.
type Metric struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Value       int    `json:"value"`
	Denominator int    `json:"denominator"`
	Definition  string `json:"definition"`
	Link        string `json:"link"` // drill-down
}

// Overview returns headline metrics.
func (s *Service) Overview(ctx context.Context, p authz.Principal) ([]Metric, error) {
	var m []Metric
	err := s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		q := func(sql string, args ...any) int {
			var n int
			if err := tx.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
				return -1
			}
			return n
		}
		certs := q(`SELECT count(*) FROM certificates WHERE NOT is_ca`)
		eps := q(`SELECT count(*) FROM endpoints WHERE enabled`)
		lins := q(`SELECT count(*) FROM lineages`)
		now := s.now()
		m = []Metric{
			{"expired", "Expired certificates", q(`SELECT count(*) FROM certificates WHERE NOT is_ca AND not_after <= $1`, now), certs,
				"Leaf certificates in the inventory whose NotAfter has passed.", "/certificates?expiring=0d"},
			{"expiring_7d", "Expiring within 7 days", q(`SELECT count(*) FROM certificates WHERE NOT is_ca AND not_after > $1 AND not_after <= $2`, now, now.Add(7*24*time.Hour)), certs,
				"Leaf certificates (not yet expired) with NotAfter in the next 7 days.", "/certificates?expiring=7d"},
			{"expiring_30d", "Expiring within 30 days", q(`SELECT count(*) FROM certificates WHERE NOT is_ca AND not_after > $1 AND not_after <= $2`, now, now.Add(30*24*time.Hour)), certs,
				"Leaf certificates (not yet expired) with NotAfter in the next 30 days.", "/certificates?expiring=30d"},
			{"endpoint_mismatch", "Endpoints serving an unexpected certificate", q(`SELECT count(DISTINCT subject_id) FROM findings WHERE resolved_at IS NULL AND check_id = 'lineage_mismatch'`), eps,
				"Enabled endpoints bound to a lineage whose last observation served a different certificate than the lineage's current one.", "/findings?check=lineage_mismatch"},
			{"endpoints_critical", "Endpoints with critical findings", q(`SELECT count(DISTINCT subject_id) FROM findings WHERE resolved_at IS NULL AND subject_type = 'endpoint' AND severity = 'critical'`), eps,
				"Enabled endpoints with at least one open critical finding (expired, untrusted, hostname mismatch, lineage mismatch...).", "/findings?severity=critical"},
			{"probe_failing", "Endpoints failing probes", q(`SELECT count(*) FROM endpoints WHERE enabled AND consecutive_failures > 0`), eps,
				"Enabled endpoints whose most recent probe failed (unreachable, refused, TLS error, scope denied).", "/endpoints?failing=1"},
			{"never_observed", "Endpoints never observed", q(`SELECT count(*) FROM endpoints WHERE enabled AND last_observed_at IS NULL`), eps,
				"Enabled endpoints that have not completed a probe yet.", "/endpoints"},
			{"unowned_lineages", "Lineages without an owning team", q(`SELECT count(*) FROM lineages WHERE team_id IS NULL`), lins,
				"Lineages with no team assigned; nobody is responsible for renewing them.", "/lineages"},
			{"open_alerts", "Open alerts", q(`SELECT count(*) FROM alerts WHERE state = 'open'`), q(`SELECT count(*) FROM alerts WHERE state IN ('open','acked')`),
				"Alerts not yet acknowledged, out of all unresolved alerts.", "/alerts"},
		}
		return nil
	})
	return m, err
}

// ListFindings lists findings.
func (s *Service) ListFindings(ctx context.Context, p authz.Principal, f store.FindingFilter) (out []store.Finding, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListFindings(ctx, f); return err })
	return out, err
}

// ---------- Teams and lineages ----------

// CreateTeam creates a team.
func (s *Service) CreateTeam(ctx context.Context, p authz.Principal, name, contact string) (*store.Team, error) {
	if strings.TrimSpace(name) == "" {
		return nil, invalid("team name is required")
	}
	var t *store.Team
	err := s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) (err error) {
		if t, err = tx.CreateTeam(ctx, name, contact); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "teams.create", "team", t.ID, map[string]any{"name": name})
	})
	return t, err
}

// ListTeams lists teams.
func (s *Service) ListTeams(ctx context.Context, p authz.Principal) (out []store.Team, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListTeams(ctx); return err })
	return out, err
}

// CreateLineage creates a lineage, optionally with a current certificate and team.
func (s *Service) CreateLineage(ctx context.Context, p authz.Principal, name, team, currentFP string) (*store.Lineage, error) {
	if strings.TrimSpace(name) == "" {
		return nil, invalid("lineage name is required")
	}
	var l *store.Lineage
	err := s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) error {
		var teamID, cur *string
		if team != "" {
			t, err := tx.TeamByRef(ctx, team)
			if err != nil {
				return invalid("team %q not found", team)
			}
			teamID = &t.ID
		}
		if currentFP != "" {
			c, err := tx.GetCertificate(ctx, strings.ToLower(currentFP))
			if err != nil {
				return invalid("certificate %q not found", currentFP)
			}
			cur = &c.SHA256
		}
		var err error
		if l, err = tx.CreateLineage(ctx, name, teamID, cur); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "lineages.create", "lineage", l.ID, map[string]any{"name": name, "team": team, "current": currentFP})
	})
	return l, err
}

// ListLineages lists lineages.
func (s *Service) ListLineages(ctx context.Context, p authz.Principal) (out []store.Lineage, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListLineages(ctx); return err })
	return out, err
}

// GetLineage returns a lineage by id or name.
func (s *Service) GetLineage(ctx context.Context, p authz.Principal, ref string) (l *store.Lineage, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { l, err = tx.LineageByRef(ctx, ref); return err })
	return l, err
}

// AssignOwner assigns a team to a lineage.
// ifVersion, if non-nil, is the lineage version the caller last saw (If-Match).
func (s *Service) AssignOwner(ctx context.Context, p authz.Principal, lineage, team string, ifVersion *int64) error {
	return s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) error {
		l, err := tx.LineageByRef(ctx, lineage)
		if err != nil {
			return err // ErrNotFound -> 404
		}
		t, err := tx.TeamByRef(ctx, team)
		if err != nil {
			return invalid("team %q not found", team)
		}
		if err := tx.AssignLineageTeam(ctx, l.ID, t.ID, ifVersion); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "lineages.assign_owner", "lineage", l.ID, map[string]any{"team": t.ID})
	})
}

// ---------- Alerts ----------

// ListAlerts lists alerts in the given states.
func (s *Service) ListAlerts(ctx context.Context, p authz.Principal, states []string) (out []store.Alert, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListAlerts(ctx, states, 0); return err })
	return out, err
}

// AckAlert acknowledges an alert.
func (s *Service) AckAlert(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.AckAlerts, func(tx *store.Tx) error {
		if err := tx.AckAlert(ctx, id, p.Actor); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "alerts.ack", "alert", id, nil)
	})
}

// ---------- Channels ----------

// CreateChannel creates a notification channel after validating its config.
func (s *Service) CreateChannel(ctx context.Context, p authz.Principal, c *store.Channel) error {
	if err := ValidateChannel(c); err != nil {
		return invalid("%v", err)
	}
	return s.tx(ctx, p, authz.ManageChannels, func(tx *store.Tx) error {
		if err := tx.CreateChannel(ctx, c); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "channels.create", "channel", c.ID, map[string]any{"name": c.Name, "kind": c.Kind,
			"min_severity": c.MinSeverity, "has_credential": c.CredentialRef != ""})
	})
}

// ListChannels lists channels.
func (s *Service) ListChannels(ctx context.Context, p authz.Principal) (out []store.Channel, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListChannels(ctx); return err })
	return out, err
}

// TestChannel enqueues a test notification to one channel.
func (s *Service) TestChannel(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageChannels, func(tx *store.Tx) error {
		c, err := tx.GetChannel(ctx, id)
		if err != nil {
			return err
		}
		n := store.Notification{Event: "test", OrgID: p.OrgID, Message: "Test notification from certloom", At: s.now().UTC()}
		b, _ := json.Marshal(n)
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (org_id, channel_id, dedupe_key, payload) VALUES ($1,$2,$3,$4)`,
			p.OrgID, c.ID, c.ID+":test:"+s.now().Format(time.RFC3339Nano), b); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "channels.test", "channel", id, nil)
	})
}

// ---------- Tokens ----------

// CreateToken creates an API token; the plaintext is returned once.
func (s *Service) CreateToken(ctx context.Context, p authz.Principal, name, role string, ttl time.Duration) (*store.APIToken, secret.Value, error) {
	if !store.ValidRole(role) {
		return nil, secret.Value{}, invalid("unknown role %q", role)
	}
	if role == store.RoleApprover {
		return nil, secret.Value{}, invalid("approvals are decided by signed-in people, so an approver token would have no use")
	}
	// Prevent privilege escalation: only owners can mint owner tokens.
	if role == store.RoleOwner && p.Role != store.RoleOwner {
		return nil, secret.Value{}, authz.ErrForbidden
	}
	var t *store.APIToken
	var v secret.Value
	err := s.tx(ctx, p, authz.ManageTokens, func(tx *store.Tx) (err error) {
		if t, v, err = tx.CreateToken(ctx, name, role, p.Actor, ttl); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "tokens.create", "token", t.ID, map[string]any{"name": name, "role": role, "ttl_seconds": int(ttl.Seconds())})
	})
	return t, v, err
}

// ListTokens lists token metadata.
func (s *Service) ListTokens(ctx context.Context, p authz.Principal) (out []store.APIToken, err error) {
	err = s.tx(ctx, p, authz.ManageTokens, func(tx *store.Tx) error { out, err = tx.ListTokens(ctx); return err })
	return out, err
}

// RevokeToken revokes a token.
func (s *Service) RevokeToken(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageTokens, func(tx *store.Tx) error {
		if err := tx.RevokeToken(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "tokens.revoke", "token", id, nil)
	})
}

// Authenticate resolves a bearer token (API token or OIDC session) to a principal.
func (s *Service) Authenticate(ctx context.Context, token string) (authz.Principal, error) {
	if strings.HasPrefix(token, "certlooms_") {
		return s.authenticateSession(ctx, token)
	}
	org, ok := store.ParseTokenOrg(token)
	if !ok {
		return authz.Principal{}, store.ErrInvalidToken
	}
	var p authz.Principal
	err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		t, err := tx.AuthenticateToken(ctx, token)
		if err != nil {
			return err
		}
		p = authz.Principal{OrgID: org, Actor: "token:" + t.ID, Role: t.Role}
		return nil
	})
	if errors.Is(err, store.ErrInvalidToken) {
		return p, store.ErrInvalidToken
	}
	return p, err
}

// ---------- Audit and automation ----------

// AuditQuery returns events after a sequence number.
func (s *Service) AuditQuery(ctx context.Context, p authz.Principal, after int64, limit int) (out []audit.Event, err error) {
	err = s.tx(ctx, p, authz.ViewAudit, func(tx *store.Tx) error { out, err = audit.Query(ctx, tx, p.OrgID, after, limit); return err })
	return out, err
}

// AuditVerify recomputes the org's audit chain.
func (s *Service) AuditVerify(ctx context.Context, p authz.Principal) (r audit.VerifyResult, err error) {
	err = s.tx(ctx, p, authz.ViewAudit, func(tx *store.Tx) error { r, err = audit.Verify(ctx, tx, p.OrgID); return err })
	return r, err
}

// SetPaused pauses or resumes automation for the principal's org.
func (s *Service) SetPaused(ctx context.Context, p authz.Principal, paused bool, reason string) error {
	return s.tx(ctx, p, authz.ManageAutomation, func(tx *store.Tx) error {
		if err := jobs.SetPaused(ctx, tx, "org:"+p.OrgID, paused, reason); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "automation.set_paused", "org", p.OrgID, map[string]any{"paused": paused, "reason": reason})
	})
}

// AuditExportStatus reports export progress for the principal's org.
func (s *Service) AuditExportStatus(ctx context.Context, p authz.Principal) (out []auditexport.Status, err error) {
	err = s.tx(ctx, p, authz.ViewAudit, func(tx *store.Tx) error { out, err = auditexport.GetStatus(ctx, tx); return err })
	return out, err
}
