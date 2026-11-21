// Package app is the service layer: every mutation is authorized, validated,
// executed and audited here, so the API, UI and CLI behave identically.
package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentpki"
	"github.com/alexandrosnt/certloom/internal/ari"
	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/oidcauth"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
)

// ErrInvalid wraps validation failures (mapped to HTTP 400).
var ErrInvalid = errors.New("invalid request")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Service holds dependencies.
type Service struct {
	DB     *store.DB
	Prober *probe.Prober
	Roots  *x509.CertPool // trust anchors for checks; nil = system pool
	Log    *slog.Logger
	Now    func() time.Time
	// OIDC is nil when single sign-on is not configured.
	OIDC *oidcauth.Provider
	// PKI is nil when agent support is not configured (no KEK).
	PKI *agentpki.PKI
	ARI *ari.Client
	// AgentServerURL is the agent listener URL shown in enrollment commands.
	AgentServerURL string
	SessionTTL     time.Duration // default 12h
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// tx runs fn in the principal's org after checking perm.
func (s *Service) tx(ctx context.Context, p authz.Principal, perm authz.Permission, fn func(tx *store.Tx) error) error {
	if err := p.Require(perm); err != nil {
		return err
	}
	return s.DB.WithOrg(ctx, p.OrgID, fn)
}

func (s *Service) audit(ctx context.Context, tx *store.Tx, p authz.Principal, action, rtype, rid string, detail map[string]any) error {
	return audit.Write(ctx, tx, &audit.Event{OrgID: p.OrgID, Actor: p.Actor, Action: action, ResourceType: rtype,
		ResourceID: rid, RequestID: RequestID(ctx), Detail: detail})
}

type ctxKey int

const requestIDKey ctxKey = 0

// WithRequestID attaches a request id for audit correlation.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request id or "".
func RequestID(ctx context.Context) string { s, _ := ctx.Value(requestIDKey).(string); return s }

// ---------- Import ----------

// ImportResult summarizes an import.
type ImportResult struct {
	Format         string   `json:"format"`
	Imported       []string `json:"imported"` // SHA-256 of newly stored certificates
	AlreadyKnown   []string `json:"already_known"`
	PrivateKeySeen bool     `json:"private_key_seen"`
	KeyMatchesLeaf *bool    `json:"key_matches_leaf,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Lineage        string   `json:"lineage,omitempty"`
}

// ImportOptions control an import.
type ImportOptions struct {
	Password secret.Value
	// Lineage, if set, names a lineage to create (or update) with the leaf as current.
	Lineage string
	Team    string // optional team for a new lineage
	DryRun  bool
}

// Import parses data and stores every certificate. Private keys are never stored.
func (s *Service) Import(ctx context.Context, p authz.Principal, data []byte, o ImportOptions) (*ImportResult, error) {
	parsed, err := certparse.Parse(data, o.Password)
	if err != nil {
		return nil, invalid("%v", err)
	}
	res := &ImportResult{Format: parsed.Format, PrivateKeySeen: parsed.PrivateKeySeen, KeyMatchesLeaf: parsed.KeyMatchesLeaf,
		Warnings: parsed.Warnings, Lineage: o.Lineage}
	err = s.tx(ctx, p, authz.ImportCerts, func(tx *store.Tx) error {
		for _, c := range parsed.Certificates {
			ins, err := tx.UpsertCertificate(ctx, c, "import")
			if err != nil {
				return err
			}
			if ins {
				res.Imported = append(res.Imported, c.SHA256)
			} else {
				res.AlreadyKnown = append(res.AlreadyKnown, c.SHA256)
			}
		}
		leaf := parsed.Certificates[0]
		if !leaf.IsCA {
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			res, err := tx.SyncFindings(ctx, "certificate", leaf.SHA256, checks.Certificate(leaf, s.now(), pv.Document.Checks()), s.now())
			if err != nil {
				return err
			}
			if err := notifySync(ctx, tx, leaf.CommonName, res, s.now()); err != nil {
				return err
			}
		}
		if o.Lineage != "" {
			if err := s.bindLineage(ctx, tx, p, o.Lineage, o.Team, leaf.SHA256); err != nil {
				return err
			}
		}
		if err := s.audit(ctx, tx, p, "certificates.import", "certificate", leaf.SHA256, map[string]any{
			"format": parsed.Format, "count": len(parsed.Certificates), "new": len(res.Imported),
			"private_key_seen": parsed.PrivateKeySeen, "lineage": o.Lineage, "dry_run": o.DryRun,
		}); err != nil {
			return err
		}
		if o.DryRun {
			return errDryRun
		}
		return nil
	})
	if errors.Is(err, errDryRun) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

var errDryRun = errors.New("dry run: rolled back")

func (s *Service) bindLineage(ctx context.Context, tx *store.Tx, p authz.Principal, name, team, sha string) error {
	l, err := tx.LineageByRef(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		var teamID *string
		if team != "" {
			t, err := tx.TeamByRef(ctx, team)
			if err != nil {
				return invalid("team %q not found", team)
			}
			teamID = &t.ID
		}
		l, err = tx.CreateLineage(ctx, name, teamID, &sha)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "lineages.create", "lineage", l.ID, map[string]any{"name": name, "current": sha})
	case err != nil:
		return err
	}
	if l.CurrentSHA256 != nil && *l.CurrentSHA256 == sha {
		return nil
	}
	if err := tx.SetLineageCurrent(ctx, l.ID, sha, "import"); err != nil {
		return err
	}
	prev := ""
	if l.CurrentSHA256 != nil {
		prev = *l.CurrentSHA256
	}
	return s.audit(ctx, tx, p, "lineages.set_current", "lineage", l.ID, map[string]any{"previous": prev, "current": sha})
}

// ---------- Scopes and endpoints ----------

// CreateScope creates a probe scope. Overrides of default-denied address
// classes are recorded explicitly in the audit event.
func (s *Service) CreateScope(ctx context.Context, p authz.Principal, name string, cfg store.ScopeConfig) (*store.ProbeScope, error) {
	if strings.TrimSpace(name) == "" {
		return nil, invalid("scope name is required")
	}
	for _, port := range cfg.Ports {
		if port < 1 || port > 65535 {
			return nil, invalid("invalid port %d", port)
		}
	}
	var out *store.ProbeScope
	err := s.tx(ctx, p, authz.ManageScopes, func(tx *store.Tx) (err error) {
		out, err = tx.CreateScope(ctx, name, cfg)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				return err
			}
			return invalid("%v", err)
		}
		return s.audit(ctx, tx, p, "scopes.create", "scope", out.ID, map[string]any{
			"name": name, "allow_cidrs": cfg.AllowCIDRs, "allow_hosts": cfg.AllowHosts, "ports": cfg.Ports,
			"allow_loopback": cfg.AllowLoopback, "allow_private": cfg.AllowPrivate, "allow_link_local": cfg.AllowLinkLocal,
		})
	})
	return out, err
}

// ListScopes lists scopes.
func (s *Service) ListScopes(ctx context.Context, p authz.Principal) (out []*store.ProbeScope, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListScopes(ctx); return err })
	return out, err
}

// AddEndpointInput describes a new endpoint.
type AddEndpointInput struct {
	Host     string
	Port     int
	SNI      string
	Scope    string // id or name
	Lineage  string // optional id or name
	Team     string // optional id or name
	Interval time.Duration
}

// AddEndpoint registers an endpoint after validating it against its scope.
func (s *Service) AddEndpoint(ctx context.Context, p authz.Principal, in AddEndpointInput) (*store.Endpoint, error) {
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	if in.Host == "" || strings.ContainsAny(in.Host, " /\\@") {
		return nil, invalid("invalid host %q", in.Host)
	}
	if in.Port == 0 {
		in.Port = 443
	}
	if in.Interval != 0 && in.Interval < time.Minute {
		return nil, invalid("interval must be at least 1m")
	}
	var out *store.Endpoint
	err := s.tx(ctx, p, authz.ManageEndpoints, func(tx *store.Tx) error {
		sc, err := tx.ScopeByRef(ctx, in.Scope)
		if err != nil {
			return invalid("scope %q not found", in.Scope)
		}
		ps, err := sc.ToProbe()
		if err != nil {
			return err
		}
		if err := ps.CheckHost(in.Host, in.Port); err != nil {
			return invalid("%v", err)
		}
		if ip := net.ParseIP(in.Host); ip != nil {
			if err := ps.CheckAddr(mustAddr(in.Host)); err != nil {
				return invalid("%v", err)
			}
		}
		e := &store.Endpoint{Host: in.Host, Port: in.Port, SNI: strings.ToLower(in.SNI), ScopeID: sc.ID,
			IntervalSeconds: int(in.Interval.Seconds())}
		if in.Lineage != "" {
			l, err := tx.LineageByRef(ctx, in.Lineage)
			if err != nil {
				return invalid("lineage %q not found", in.Lineage)
			}
			e.LineageID = &l.ID
		}
		if in.Team != "" {
			t, err := tx.TeamByRef(ctx, in.Team)
			if err != nil {
				return invalid("team %q not found", in.Team)
			}
			e.TeamID = &t.ID
		}
		if err := tx.CreateEndpoint(ctx, e); err != nil {
			return err
		}
		out = e
		return s.audit(ctx, tx, p, "endpoints.create", "endpoint", e.ID, map[string]any{
			"host": e.Host, "port": e.Port, "sni": e.SNI, "scope": sc.Name, "interval_seconds": e.IntervalSeconds})
	})
	return out, err
}

// ListEndpoints lists endpoints.
func (s *Service) ListEndpoints(ctx context.Context, p authz.Principal) (out []*store.Endpoint, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListEndpoints(ctx); return err })
	return out, err
}

// EndpointDetail is an endpoint with recent observations and open findings.
type EndpointDetail struct {
	*store.Endpoint
	Observations []store.Observation `json:"observations"`
	Findings     []store.Finding     `json:"findings"`
}

// GetEndpoint returns endpoint detail.
func (s *Service) GetEndpoint(ctx context.Context, p authz.Principal, id string) (*EndpointDetail, error) {
	var d EndpointDetail
	err := s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) (err error) {
		if d.Endpoint, err = tx.GetEndpoint(ctx, id); err != nil {
			return err
		}
		if d.Observations, err = tx.ListObservations(ctx, id, 20); err != nil {
			return err
		}
		d.Findings, err = tx.ListFindings(ctx, store.FindingFilter{SubjectType: "endpoint", SubjectID: id})
		return err
	})
	return &d, err
}

// RequestProbe makes an endpoint due now (the scheduler picks it up).
func (s *Service) RequestProbe(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageEndpoints, func(tx *store.Tx) error {
		if err := tx.ProbeNow(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "endpoints.probe_requested", "endpoint", id, nil)
	})
}

// BindEndpointLineage sets the expected lineage for an endpoint.
// ifVersion, if non-nil, is the endpoint version the caller last saw (If-Match).
func (s *Service) BindEndpointLineage(ctx context.Context, p authz.Principal, endpointID, lineage string, ifVersion *int64) error {
	return s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) error {
		l, err := tx.LineageByRef(ctx, lineage)
		if err != nil {
			return invalid("lineage %q not found", lineage)
		}
		if err := tx.SetEndpointLineage(ctx, endpointID, &l.ID, ifVersion); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "endpoints.bind_lineage", "endpoint", endpointID, map[string]any{"lineage": l.ID})
	})
}

// ---------- Probing (system actions run by the scheduler) ----------

// JobKindProbe is the job kind for endpoint probes.
const JobKindProbe = "probe_endpoint"

type probePayload struct {
	EndpointID string `json:"endpoint_id"`
}

// ScheduleDueProbes enqueues probe jobs for every due endpoint in every org.
// Dedupe keys ensure an endpoint has at most one active probe job.
func (s *Service) ScheduleDueProbes(ctx context.Context) (int, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT id FROM organizations`)
	if err != nil {
		return 0, err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	n := 0
	for _, org := range orgs {
		// Drain in batches; endpoints that already have an active probe job are
		// skipped, so the loop terminates and repeated ticks do no wasted work.
		for {
			batch := 0
			err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
				r, err := tx.Query(ctx, `SELECT e.id FROM endpoints e
					WHERE e.enabled AND e.next_probe_at <= now()
					  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.kind = $1 AND j.dedupe_key = e.id AND j.state IN ('pending','running'))
					ORDER BY e.next_probe_at LIMIT 1000`, JobKindProbe)
				if err != nil {
					return err
				}
				due, err := pgx.CollectRows(r, pgx.RowTo[string])
				if err != nil {
					return err
				}
				batch = len(due)
				for _, id := range due {
					ok, err := jobs.Enqueue(ctx, tx, org, JobKindProbe, id, probePayload{EndpointID: id}, time.Time{})
					if err != nil {
						return err
					}
					if ok {
						n++
					}
				}
				return nil
			})
			if err != nil {
				return n, err
			}
			if batch < 1000 {
				break
			}
		}
	}
	return n, nil
}

// RunProbeJob probes one endpoint, evaluates checks, stores the observation,
// syncs findings and enqueues notifications, all fenced by the job lease.
func (s *Service) RunProbeJob(ctx context.Context, j jobs.Job) error {
	var pl probePayload
	if err := jsonUnmarshal(j.Payload, &pl); err != nil {
		return err
	}
	var ep *store.Endpoint
	var scope *probe.Scope
	var expected string
	var known []*x509.Certificate
	var pol checks.Policy
	err := s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) (err error) {
		if ep, err = tx.GetEndpoint(ctx, pl.EndpointID); err != nil {
			return err
		}
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		pol = pv.Document.Checks()
		sc, err := tx.ScopeByRef(ctx, ep.ScopeID)
		if err != nil {
			return err
		}
		if !sc.Enabled {
			return fmt.Errorf("scope %s is disabled", sc.Name)
		}
		if scope, err = sc.ToProbe(); err != nil {
			return err
		}
		if ep.LineageID != nil {
			l, err := tx.LineageByRef(ctx, *ep.LineageID)
			if err != nil {
				return err
			}
			if l.CurrentSHA256 != nil {
				expected = *l.CurrentSHA256
			}
		}
		known, err = tx.KnownIntermediates(ctx)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil // endpoint deleted: nothing to do
	}
	if err != nil {
		return err
	}

	obs := s.Prober.Probe(ctx, scope, probe.Target{Host: ep.Host, Port: ep.Port, SNI: ep.SNI})
	now := s.now()
	failures := 0
	if obs.ErrorClass != "" {
		failures = ep.ConsecutiveFailures + 1
	}
	prev := ""
	if ep.LastLeafSHA256 != nil {
		prev = *ep.LastLeafSHA256
	}
	fs := checks.Endpoint(checks.EndpointInput{Observation: obs, ExpectedName: ep.Name(), PreviousLeaf: prev, ExpectedLeaf: expected,
		Roots: s.Roots, KnownIntermediates: known, ConsecutiveFailures: failures, Now: now, Policy: pol})
	next := now.Add(jitter(time.Duration(ep.IntervalSeconds) * time.Second))
	if obs.ErrorClass != "" {
		next = now.Add(min(jobs.Backoff(failures, time.Minute, time.Duration(ep.IntervalSeconds)*time.Second), time.Duration(ep.IntervalSeconds)*time.Second))
	}

	return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		if err := jobs.Fence(ctx, tx, j); err != nil {
			return err
		}
		for _, c := range obs.Chain {
			if _, err := tx.UpsertCertificate(ctx, c, "probe"); err != nil {
				return err
			}
		}
		if err := tx.RecordObservation(ctx, ep, obs, next); err != nil {
			return err
		}
		// A transient failure keeps the last known certificate findings; only
		// replace them once the failure threshold is reached or on success.
		if obs.ErrorClass != "" && len(fs) == 0 {
			return jobs.Complete(ctx, tx, j)
		}
		res, err := tx.SyncFindings(ctx, "endpoint", ep.ID, fs, now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, fmt.Sprintf("%s:%d", ep.Name(), ep.Port), res, now); err != nil {
			return err
		}
		return jobs.Complete(ctx, tx, j)
	})
}

// notifySync enqueues notifications for a findings sync. Info findings never
// notify; resolutions notify only for findings that had alerted.
func notifySync(ctx context.Context, tx *store.Tx, label string, res *store.SyncResult, now time.Time) error {
	send := func(event, dedupeSuffix string, fs []store.Finding) error {
		for _, f := range fs {
			if f.Severity == string(checks.Info) {
				continue
			}
			if err := tx.EnqueueNotification(ctx, notificationFor(tx.OrgID, event, label, f, now), f.ID+":"+dedupeSuffix+f.Severity); err != nil {
				return err
			}
		}
		return nil
	}
	if err := send("finding.opened", "", res.Opened); err != nil {
		return err
	}
	if err := send("finding.escalated", "esc:", res.Escalated); err != nil {
		return err
	}
	return send("finding.resolved", "resolved:", res.Resolved)
}

func notificationFor(org, event, label string, f store.Finding, at time.Time) store.Notification {
	return store.Notification{Event: event, OrgID: org, FindingID: f.ID, SubjectType: f.SubjectType, SubjectID: f.SubjectID,
		Subject: label, Check: f.Check, Severity: f.Severity, Message: f.Message, Remediation: f.Remediation, At: at.UTC()}
}

// JobKindCertSweep re-evaluates intrinsic checks (e.g. expiry) for imported
// certificates that are not observed on any endpoint.
const JobKindCertSweep = "certificate_sweep"

// RunCertSweep evaluates every non-CA certificate in the org.
func (s *Service) RunCertSweep(ctx context.Context, j jobs.Job) error {
	return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		if err := jobs.Fence(ctx, tx, j); err != nil {
			return err
		}
		now := s.now()
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		pol := pv.Document.Checks()
		var after string
		var afterNA time.Time
		for {
			certs, err := tx.ListCertificates(ctx, store.CertFilter{Limit: 500, AfterSHA256: after, AfterNotAfter: afterNA})
			if err != nil {
				return err
			}
			for _, c := range certs {
				res, err := tx.SyncFindings(ctx, "certificate", c.SHA256, checks.Certificate(c.Certificate, now, pol), now)
				if err != nil {
					return err
				}
				label := c.CommonName
				if label == "" && len(c.DNSNames) > 0 {
					label = c.DNSNames[0]
				}
				if err := notifySync(ctx, tx, label, res, now); err != nil {
					return err
				}
			}
			if len(certs) < 500 {
				break
			}
			last := certs[len(certs)-1]
			after, afterNA = last.SHA256, last.NotAfter
		}
		return jobs.Complete(ctx, tx, j)
	})
}

// ScheduleCertSweeps enqueues one sweep per org (deduplicated per hour).
func (s *Service) ScheduleCertSweeps(ctx context.Context) error {
	rows, err := s.DB.Pool.Query(ctx, `SELECT id FROM organizations`)
	if err != nil {
		return err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	slot := s.now().UTC().Truncate(time.Hour).Format(time.RFC3339)
	for _, org := range orgs {
		err := s.DB.WithoutOrg(ctx, func(tx pgx.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, org, JobKindCertSweep, org+":"+slot, struct{}{}, time.Time{})
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}
