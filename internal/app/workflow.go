package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/ari"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/privateca"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
)

// Job kinds used by renewals.
const (
	JobKindAdvance  = "workflow_advance"
	JobKindARICheck = "ari_check"
)

// Task lifetimes: an agent offline longer than this makes the step expire.
const (
	issueTaskTTL    = 2 * time.Hour
	deployTaskTTL   = 30 * time.Minute
	verifyTaskTTL   = 15 * time.Minute
	rollbackTaskTTL = 2 * time.Hour
	maxIssueAttempt = 3
)

const workflowActor = "system:workflow"

// ---------- issuers ----------

// CreateIssuer registers an issuer. For ACME, agreeing to the CA's terms of
// service is an explicit, audited owner decision. Vault and step-ca issuers
// need cred (ADR-0028), which is stored under the KEK and never returned.
func (s *Service) CreateIssuer(ctx context.Context, p authz.Principal, i *store.Issuer, cred secret.Value) error {
	if strings.TrimSpace(i.Name) == "" {
		return invalid("issuer name is required")
	}
	if i.Kind == "" {
		i.Kind = store.IssuerACME
	}
	if i.Kind == store.IssuerACME {
		u, err := url.Parse(i.DirectoryURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("directory_url must be an https URL")
		}
		if !i.AgreeTOS {
			return invalid("agree_tos must be true: you must accept the CA's terms of service to use it")
		}
		if !cred.IsEmpty() || i.CABundle != "" || i.Settings != (store.IssuerSettings{}) {
			return invalid("credential, ca_bundle and settings belong to vault and stepca issuers")
		}
	} else {
		if err := checkNativeIssuer(i, cred); err != nil {
			return err
		}
		if s.PKI == nil {
			return ErrAgentsDisabled
		}
	}
	return s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		i.ID = ids.New("iss")
		if !cred.IsEmpty() {
			var err error
			if i.CredentialCiphertext, err = s.PKI.KEK.Seal(cred.Reveal(), issuerCredentialAAD(i.ID)); err != nil {
				return err
			}
		}
		if err := tx.CreateIssuer(ctx, i, p.Actor); err != nil {
			return err
		}
		if err := storeBundle(ctx, tx, i.CABundle); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.create", "issuer", i.ID, map[string]any{"name": i.Name, "kind": i.Kind, "directory_url": i.DirectoryURL,
			"agree_tos": i.AgreeTOS, "profile": i.Profile, "settings": i.Settings, "credential": !cred.IsEmpty()})
	})
}

// ListIssuers lists issuers.
func (s *Service) ListIssuers(ctx context.Context, p authz.Principal) (out []store.Issuer, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListIssuers(ctx); return err })
	return out, err
}

// ---------- deployments ----------

// DeploymentInput describes a new deployment.
type DeploymentInput struct {
	Lineage, Agent, Target, Issuer, Endpoint string
	SANs                                     []string
	// Window is an optional maintenance window, e.g. "Mon-Fri 02:00-05:00 Europe/Athens".
	Window string
	// Emergency is "block" (default) or "renew_outside_window".
	Emergency string
	// Challenge is "http-01" (default) or "dns-01". Wildcard SANs need dns-01.
	Challenge string
	// Template names a certificate template (ADR-0020); it fixes the issuer
	// and challenge and checks the names.
	Template string
	// KeyAlgorithm defaults to the template's first, or ecdsa-p256.
	KeyAlgorithm string
}

// CreateDeployment binds a lineage to an agent target and issuer. SANs must
// be allowed by the target's locally configured allowlist (as last reported
// by the agent); the agent enforces the same list again (threat T12).
func (s *Service) CreateDeployment(ctx context.Context, p authz.Principal, in DeploymentInput) (*store.Deployment, error) {
	if len(in.SANs) == 0 {
		return nil, invalid("at least one SAN is required")
	}
	perm := authz.ManageDeployments
	if !p.Can(perm) {
		perm = authz.RequestDeployments
	}
	var d *store.Deployment
	err := s.tx(ctx, p, perm, func(tx *store.Tx) error {
		tpl, err := templateForDeployment(ctx, tx, &in)
		if err != nil {
			return err
		}
		if err := checkWindow(in.Window, in.Emergency); err != nil {
			return err
		}
		iss, err := tx.GetIssuer(ctx, in.Issuer)
		if err != nil {
			return invalid("issuer %q not found", in.Issuer)
		}
		native := iss.Native()
		switch {
		case native && (in.Challenge == "" || in.Challenge == agentproto.ChallengeNone || tpl != nil):
			// The control plane signs a CSR; there is no ACME challenge. A
			// template's challenge only applies to ACME issuers.
			in.Challenge = agentproto.ChallengeNone
		case native:
			return invalid("issuer %s signs CSRs (kind %s); challenge %s does not apply", iss.Name, iss.Kind, in.Challenge)
		case in.Challenge == "":
			in.Challenge = agentproto.ChallengeHTTP01
		case in.Challenge != agentproto.ChallengeHTTP01 && in.Challenge != agentproto.ChallengeDNS01:
			return invalid("challenge must be http-01 or dns-01")
		}
		if in.KeyAlgorithm == "" {
			in.KeyAlgorithm = agentproto.KeyECDSAP256
		}
		if in.KeyAlgorithm != agentproto.KeyECDSAP256 {
			return invalid("key algorithm must be %s", agentproto.KeyECDSAP256)
		}
		dns01 := in.Challenge == agentproto.ChallengeDNS01
		l, err := tx.LineageByRef(ctx, in.Lineage)
		if err != nil {
			return invalid("lineage %q not found", in.Lineage)
		}
		a, err := tx.GetAgent(ctx, in.Agent)
		if err != nil || a.State != "active" {
			return invalid("agent %q not found or not active", in.Agent)
		}
		var tgt *agentproto.Target
		for i := range a.Capabilities.Targets {
			if a.Capabilities.Targets[i].Name == in.Target {
				tgt = &a.Capabilities.Targets[i]
			}
		}
		if tgt == nil {
			return invalid("agent %q does not report a target named %q (check its config and that it has sent a heartbeat)", a.Name, in.Target)
		}
		if tgt.Type == agentproto.TargetPlugin && !a.Capabilities.HasPlugin(tgt.Plugin, agentproto.PluginKindDeployTarget) {
			return invalid("target %q uses plugin %q, which agent %q does not report as installed and trusted for deploy_target (see certloom agent plugins)", in.Target, tgt.Plugin, a.Name)
		}
		if native && !slices.Contains(a.Capabilities.Tasks, agentproto.TaskCSR) {
			return invalid("issuer %s needs agent %q to create CSRs (task %s), which it does not report: upgrade the agent or allow the task", iss.Name, a.Name, agentproto.TaskCSR)
		}
		if dns01 && len(a.Capabilities.DNSSolvers) == 0 {
			central, err := tx.ListDNSSolvers(ctx, a.ID)
			if err != nil {
				return err
			}
			if len(central) == 0 || !a.Capabilities.AcceptsCentralDNS() {
				return invalid("agent %q has no dns solver: configure dns_solvers on the host, or assign a central one (certloom dns-solver assign)", a.Name)
			}
		}
		for _, san := range in.SANs {
			if strings.HasPrefix(san, "*") && !dns01 && !native {
				return invalid("wildcard SAN %q needs challenge dns-01", san)
			}
			if !SANAllowed(san, tgt.AllowedSANs, dns01 || native) {
				return invalid("SAN %q is not in target %q's allowed_sans (a wildcard must be listed literally)", san, in.Target)
			}
		}
		d = &store.Deployment{LineageID: l.ID, AgentID: a.ID, Target: in.Target, IssuerID: iss.ID, SANs: in.SANs,
			MaintenanceWindow: normWindow(in.Window), WindowEmergency: in.Emergency, Challenge: in.Challenge}
		if in.Endpoint != "" {
			e, err := tx.GetEndpoint(ctx, in.Endpoint)
			if err != nil {
				return invalid("endpoint %q not found", in.Endpoint)
			}
			d.EndpointID = &e.ID
		}
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		if pv.Document.Spec.Templates.Required && tpl == nil {
			return invalid("policy templates.required: create the deployment from a template (--template)")
		}
		if tpl != nil {
			d.TemplateID = &tpl.ID
		}
		pending := approvalNeeded(p, pv.Document)
		// A pending deployment changes nothing else yet; the endpoint is bound
		// to the lineage when the deployment is approved.
		if d.EndpointID != nil && !pending {
			if err := tx.SetEndpointLineage(ctx, *d.EndpointID, &l.ID, nil); err != nil {
				return err
			}
		}
		d.KeyAlgorithm = in.KeyAlgorithm
		spec := store.BuildDeploymentSpec(d, iss, a)
		if pending {
			d.Approval = "pending"
		} else {
			digest := spec.SHA256()
			d.Approval, d.ApprovedSpecSHA256 = "approved", &digest
		}
		if err := tx.CreateDeployment(ctx, d, p.Actor); err != nil {
			return err
		}
		var approvalID string
		if pending {
			apr, err := s.requestApproval(ctx, tx, d, spec, p.Actor, pv.Document)
			if err != nil {
				return err
			}
			approvalID = apr.ID
		}
		if err := s.emit(ctx, tx, "deployment.created", d.ID, map[string]any{"deployment_id": d.ID, "lineage_id": l.ID, "agent_id": a.ID,
			"target": in.Target, "issuer_id": iss.ID, "sans": in.SANs, "challenge": d.Challenge, "template_id": d.TemplateID, "approval": d.Approval}); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "deployments.create", "deployment", d.ID, map[string]any{"lineage": l.ID, "agent": a.ID,
			"target": in.Target, "issuer": iss.ID, "sans": in.SANs, "endpoint": in.Endpoint, "maintenance_window": d.MaintenanceWindow,
			"window_emergency": d.WindowEmergency, "challenge": d.Challenge, "template": d.TemplateID, "approval": d.Approval, "approval_request": approvalID})
	})
	return d, err
}

// SANAllowed reports whether san may be requested for a target with the
// given allowlist; see agentproto.SANAllowed.
func SANAllowed(san string, allowed []string, wildcards bool) bool {
	return agentproto.SANAllowed(san, allowed, wildcards)
}

// ListDeployments lists deployments.
func (s *Service) ListDeployments(ctx context.Context, p authz.Principal) (out []*store.Deployment, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListDeployments(ctx); return err })
	return out, err
}

// ---------- runs ----------

// RequestRenewal starts a renewal run now.
func (s *Service) RequestRenewal(ctx context.Context, p authz.Principal, deploymentID string) (*store.Run, error) {
	var r *store.Run
	err := s.tx(ctx, p, authz.RunRenewals, func(tx *store.Tx) (err error) {
		r, err = s.startRun(ctx, tx, deploymentID, "manual", p.Actor)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "renewals.request", "run", r.ID, map[string]any{"deployment": deploymentID})
	})
	return r, err
}

func (s *Service) startRun(ctx context.Context, tx *store.Tx, deploymentID, reason, actor string) (*store.Run, error) {
	d, err := tx.GetDeployment(ctx, deploymentID, true)
	if err != nil {
		return nil, err
	}
	if !d.Enabled {
		return nil, invalid("deployment is disabled")
	}
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return nil, err
	}
	problem, digest, err := s.approvalProblem(ctx, tx, d, approvalsRequired(pv.Document), nil)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		return nil, invalid("%s", problem)
	}
	l, err := tx.LineageByRef(ctx, d.LineageID)
	if err != nil {
		return nil, err
	}
	r, err := tx.CreateRun(ctx, d.ID, reason, actor, l.CurrentSHA256, digest)
	if err != nil {
		if errors.Is(err, store.ErrRunActive) {
			return nil, fmt.Errorf("%w: %w", store.ErrConflict, err)
		}
		return nil, err
	}
	_, err = jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, r.ID, map[string]string{"run_id": r.ID}, time.Time{})
	return r, err
}

// ListRuns lists recent runs.
func (s *Service) ListRuns(ctx context.Context, p authz.Principal) (out []*store.Run, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListRuns(ctx, 100); return err })
	return out, err
}

// GetRun returns a run with its timeline.
func (s *Service) GetRun(ctx context.Context, p authz.Principal, id string) (r *store.Run, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { r, err = tx.GetRun(ctx, id, false); return err })
	return r, err
}

// CancelRun cancels a run that has not yet changed the target. Once the
// agent may have switched certificates, cancelling is refused: use the
// rollback path instead of leaving the target in an unknown state.
func (s *Service) CancelRun(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.RunRenewals, func(tx *store.Tx) error {
		r, err := tx.GetRun(ctx, id, true)
		if err != nil {
			return err
		}
		switch r.State {
		case store.RunPlanned, store.RunIssuing, store.RunSigning, store.RunIssued, store.RunRetryScheduled, store.RunWaitingWindow, store.RunBlocked:
		default:
			return invalid("cannot cancel a run in state %q", r.State)
		}
		r.State, r.Error = store.RunCancelled, "cancelled by "+p.Actor
		if err := tx.UpdateRun(ctx, r, r.Error); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "renewals.cancel", "run", id, nil)
	})
}

// ---------- scheduling ----------

// ScheduleRenewals starts runs for due deployments and enqueues ARI checks.
func (s *Service) ScheduleRenewals(ctx context.Context) (int, error) {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return 0, err
	}
	started := 0
	var errs []error
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			// Safety net: expire overdue tasks (an offline agent never polls to
			// expire them) and re-advance runs whose current task has finished.
			if err := s.expireApprovals(ctx, tx); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE agent_tasks SET state = 'expired', error = 'not completed before not_after'
				WHERE state IN ('pending','delivered') AND not_after <= now()`); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT r.id FROM workflow_runs r JOIN agent_tasks t ON t.id = r.current_task_id
				WHERE r.state NOT IN ('verified','failed','rolled_back','cancelled','retry_scheduled')
				  AND t.state IN ('succeeded','failed','expired') AND r.updated_at < now() - interval '30 seconds'`)
			if err != nil {
				return err
			}
			stuck, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			for _, id := range stuck {
				if _, err := jobs.Enqueue(ctx, tx, org, JobKindAdvance, id+":sweep", map[string]string{"run_id": id}, time.Time{}); err != nil {
					return err
				}
			}
			ds, err := tx.ListDeployments(ctx)
			if err != nil {
				return err
			}
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			required := approvalsRequired(pv.Document)
			now := s.now()
			for _, d := range ds {
				if !d.Enabled {
					continue
				}
				ariDue := d.ARINextAt == nil || !d.ARINextAt.After(now)
				renewDue := d.RenewAt != nil && !d.RenewAt.After(now)
				if !ariDue && !renewDue {
					continue
				}
				// Resolved only when something is due: it reads the issuer and agent.
				problem, _, err := s.approvalProblem(ctx, tx, d, required, nil)
				if err != nil {
					return err
				}
				if problem != "" {
					if renewDue {
						// Once a day, so a renewal that waits for approval is not missed.
						key := d.ID + ":blocked:" + now.UTC().Format(time.DateOnly)
						if err := s.notifyApproval(ctx, tx, pv.Document, d, "approval.blocking_renewal", key,
							"renewal is due but blocked: "+problem); err != nil {
							return err
						}
					}
					continue
				}
				if ariDue {
					if _, err := jobs.Enqueue(ctx, tx, org, JobKindARICheck, d.ID, map[string]string{"deployment_id": d.ID}, time.Time{}); err != nil {
						return err
					}
				}
				if !renewDue {
					continue
				}
				if _, err := tx.ActiveRunFor(ctx, d.ID); err == nil {
					continue
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
				if _, err := s.startRun(ctx, tx, d.ID, "scheduled: "+d.RenewReason, workflowActor); err != nil {
					return err
				}
				started++
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return started, errors.Join(errs...)
}

// RunARICheck computes the next renewal time for a deployment: ARI window if
// the CA offers one, otherwise the lifetime-based fallback.
func (s *Service) RunARICheck(ctx context.Context, j jobs.Job) error {
	var pl struct {
		DeploymentID string `json:"deployment_id"`
	}
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return err
	}
	var cert *x509.Certificate
	var checked *string // lineage certificate this check is for
	var dirURL string
	err := s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		d, err := tx.GetDeployment(ctx, pl.DeploymentID, false)
		if err != nil {
			return err
		}
		l, err := tx.LineageByRef(ctx, d.LineageID)
		if err != nil {
			return err
		}
		iss, err := tx.GetIssuer(ctx, d.IssuerID)
		if err != nil {
			return err
		}
		if !iss.Native() {
			dirURL = iss.DirectoryURL // only ACME has renewal information
		}
		checked = l.CurrentSHA256
		if l.CurrentSHA256 != nil {
			c, err := tx.GetCertificate(ctx, *l.CurrentSHA256)
			if err != nil {
				return err
			}
			cert = c.X509
		}
		return nil
	})
	if err != nil {
		return err
	}
	now := s.now()
	var at time.Time
	var reason string
	next := now.Add(24 * time.Hour)
	switch cert {
	case nil:
		at, reason = now, "no current certificate"
	default:
		client := s.ARI
		if client == nil {
			client = &ari.Client{}
		}
		w, ferr := func() (*ari.Window, error) {
			if dirURL == "" {
				return nil, errors.New("issuer has no ARI")
			}
			u, err := client.RenewalInfoURL(ctx, dirURL)
			if err != nil {
				return nil, err
			}
			return client.Fetch(ctx, u, cert)
		}()
		if ferr == nil {
			at = ari.ChooseTime(w, now, nil)
			reason = fmt.Sprintf("ARI window %s - %s", w.Start.UTC().Format(time.RFC3339), w.End.UTC().Format(time.RFC3339))
			next = now.Add(ari.ClampRetry(w.RetryAfter))
		} else {
			at = ari.Fallback(cert)
			reason = "fallback (2/3 of lifetime): " + truncate(ferr.Error(), 120)
		}
	}
	return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		if err := jobs.Fence(ctx, tx, j); err != nil {
			return err
		}
		// A renewal may have finished while the CA was asked. Its verify step
		// already made a new check due; never overwrite that with this result.
		d, err := tx.GetDeployment(ctx, pl.DeploymentID, true)
		if err != nil {
			return err
		}
		l, err := tx.LineageByRef(ctx, d.LineageID)
		if err != nil {
			return err
		}
		if !sameSHA(l.CurrentSHA256, checked) {
			return jobs.Complete(ctx, tx, j)
		}
		if err := tx.SetRenewal(ctx, pl.DeploymentID, at, reason, &next); err != nil {
			return err
		}
		return jobs.Complete(ctx, tx, j)
	})
}

func sameSHA(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------- the state machine ----------

// RunAdvance moves a run forward one or more steps. It is safe to call any
// number of times (at-least-once delivery): every transition is decided under
// a row lock on the run and is a no-op if the run is waiting on an agent.
func (s *Service) RunAdvance(ctx context.Context, j jobs.Job) error {
	var pl struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return err
	}
	// Phase 1 (no locks): external verification needs network I/O, which must
	// not happen inside a transaction.
	external, err := s.externalVerify(ctx, j.OrgID, pl.RunID)
	if err != nil {
		return err
	}
	if external.sign, err = s.externalSign(ctx, j.OrgID, pl.RunID); err != nil {
		return err
	}
	return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		if err := jobs.Fence(ctx, tx, j); err != nil {
			return err
		}
		if err := s.advance(ctx, tx, pl.RunID, external); err != nil {
			return err
		}
		return jobs.Complete(ctx, tx, j)
	})
}

// externalResult is the control plane's own probe of the deployment endpoint.
type externalResult struct {
	checked bool
	served  string
	err     string
	// sign is set when the run was signing and the issuer was called.
	sign *signResult
}

func (s *Service) externalVerify(ctx context.Context, org, runID string) (externalResult, error) {
	var ep *store.Endpoint
	var scope *probe.Scope
	needed := false
	err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		r, err := tx.GetRun(ctx, runID, false)
		if err != nil || r.State != store.RunVerifying {
			return err
		}
		d, err := tx.GetDeployment(ctx, r.DeploymentID, false)
		if err != nil || d.EndpointID == nil {
			return err
		}
		if ep, err = tx.GetEndpoint(ctx, *d.EndpointID); err != nil {
			return err
		}
		sc, err := tx.ScopeByRef(ctx, ep.ScopeID)
		if err != nil {
			return err
		}
		scope, err = sc.ToProbe()
		needed = true
		return err
	})
	if err != nil || !needed {
		return externalResult{}, err
	}
	o := s.Prober.Probe(ctx, scope, probe.Target{Host: ep.Host, Port: ep.Port, SNI: ep.SNI})
	if o.ErrorClass != "" {
		return externalResult{checked: true, err: o.ErrorClass + ": " + o.Error}, nil
	}
	return externalResult{checked: true, served: o.Leaf().SHA256}, nil
}

func (s *Service) advance(ctx context.Context, tx *store.Tx, runID string, ext externalResult) error {
	r, err := tx.GetRun(ctx, runID, true)
	if err != nil {
		return err
	}
	if store.Terminal(r.State) {
		return nil
	}
	d, err := tx.GetDeployment(ctx, r.DeploymentID, true)
	if err != nil {
		return err
	}
	agent, err := tx.GetAgent(ctx, d.AgentID)
	if err != nil {
		return err
	}
	if agent.State != "active" {
		return s.finish(ctx, tx, r, d, store.RunFailed, "agent was revoked; target state unknown if a deploy was in progress")
	}
	// Approval is checked again before every step that orders a certificate
	// or changes the target, not only when the run starts. A run issuing right
	// now finishes issuing, but its certificate is not deployed.
	switch r.State {
	case store.RunPlanned, store.RunRetryScheduled, store.RunIssued, store.RunWaitingWindow, store.RunBlocked:
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		problem, _, err := s.approvalProblem(ctx, tx, d, approvalsRequired(pv.Document), r.SpecSHA256)
		if err != nil {
			return err
		}
		if problem != "" {
			return s.finish(ctx, tx, r, d, store.RunCancelled, problem+"; the target was not changed")
		}
	}
	task := func() (*store.AgentTask, error) {
		if r.CurrentTaskID == nil {
			return nil, errors.New("run has no current task")
		}
		return tx.GetTask(ctx, *r.CurrentTaskID)
	}

	for range 6 { // bounded: each iteration performs at most one transition
		switch r.State {
		case store.RunPlanned:
			if err := s.sendIssue(ctx, tx, r, d); err != nil {
				return err
			}
		case store.RunRetryScheduled:
			// Tolerate small clock skew between this process and the database
			// (which decides when the retry job is claimable).
			if r.NextAttemptAt != nil && r.NextAttemptAt.After(s.now().Add(5*time.Second)) {
				// Not due yet: schedule a wake-up with a unique key, because a
				// job with the usual key may be the one executing right now and
				// would swallow the re-enqueue as a duplicate.
				_, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, fmt.Sprintf("%s:retry:%d", r.ID, s.now().UnixNano()),
					map[string]string{"run_id": r.ID}, *r.NextAttemptAt)
				return err
			}
			r.Attempt++
			if err := s.sendIssue(ctx, tx, r, d); err != nil {
				return err
			}
		case store.RunIssuing:
			t, err := task()
			if err != nil {
				return err
			}
			switch t.State {
			case "pending", "delivered":
				return nil // waiting for the agent
			case "succeeded":
				if t.Type == agentproto.TaskCSR {
					var out agentproto.CSROutput
					_ = json.Unmarshal(t.Result, &out)
					if _, err := privateca.CheckCSR(out.CSRPEM, d.SANs, d.KeyAlgorithm); err != nil {
						// Never sent to the CA. The agent made this CSR, so asking again would not help.
						return s.finish(ctx, tx, r, d, store.RunFailed, "agent CSR rejected: "+err.Error())
					}
					r.State = store.RunSigning
					if err := tx.UpdateRun(ctx, r, "CSR received and checked; signing with the issuer"); err != nil {
						return err
					}
					// The CA is called outside this transaction, by the next advance.
					_, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, fmt.Sprintf("%s:sign:%d", r.ID, r.Attempt),
						map[string]string{"run_id": r.ID}, time.Time{})
					return err
				}
				var out agentproto.IssueOutput
				_ = json.Unmarshal(t.Result, &out)
				if out.AccountSlot != "" {
					if err := s.eabRegistered(ctx, tx, d.AgentID, out.AccountSlot); err != nil {
						return err
					}
				}
				if err := s.recordIssued(ctx, tx, r, d, out.ChainPEM); err != nil {
					return err
				}
				if store.Terminal(r.State) {
					return nil
				}
			default: // failed or expired
				var out agentproto.IssueOutput
				_ = json.Unmarshal(t.Result, &out)
				if out.AccountSlot != "" {
					if err := s.eabRegistered(ctx, tx, d.AgentID, out.AccountSlot); err != nil {
						return err
					}
				}
				if out.EABRejected || out.ProblemType == "urn:ietf:params:acme:error:externalAccountRequired" {
					// Retrying with the same key would fail the same way.
					if err := s.eabRejected(ctx, tx, d.IssuerID, d.AgentID); err != nil {
						return err
					}
					return s.finish(ctx, tx, r, d, store.RunFailed, "the CA refused ACME account registration (External Account Binding): "+t.Error)
				}
				wait, detail, rateLimited := retryAfter(out)
				return s.retryIssue(ctx, tx, r, d, t.Error, wait, detail, rateLimited)
			}
		case store.RunSigning:
			if ext.sign == nil {
				return nil // the signing advance job is queued
			}
			if err := s.systemAudit(ctx, tx, workflowActor, "issuers.credential_used", "issuer", d.IssuerID,
				map[string]any{"run": r.ID, "ok": ext.sign.err == nil}); err != nil {
				return err
			}
			if err := ext.sign.err; err != nil {
				var ce *privateca.Error
				if errors.As(err, &ce) && ce.Permanent {
					return s.finish(ctx, tx, r, d, store.RunFailed, "the issuer refused to sign: "+err.Error())
				}
				var wait time.Duration
				detail := ""
				if ce != nil && ce.RetryAfter > 0 {
					wait, detail = ce.RetryAfter, " (rate limited)"
				}
				return s.retryIssue(ctx, tx, r, d, err.Error(), wait, detail, wait > 0)
			}
			if err := s.recordIssued(ctx, tx, r, d, ext.sign.chain); err != nil {
				return err
			}
			if store.Terminal(r.State) {
				return nil
			}
		case store.RunIssued, store.RunWaitingWindow, store.RunBlocked:
			if ok, err := s.windowGate(ctx, tx, r, d); err != nil || !ok {
				return err
			}
			c, err := tx.GetCertificate(ctx, *r.IssuedSHA256)
			if err != nil {
				return err
			}
			chain, err := s.chainPEM(ctx, tx, c)
			if err != nil {
				return err
			}
			if err := s.sendTask(ctx, tx, r, d, agentproto.TaskDeploy, agentproto.DeployPayload{RunID: r.ID, ChainPEM: chain}, deployTaskTTL,
				store.RunDeploying, "deploy task sent to agent"); err != nil {
				return err
			}
		case store.RunDeploying:
			t, err := task()
			if err != nil {
				return err
			}
			switch t.State {
			case "pending", "delivered":
				return nil
			case "succeeded":
				if err := s.sendTask(ctx, tx, r, d, agentproto.TaskVerify, agentproto.VerifyPayload{ExpectedSHA256: *r.IssuedSHA256, SNI: verifySNI(d.SANs), RunID: r.ID},
					verifyTaskTTL, store.RunVerifying, "activated on target; verifying"); err != nil {
					return err
				}
			default:
				var out agentproto.DeployOutput
				_ = json.Unmarshal(t.Result, &out)
				if out.RolledBack {
					return s.finish(ctx, tx, r, d, store.RunRolledBack, "activation failed and the agent restored the previous certificate: "+t.Error)
				}
				return s.startRollback(ctx, tx, r, d, "activation failed or did not report back: "+firstNonEmpty(t.Error, t.State))
			}
		case store.RunVerifying:
			t, err := task()
			if err != nil {
				return err
			}
			switch t.State {
			case "pending", "delivered":
				return nil
			case "succeeded":
				var out agentproto.VerifyOutput
				_ = json.Unmarshal(t.Result, &out)
				if !out.Match {
					return s.startRollback(ctx, tx, r, d, "local verification: target serves "+short(out.ServedSHA256)+", expected "+short(*r.IssuedSHA256))
				}
				if ext.checked && ext.served != *r.IssuedSHA256 {
					why := "external verification: endpoint serves " + short(ext.served)
					if ext.err != "" {
						why = "external verification failed: " + ext.err
					}
					return s.startRollback(ctx, tx, r, d, why+", expected "+short(*r.IssuedSHA256))
				}
				detail := "verified locally by the agent"
				if ext.checked {
					detail += " and externally by the control plane"
				}
				return s.complete(ctx, tx, r, d, detail)
			default:
				return s.startRollback(ctx, tx, r, d, "local verification did not complete: "+firstNonEmpty(t.Error, t.State))
			}
		case store.RunRollingBack:
			t, err := task()
			if err != nil {
				return err
			}
			switch t.State {
			case "pending", "delivered":
				return nil
			case "succeeded":
				return s.finish(ctx, tx, r, d, store.RunRolledBack, r.Error)
			default:
				return s.finish(ctx, tx, r, d, store.RunFailed, "ROLLBACK FAILED, manual intervention required: "+t.Error+" (original problem: "+r.Error+")")
			}
		default:
			return nil
		}
	}
	return nil
}

// maxRetryAfter bounds how long a CA's Retry-After can park a run.
const maxRetryAfter = 7 * 24 * time.Hour

// retryAfter reads the CA's rate-limit answer from a failed issue result.
func retryAfter(out agentproto.IssueOutput) (wait time.Duration, detail string, rateLimited bool) {
	if out.ProblemType != "urn:ietf:params:acme:error:rateLimited" {
		return 0, "", false
	}
	wait = min(time.Duration(out.RetryAfterSeconds)*time.Second, maxRetryAfter)
	if out.RetryAfterSeconds > 0 {
		return wait, fmt.Sprintf(" (rate limited by the CA, Retry-After %s)", wait), true
	}
	// No Retry-After: treat it like any other failure (normal backoff and attempt limit).
	return 0, " (rate limited by the CA)", false
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	if s == "" {
		return "(nothing)"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Service) sendIssue(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment) error {
	iss, err := tx.GetIssuer(ctx, d.IssuerID)
	if err != nil {
		return err
	}
	if iss.Native() {
		return s.sendTask(ctx, tx, r, d, agentproto.TaskCSR, agentproto.CSRPayload{RunID: r.ID, SANs: d.SANs, KeyAlgorithm: d.KeyAlgorithm},
			issueTaskTTL, store.RunIssuing, fmt.Sprintf("CSR task sent to agent (attempt %d)", r.Attempt))
	}
	p := agentproto.IssuePayload{RunID: r.ID, DirectoryURL: iss.DirectoryURL, Email: iss.Email, AgreeTOS: iss.AgreeTOS, Profile: iss.Profile, SANs: d.SANs,
		KeyAlgorithm: d.KeyAlgorithm, Challenge: d.Challenge}
	if r.PreviousSHA256 != nil {
		if c, err := tx.GetCertificate(ctx, *r.PreviousSHA256); err == nil {
			if id, err := ari.CertID(c.X509); err == nil {
				p.ReplacesCertID = id // RFC 9773 "replaces"
			}
		}
	}
	a, err := tx.GetAgent(ctx, d.AgentID)
	if err != nil {
		return err
	}
	var eab *eabPlan
	if iss.EABMode != store.EABNone {
		p.AccountSlot = agentproto.AccountSlot(iss.ID)
		var why string
		if eab, why, err = s.planEAB(ctx, tx, iss, a); err != nil {
			return err
		}
		if why != "" {
			return s.finish(ctx, tx, r, d, store.RunFailed, why)
		}
	}
	dns01 := d.Challenge == agentproto.ChallengeDNS01
	var payload any = p
	if dns01 || eab != nil {
		payload = taskBound(func(taskID string) (any, error) {
			var err error
			if dns01 {
				if p.DNSSolvers, err = s.centralSolversFor(ctx, tx, a, r.ID, taskID); err != nil {
					return nil, err
				}
			}
			if eab != nil {
				p.EAB, err = s.sealEAB(ctx, tx, eab, a, r.ID, taskID)
			}
			return p, err
		})
	}
	return s.sendTask(ctx, tx, r, d, agentproto.TaskIssue, payload, issueTaskTTL, store.RunIssuing,
		fmt.Sprintf("issue task sent to agent (attempt %d)", r.Attempt))
}

// taskBound builds a payload that depends on the task id, such as secrets
// sealed to one task.
type taskBound func(taskID string) (any, error)

func (s *Service) sendTask(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, typ string, payload any,
	ttl time.Duration, next, detail string) error {
	seq, err := tx.NextTargetSeq(ctx, d.ID)
	if err != nil {
		return err
	}
	bound, _ := payload.(taskBound)
	if bound != nil {
		payload = struct{}{}
	}
	t, err := s.signTask(tx.OrgID, d.AgentID, typ, d.Target, seq, payload, ttl)
	if err != nil {
		return err
	}
	if bound != nil {
		p, err := bound(t.ID)
		if err != nil {
			return err
		}
		if t.Payload, err = json.Marshal(p); err != nil {
			return err
		}
	}
	env, err := agentproto.Sign(s.PKI.TaskKey, t)
	if err != nil {
		return err
	}
	if err := tx.InsertTask(ctx, t, env, &r.ID); err != nil {
		return err
	}
	r.State, r.CurrentTaskID = next, &t.ID
	return tx.UpdateRun(ctx, r, detail)
}

func (s *Service) startRollback(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, why string) error {
	r.Error = why
	if err := s.sendTask(ctx, tx, r, d, agentproto.TaskRollback, agentproto.RollbackPayload{RunID: r.ID}, rollbackTaskTTL,
		store.RunRollingBack, "rolling back: "+why); err != nil {
		return err
	}
	return s.notifyRun(ctx, tx, r, "renewal.rolling_back", "warning", why)
}

// recordIssued checks and stores an issued chain and moves the run to
// issued. A chain that fails the checks fails the run instead.
func (s *Service) recordIssued(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, chainPEM string) error {
	leaf, err := s.acceptIssued(ctx, tx, d, chainPEM)
	if err != nil {
		// A bad certificate is never deployed. Retrying would order again.
		return s.finish(ctx, tx, r, d, store.RunFailed, "issued certificate rejected: "+err.Error())
	}
	r.IssuedSHA256, r.State, r.CurrentTaskID = &leaf, store.RunIssued, nil
	if err := tx.UpdateRun(ctx, r, "certificate "+leaf[:16]+" issued and recorded (checkpoint)"); err != nil {
		return err
	}
	if err := s.systemAudit(ctx, tx, workflowActor, "renewals.issued", "run", r.ID, map[string]any{"sha256": leaf}); err != nil {
		return err
	}
	return s.emit(ctx, tx, "certificate.issued", r.ID, map[string]any{"sha256": leaf, "run_id": r.ID, "deployment_id": d.ID,
		"lineage_id": d.LineageID, "issuer_id": d.IssuerID, "sans": d.SANs})
}

// retryIssue schedules another issuance attempt, or fails the run once the
// attempts are used up. A CA's own wait (rateLimited) costs no attempt.
func (s *Service) retryIssue(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, why string,
	wait time.Duration, detail string, rateLimited bool) error {
	if r.Attempt >= maxIssueAttempt && !rateLimited {
		return s.finish(ctx, tx, r, d, store.RunFailed, fmt.Sprintf("issuance failed after %d attempts: %s", r.Attempt, why))
	}
	if rateLimited {
		r.Attempt--
	}
	next := s.now().Add(max(wait, jobs.Backoff(r.Attempt, 2*time.Minute, time.Hour)))
	r.State, r.NextAttemptAt, r.CurrentTaskID, r.Error = store.RunRetryScheduled, &next, nil, why
	if err := tx.UpdateRun(ctx, r, "issuance attempt failed"+detail+"; retry at "+next.UTC().Format(time.RFC3339)+": "+why); err != nil {
		return err
	}
	if rateLimited {
		if err := s.notifyRun(ctx, tx, r, "renewal.rate_limited", "warning", "the CA rate-limited issuance; next attempt at "+next.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	_, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, r.ID+":retry", map[string]string{"run_id": r.ID}, next)
	return err
}

// acceptIssued validates the returned chain before anything is deployed:
// it must parse, be a leaf, be currently valid, and cover exactly the SANs
// requested. The leaf and chain are stored; the SHA-256 is returned.
func (s *Service) acceptIssued(ctx context.Context, tx *store.Tx, d *store.Deployment, chainPEM string) (string, error) {
	parsed, err := certparse.Parse([]byte(chainPEM), secret.Value{})
	if err != nil {
		return "", err
	}
	leaf := parsed.Certificates[0]
	if leaf.IsCA {
		return "", errors.New("first certificate in chain is a CA")
	}
	now := s.now()
	if now.Before(leaf.NotBefore.Add(-5*time.Minute)) || !now.Before(leaf.NotAfter) {
		return "", errors.New("certificate is not currently valid")
	}
	got := append([]string(nil), leaf.DNSNames...)
	want := append([]string(nil), d.SANs...)
	slices.Sort(got)
	slices.Sort(want)
	for i := range want {
		want[i] = strings.ToLower(want[i])
	}
	if !slices.Equal(got, want) {
		return "", fmt.Errorf("certificate SANs %v do not match requested %v", got, want)
	}
	for _, c := range parsed.Certificates {
		if _, err := tx.UpsertCertificate(ctx, c, "issued"); err != nil {
			return "", err
		}
	}
	return leaf.SHA256, nil
}

// chainPEM rebuilds leaf + intermediates from the inventory.
func (s *Service) chainPEM(ctx context.Context, tx *store.Tx, leaf *store.CertificateRow) (string, error) {
	var b strings.Builder
	b.WriteString(string(pemEncode(leaf.DER)))
	inters, err := tx.KnownIntermediates(ctx)
	if err != nil {
		return "", err
	}
	cur := leaf.X509
	for range 5 {
		var next *x509.Certificate
		for _, c := range inters {
			if string(c.RawSubject) == string(cur.RawIssuer) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		b.WriteString(string(pemEncode(next.Raw)))
		cur = next
	}
	return b.String(), nil
}

func (s *Service) complete(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, detail string) error {
	if err := tx.SetLineageCurrent(ctx, d.LineageID, *r.IssuedSHA256, "renewal "+r.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE lineages SET management_level = 'verified' WHERE id = $1`, d.LineageID); err != nil {
		return err
	}
	c, err := tx.GetCertificate(ctx, *r.IssuedSHA256)
	if err != nil {
		return err
	}
	// Next renewal: fallback now; the ARI check (due immediately) refines it.
	now := s.now()
	if err := tx.SetRenewal(ctx, d.ID, ari.Fallback(c.X509), "fallback (2/3 of lifetime) until ARI is checked", &now); err != nil {
		return err
	}
	if d.EndpointID != nil {
		if err := tx.ProbeNow(ctx, *d.EndpointID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	r.State, r.CurrentTaskID, r.Error = store.RunVerified, nil, ""
	if err := tx.UpdateRun(ctx, r, detail); err != nil {
		return err
	}
	if err := s.systemAudit(ctx, tx, workflowActor, "renewals.verified", "run", r.ID, map[string]any{"sha256": *r.IssuedSHA256, "deployment": d.ID}); err != nil {
		return err
	}
	return s.notifyRun(ctx, tx, r, "renewal.verified", "info", detail)
}

func (s *Service) finish(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment, state, why string) error {
	r.State, r.Error, r.CurrentTaskID = state, why, nil
	if err := tx.UpdateRun(ctx, r, why); err != nil {
		return err
	}
	// Try again later rather than never: the scheduler retries after a delay.
	retry := s.now().Add(6 * time.Hour)
	if err := tx.SetRenewal(ctx, d.ID, retry, "retry after "+state+" run "+r.ID, nil); err != nil {
		return err
	}
	if err := s.systemAudit(ctx, tx, workflowActor, "renewals."+state, "run", r.ID, map[string]any{"reason": why}); err != nil {
		return err
	}
	return s.notifyRun(ctx, tx, r, "renewal."+state, "critical", why)
}

func (s *Service) notifyRun(ctx context.Context, tx *store.Tx, r *store.Run, event, severity, msg string) error {
	n := store.Notification{Event: event, OrgID: tx.OrgID, SubjectType: "run", SubjectID: r.ID, Subject: "renewal " + r.ID,
		Severity: severity, Message: msg, At: s.now().UTC()}
	if severity == "info" {
		n.Severity = "warning" // deliver success notices to channels at the default threshold
	}
	return tx.EnqueueNotification(ctx, n, r.ID+":"+event)
}

// verifySNI picks the server name for the local verification handshake: the
// first SAN that is a real host name, or else a name the wildcard covers.
func verifySNI(sans []string) string {
	for _, s := range sans {
		if !strings.HasPrefix(s, "*.") {
			return s
		}
	}
	return "certloom-verify." + strings.TrimPrefix(sans[0], "*.")
}
