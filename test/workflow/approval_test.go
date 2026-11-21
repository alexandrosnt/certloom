package workflow

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/store"
)

const requireApprovals = `apiVersion: certloom/v1
kind: MonitoringPolicy
spec:
  approvals:
    deployments: required
    expireAfter: 2h
`

// approvalEnv replaces the env's deployment with one created under a policy
// that requires approval, and returns the pending deployment and request.
func approvalEnv(t *testing.T) (*env, *store.Deployment, *store.Approval) {
	t.Helper()
	e := newEnv(t)
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(requireApprovals), false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `DELETE FROM deployments`); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www",
		Issuer: "fake", SANs: []string{"www.wf.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Approval != "pending" {
		t.Fatalf("approval = %q, want pending", d.Approval)
	}
	as, err := e.svc.ListApprovals(ctx, e.owner, store.ApprovalRequested)
	if err != nil || len(as) != 1 || as[0].ResourceID != d.ID || as[0].RequestedBy != e.owner.Actor {
		t.Fatalf("open requests: %+v %v", as, err)
	}
	return e, d, as[0]
}

func (e *env) principal(actor, role string) authz.Principal {
	return authz.Principal{OrgID: e.owner.OrgID, Actor: actor, Role: role}
}

func TestPendingDeploymentDoesNotRenew(t *testing.T) {
	e, d, _ := approvalEnv(t)
	if _, err := e.svc.RequestRenewal(ctx, e.owner, d.ID); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("manual renewal of a pending deployment: %v", err)
	}
	// Even when due, the scheduler leaves it alone.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET renew_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.ScheduleRenewals(ctx); err != nil || n != 0 {
		t.Fatalf("scheduler started %d runs (%v)", n, err)
	}
}

func TestApprovalSeparationOfDuties(t *testing.T) {
	e, d, a := approvalEnv(t)
	approver := e.principal("user:approver@wf.test", store.RoleApprover)

	// The requester cannot approve, even as owner.
	if _, err := e.svc.DecideApproval(ctx, e.owner, a.ID, true, ""); !errors.Is(err, app.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	// API tokens never decide.
	if _, err := e.svc.DecideApproval(ctx, e.principal("token:tok_x", store.RoleOwner), a.ID, true, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("token approval: %v", err)
	}
	// Roles without approvals:decide cannot either.
	if _, err := e.svc.DecideApproval(ctx, e.principal("user:op@wf.test", store.RoleDeploymentOperator), a.ID, true, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator approval: %v", err)
	}
	// Denying needs a reason.
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, false, " "); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("deny without reason: %v", err)
	}

	got, err := e.svc.DecideApproval(ctx, approver, a.ID, true, "change ticket 42")
	if err != nil || got.State != store.ApprovalApproved {
		t.Fatalf("approve: %+v %v", got, err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, false, "too late"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second decision: %v", err)
	}
	ds, _ := e.svc.ListDeployments(ctx, e.owner)
	if ds[0].Approval != "approved" || ds[0].ApprovedSpecSHA256 == nil || *ds[0].ApprovedSpecSHA256 != a.SpecSHA256 {
		t.Fatalf("deployment after approval: %+v", ds[0])
	}
	run, err := e.svc.RequestRenewal(ctx, e.owner, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.pump(run.ID); r.State != store.RunVerified {
		t.Fatalf("run after approval: %s %q", r.State, r.Error)
	}
	var actions string
	_ = e.db.Owner.QueryRow(ctx, `SELECT string_agg(action, ',' ORDER BY seq) FROM audit_events WHERE action LIKE 'approvals.%'`).Scan(&actions)
	if actions != "approvals.approve" {
		t.Fatalf("audit: %q", actions)
	}
}

// A request made through an API token cannot be approved by the person who
// created that token.
func TestApprovalRefusedForTokenCreator(t *testing.T) {
	e, _, _ := approvalEnv(t)
	if _, err := e.db.Owner.Exec(ctx, `DELETE FROM approvals; DELETE FROM deployments`); err != nil {
		t.Fatal(err)
	}
	alice := e.principal("user:alice@wf.test", store.RoleOwner)
	tok, _, err := e.svc.CreateToken(ctx, alice, "ci", store.RoleRequester, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requester := e.principal("token:"+tok.ID, store.RoleRequester)
	d, err := e.svc.CreateDeployment(ctx, requester, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www",
		Issuer: "fake", SANs: []string{"www.wf.test"}})
	if err != nil || d.Approval != "pending" {
		t.Fatalf("requester create: %+v %v", d, err)
	}
	as, _ := e.svc.ListApprovals(ctx, e.owner, store.ApprovalRequested)
	if _, err := e.svc.DecideApproval(ctx, alice, as[0].ID, true, ""); !errors.Is(err, app.ErrSelfApproval) {
		t.Fatalf("token creator approval: %v", err)
	}
	if _, err := e.svc.DecideApproval(ctx, e.owner, as[0].ID, true, ""); err != nil {
		t.Fatalf("someone else approves: %v", err)
	}
	// Approver tokens cannot be minted at all.
	if _, _, err := e.svc.CreateToken(ctx, alice, "bot", store.RoleApprover, time.Hour); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("approver token: %v", err)
	}
}

// The approval covers the exact spec. If the deployment changes, the old
// approval no longer counts: no new run starts and a planned one is cancelled
// before anything is ordered.
func TestApprovalBoundToSpec(t *testing.T) {
	e, d, a := approvalEnv(t)
	approver := e.principal("user:approver@wf.test", store.RoleApprover)

	// Changed before the decision: cannot be approved.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET sans = ARRAY['www.wf.test','other.wf.test']`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, true, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("approve changed spec: %v", err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET sans = ARRAY['WWW.wf.test.']`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, true, ""); err != nil {
		t.Fatalf("approve after reverting (case and trailing dot do not matter): %v", err)
	}

	// Changed after approval, while a run is planned.
	run, err := e.svc.RequestRenewal(ctx, e.owner, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET sans = ARRAY['evil.wf.test']`); err != nil {
		t.Fatal(err)
	}
	r := e.pump(run.ID)
	if r.State != store.RunCancelled || !strings.Contains(r.Error, "target was not changed") || e.issueCalls.Load() != 0 {
		t.Fatalf("run: %s %q, issue calls %d", r.State, r.Error, e.issueCalls.Load())
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, d.ID); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("renewal after spec change: %v", err)
	}
	// A new request for the new spec can be opened.
	if _, err := e.svc.RequestDeploymentApproval(ctx, e.owner, d.ID); err != nil {
		t.Fatalf("re-request: %v", err)
	}
}

func TestDeniedAndExpiredRequests(t *testing.T) {
	e, d, a := approvalEnv(t)
	approver := e.principal("user:approver@wf.test", store.RoleApprover)
	if _, err := e.svc.RequestDeploymentApproval(ctx, e.owner, d.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second open request: %v", err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, false, "wrong issuer"); err != nil {
		t.Fatal(err)
	}
	ds, _ := e.svc.ListDeployments(ctx, e.owner)
	if ds[0].Approval != "denied" {
		t.Fatalf("approval after deny: %q", ds[0].Approval)
	}

	// Re-request, let it expire.
	a2, err := e.svc.RequestDeploymentApproval(ctx, e.owner, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = $1`, a2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a2.ID, true, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("approve expired: %v", err)
	}
	if _, err := e.svc.ScheduleRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.GetApproval(ctx, e.owner, a2.ID)
	if got.State != store.ApprovalExpired {
		t.Fatalf("state after sweep: %s", got.State)
	}
}

// With approvals optional, owners and deployment operators still create
// deployments directly, but requesters always go through approval.
func TestRequesterNeedsApprovalEvenWhenOptional(t *testing.T) {
	e := newEnv(t)
	if e.dep.Approval != "approved" || e.dep.ApprovedSpecSHA256 == nil {
		t.Fatalf("owner deployment: %+v", e.dep)
	}
	if _, err := e.db.Owner.Exec(ctx, `DELETE FROM deployments`); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.CreateDeployment(ctx, e.principal("user:req@wf.test", store.RoleRequester), app.DeploymentInput{Lineage: "www",
		Agent: "web-01", Target: "www", Issuer: "fake", SANs: []string{"www.wf.test"}})
	if err != nil || d.Approval != "pending" {
		t.Fatalf("requester create: %+v %v", d, err)
	}
	if _, err := e.svc.CreateDeployment(ctx, e.principal("user:v@wf.test", store.RoleViewer), app.DeploymentInput{SANs: []string{"www.wf.test"}}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer create: %v", err)
	}
}

// Editing a referenced record (here the issuer's directory URL) voids the
// approval just like editing the deployment.
func TestIssuerChangeVoidsApproval(t *testing.T) {
	e, d, a := approvalEnv(t)
	approver := e.principal("user:approver@wf.test", store.RoleApprover)
	if _, err := e.db.Owner.Exec(ctx, `UPDATE issuers SET directory_url = 'https://other-ca.invalid/dir'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, true, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("approve after issuer change: %v", err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE issuers SET directory_url = 'https://acme.invalid/dir'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, approver, a.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE issuers SET profile = 'shortlived'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, d.ID); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "changed since it was approved") {
		t.Fatalf("renewal after profile change: %v", err)
	}
}

// A run that has issued but not deployed yet (waiting for its window) is
// cancelled when the approval is revoked or the spec changes, and the
// target is never touched.
func TestRevokeOrChangeStopsRunBeforeDeploy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(e *env, d *store.Deployment)
		want   string
	}{
		{"revoke", func(e *env, d *store.Deployment) {
			approver := e.principal("user:approver@wf.test", store.RoleApprover)
			if _, err := e.svc.RevokeDeploymentApproval(ctx, approver, d.ID, " "); !errors.Is(err, app.ErrInvalid) {
				t.Fatalf("revoke without reason: %v", err)
			}
			if _, err := e.svc.RevokeDeploymentApproval(ctx, e.principal("user:op@wf.test", store.RoleDeploymentOperator), d.ID, "x"); !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("operator revoke: %v", err)
			}
			if _, err := e.svc.RevokeDeploymentApproval(ctx, approver, d.ID, "incident 7"); err != nil {
				t.Fatal(err)
			}
		}, "approval: revoked"},
		{"agent target type", func(e *env, _ *store.Deployment) {
			if _, err := e.db.Owner.Exec(ctx, `UPDATE agents SET capabilities = jsonb_set(capabilities, '{targets,0,type}', '"apache"')`); err != nil {
				t.Fatal(err)
			}
		}, "changed since it was approved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, d, a := approvalEnv(t)
			if _, err := e.svc.DecideApproval(ctx, e.principal("user:approver@wf.test", store.RoleApprover), a.ID, true, ""); err != nil {
				t.Fatal(err)
			}
			window, _ := windowInTwoDays()
			if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, d.ID, window, ""); err != nil {
				t.Fatal(err)
			}
			run, err := e.svc.RequestRenewal(ctx, e.owner, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			e.step(4)
			if r, _ := e.svc.GetRun(ctx, e.owner, run.ID); r.State != store.RunWaitingWindow || r.SpecSHA256 == nil || *r.SpecSHA256 != a.SpecSHA256 {
				t.Fatalf("setup: %s spec %v", r.State, r.SpecSHA256)
			}
			tc.change(e, d)
			e.svc.Now = func() time.Time { return time.Now().AddDate(0, 0, 3) } // window would be open
			r := e.pump(run.ID)
			if r.State != store.RunCancelled || !strings.Contains(r.Error, tc.want) || strings.Contains(steps(r), "deploying") {
				t.Fatalf("run: %s %q (%s)", r.State, r.Error, steps(r))
			}
		})
	}
}

// Deployments from before approvals existed keep renewing while approvals
// are optional, but need an explicit approval once they are required.
func TestLegacyDeploymentNeedsApprovalWhenRequired(t *testing.T) {
	e := newEnv(t)
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET approved_spec_sha256 = NULL`); err != nil {
		t.Fatal(err)
	}
	run, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	if err != nil {
		t.Fatalf("legacy deployment, approvals optional: %v", err)
	}
	if r := e.pump(run.ID); r.State != store.RunVerified {
		t.Fatalf("legacy run: %s %q", r.State, r.Error)
	}
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(requireApprovals), false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "never been approved") {
		t.Fatalf("legacy deployment, approvals required: %v", err)
	}
	// A due renewal that is blocked raises a notification instead of
	// silently waiting.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET renew_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CreateChannel(ctx, e.owner, webhook("all")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if n, err := e.svc.ScheduleRenewals(ctx); err != nil || n != 0 {
			t.Fatalf("scheduler: %d %v", n, err)
		}
	}
	var blocked int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE payload->>'event' = 'approval.blocking_renewal'`).Scan(&blocked)
	if blocked != 1 {
		t.Fatalf("blocked-renewal notifications: %d, want 1 per day", blocked)
	}
	a, err := e.svc.RequestDeploymentApproval(ctx, e.owner, e.dep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DecideApproval(ctx, e.principal("user:approver@wf.test", store.RoleApprover), a.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID); err != nil {
		t.Fatalf("after explicit approval: %v", err)
	}
}

// approvals.channels routes approval events to the named channels only.
func TestApprovalChannels(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"approvers", "oncall"} {
		if err := e.svc.CreateChannel(ctx, e.owner, webhook(name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(requireApprovals+"    channels: [approvers]\n"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `DELETE FROM deployments`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www",
		Issuer: "fake", SANs: []string{"www.wf.test"}}); err != nil {
		t.Fatal(err)
	}
	var got string
	_ = e.db.Owner.QueryRow(ctx, `SELECT string_agg(c.name, ',') FROM outbox o JOIN notification_channels c ON c.id = o.channel_id
		WHERE o.payload->>'event' = 'approval.requested'`).Scan(&got)
	if got != "approvers" {
		t.Fatalf("approval.requested went to %q, want approvers only", got)
	}
}

func webhook(name string) *store.Channel {
	return &store.Channel{Name: name, Kind: "webhook", Config: []byte(`{"url":"https://hooks.example.test/` + name + `"}`), MinSeverity: "info", Enabled: true}
}
