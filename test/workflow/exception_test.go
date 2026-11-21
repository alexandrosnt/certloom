package workflow

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/store"
)

const excSubject = "cert-legacy-appliance"

// syncWeakKey records the subject's weak_key finding as a probe or sweep
// would; fp stands for the condition (which key).
func (e *env) syncWeakKey(sev checks.Severity, fp string) *store.SyncResult {
	e.t.Helper()
	var fs []checks.Finding
	if sev != "" {
		fs = []checks.Finding{{Check: checks.CheckWeakKey, Severity: sev, Message: "RSA 1024", Fingerprint: fp}}
	}
	var res *store.SyncResult
	err := e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) (err error) {
		res, err = tx.SyncFindings(ctx, "certificate", excSubject, fs, time.Now())
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// alertState is the alert's state as every reader sees it.
func (e *env) alertState() string {
	as, err := e.svc.ListAlerts(ctx, e.owner, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, a := range as {
		if a.Finding.SubjectID == excSubject && a.State != "resolved" {
			return a.State
		}
	}
	return ""
}

func (e *env) outboxCount(event string) int {
	var n int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE payload->>'event' = $1`, event).Scan(&n)
	return n
}

func weakKeyInput() app.ExceptionInput {
	due := time.Now().AddDate(0, 0, 60)
	return app.ExceptionInput{SubjectType: "certificate", SubjectID: excSubject, Check: checks.CheckWeakKey,
		Rationale: "appliance cannot do RSA 2048 until firmware 9", CompensatingControls: "only reachable from the admin VLAN",
		RiskOwner: "Head of IT", RemediationOwner: "network team", RemediationDue: &due, TrackingRef: "CHG-1234",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
}

var (
	operatorP = func(e *env) authz.Principal { return e.principal("user:op@wf.test", store.RoleOperator) }
	approverP = func(e *env) authz.Principal { return e.principal("user:approver@wf.test", store.RoleApprover) }
)

// requestWeakKeyException opens a warning finding and a pending exception.
func requestWeakKeyException(t *testing.T) (*env, *store.Exception, *store.Approval) {
	t.Helper()
	e := newEnv(t)
	if err := e.svc.CreateChannel(ctx, e.owner, webhook("all")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.RequestException(ctx, operatorP(e), weakKeyInput()); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "no open") {
		t.Fatalf("exception without a finding: %v", err)
	}
	e.syncWeakKey(checks.Warning, "key-A")
	exc, apr, err := e.svc.RequestException(ctx, operatorP(e), weakKeyInput())
	if err != nil || exc.State != store.ExceptionRequested || apr.ResourceType != "exception" {
		t.Fatalf("request: %+v %+v %v", exc, apr, err)
	}
	if exc.MaxSeverity != "warning" || exc.Fingerprint == "" || exc.CheckVersion != 1 || len(exc.Evidence) == 0 {
		t.Fatalf("exception must record the condition as seen: %+v", exc)
	}
	if e.alertState() != "open" {
		t.Fatal("a requested exception must not suppress anything")
	}
	return e, exc, apr
}

func approve(t *testing.T, e *env, apr *store.Approval) {
	t.Helper()
	if _, err := e.svc.DecideApproval(ctx, approverP(e), apr.ID, true, "risk owner agreed"); err != nil {
		t.Fatal(err)
	}
}

func TestExceptionRequestValidation(t *testing.T) {
	e, _, _ := requestWeakKeyException(t)
	base := weakKeyInput()
	for name, mod := range map[string]func(*app.ExceptionInput){
		"no rationale":    func(in *app.ExceptionInput) { in.Rationale = " " },
		"no risk owner":   func(in *app.ExceptionInput) { in.RiskOwner = "" },
		"too long":        func(in *app.ExceptionInput) { in.ExpiresAt = time.Now().Add(91 * 24 * time.Hour) },
		"too short":       func(in *app.ExceptionInput) { in.ExpiresAt = time.Now().Add(30 * time.Minute) },
		"unknown check":   func(in *app.ExceptionInput) { in.Check = "nope" },
		"remediation due": func(in *app.ExceptionInput) { d := time.Now().AddDate(0, 0, -3); in.RemediationDue = &d },
	} {
		in := base
		mod(&in)
		if _, _, err := e.svc.RequestException(ctx, operatorP(e), in); !errors.Is(err, app.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := e.svc.RequestException(ctx, operatorP(e), base); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second live request: %v", err)
	}
}

// Who may request, approve and revoke, including through API tokens.
func TestExceptionAuthorization(t *testing.T) {
	e := newEnv(t)
	e.syncWeakKey(checks.Warning, "key-A")
	alice := e.principal("user:alice@wf.test", store.RoleOwner)
	for _, role := range []string{store.RoleViewer, store.RoleAuditor, store.RoleApprover, store.RoleDeploymentOperator, store.RoleIssuerAdmin} {
		if _, _, err := e.svc.RequestException(ctx, e.principal("user:x@wf.test", role), weakKeyInput()); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("%s may not request: %v", role, err)
		}
	}
	// A requester token alice created makes the request.
	tok, _, err := e.svc.CreateToken(ctx, alice, "grc-bot", store.RoleRequester, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exc, apr, err := e.svc.RequestException(ctx, e.principal("token:"+tok.ID, store.RoleRequester), weakKeyInput())
	if err != nil {
		t.Fatalf("requester token: %v", err)
	}
	for name, p := range map[string]authz.Principal{
		"token creator":  alice,
		"token itself":   e.principal("token:"+tok.ID, store.RoleOwner),
		"other token":    e.principal("token:tok_other", store.RoleOwner),
		"operator":       operatorP(e),
		"requester role": e.principal("user:r@wf.test", store.RoleRequester),
	} {
		if _, err := e.svc.DecideApproval(ctx, p, apr.ID, true, ""); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("%s must not approve: %v", name, err)
		}
	}
	if _, err := e.svc.DecideApproval(ctx, alice, apr.ID, true, ""); !errors.Is(err, app.ErrSelfApproval) {
		t.Fatalf("token creator must get the self-approval error: %v", err)
	}
	approve(t, e, apr)
	for name, p := range map[string]authz.Principal{
		"operator":  operatorP(e),
		"requester": e.principal("user:r@wf.test", store.RoleRequester),
		"viewer":    e.principal("user:v@wf.test", store.RoleViewer),
	} {
		if _, err := e.svc.RevokeException(ctx, p, exc.ID, "x"); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("%s must not revoke: %v", name, err)
		}
	}
	if _, err := e.svc.RevokeException(ctx, approverP(e), exc.ID, " "); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("revoke without reason: %v", err)
	}
	// Ending an exception only restores alerting, so an owner token may do it.
	if _, err := e.svc.RevokeException(ctx, e.principal("token:tok_owner", store.RoleOwner), exc.ID, "incident"); err != nil {
		t.Fatalf("owner token revoke: %v", err)
	}
}

func TestExceptionSuppressesOnlyItsCondition(t *testing.T) {
	e, exc, apr := requestWeakKeyException(t)
	approve(t, e, apr)
	if got, _ := e.svc.GetException(ctx, e.owner, exc.ID); got.State != store.ExceptionActive || e.alertState() != "suppressed" {
		t.Fatalf("after approval: %s alert %q", got.State, e.alertState())
	}
	fs, _ := e.svc.ListFindings(ctx, e.owner, store.FindingFilter{SubjectID: excSubject})
	if len(fs) != 1 || fs[0].ExceptionID == nil || *fs[0].ExceptionID != exc.ID {
		t.Fatalf("the finding stays visible and points at the exception: %+v", fs)
	}

	// Resolved and found again with the same condition: covered from the start.
	e.syncWeakKey("", "")
	if res := e.syncWeakKey(checks.Warning, "key-A"); len(res.Opened) != 1 || res.Opened[0].ExceptionID == nil || e.alertState() != "suppressed" {
		t.Fatalf("same condition again: %+v alert %q", res.Opened, e.alertState())
	}
	// A different key under the same check is a different condition.
	if res := e.syncWeakKey(checks.Warning, "key-B"); len(res.Reopened) != 1 || e.alertState() != "open" {
		t.Fatalf("changed condition: %+v alert %q", res, e.alertState())
	}
	e.syncWeakKey(checks.Warning, "key-A")
	if e.alertState() != "suppressed" {
		t.Fatalf("back to the accepted condition: %q", e.alertState())
	}
	// Worse than accepted: alerting comes back, notified as an escalation.
	if res := e.syncWeakKey(checks.Critical, "key-A"); len(res.Escalated) != 1 || res.Escalated[0].ExceptionID != nil || len(res.Reopened) != 0 {
		t.Fatalf("escalation: %+v", res)
	}
	if e.alertState() != "open" {
		t.Fatalf("after escalation: %q", e.alertState())
	}
}

// The approver approves what the finding is now, not what it was.
func TestExceptionRevalidatedOnApproval(t *testing.T) {
	e, _, apr := requestWeakKeyException(t)
	e.syncWeakKey(checks.Critical, "key-A")
	if _, err := e.svc.DecideApproval(ctx, approverP(e), apr.ID, true, ""); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "worse") {
		t.Fatalf("approve after escalation: %v", err)
	}
	e.syncWeakKey(checks.Warning, "key-B")
	if _, err := e.svc.DecideApproval(ctx, approverP(e), apr.ID, true, ""); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "different condition") {
		t.Fatalf("approve after condition change: %v", err)
	}
	e.syncWeakKey(checks.Warning, "key-A")
	approve(t, e, apr)
}

func TestProhibitedChecks(t *testing.T) {
	e, exc, apr := requestWeakKeyException(t)
	approve(t, e, apr)
	if e.alertState() != "suppressed" {
		t.Fatal("setup")
	}
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte("apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec:\n  exceptions: {prohibitedChecks: [weak_key]}\n"), false); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetException(ctx, e.owner, exc.ID); got.State != store.ExceptionRevoked || e.alertState() != "open" {
		t.Fatalf("after prohibiting: %s alert %q", got.State, e.alertState())
	}
	if _, _, err := e.svc.RequestException(ctx, operatorP(e), weakKeyInput()); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "prohibitedChecks") {
		t.Fatalf("request for a prohibited check: %v", err)
	}
}

// Expiry counts the moment it passes, before any background job runs.
func TestExceptionExpiryIsImmediate(t *testing.T) {
	e, exc, apr := requestWeakKeyException(t)
	approve(t, e, apr)
	if _, err := e.db.Owner.Exec(ctx, `UPDATE policy_exceptions SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if e.alertState() != "open" {
		t.Fatalf("lapsed suppression must read as open: %q", e.alertState())
	}
	fs, _ := e.svc.ListFindings(ctx, e.owner, store.FindingFilter{SubjectID: excSubject})
	if fs[0].ExceptionID != nil {
		t.Fatal("a lapsed exception must not be shown as covering the finding")
	}
	if n, err := e.svc.SweepExceptions(ctx); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got, _ := e.svc.GetException(ctx, e.owner, exc.ID); got.State != store.ExceptionExpired || e.outboxCount("exception.expired") != 1 {
		t.Fatalf("after sweep: %s", got.State)
	}
}

func TestExceptionReminders(t *testing.T) {
	e, _, apr := requestWeakKeyException(t)
	approve(t, e, apr)
	sweep := func() {
		if _, err := e.svc.SweepExceptions(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A 2-day exception is reminded half way, not 7 days ahead.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE policy_exceptions SET approved_at = now() - interval '12 hours', expires_at = now() + interval '36 hours'`); err != nil {
		t.Fatal(err)
	}
	sweep()
	if n := e.outboxCount("exception.expiring"); n != 0 {
		t.Fatalf("reminded too early: %d", n)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE policy_exceptions SET approved_at = now() - interval '26 hours', expires_at = now() + interval '22 hours'`); err != nil {
		t.Fatal(err)
	}
	sweep()
	sweep()
	if n := e.outboxCount("exception.expiring"); n != 1 {
		t.Fatalf("reminders: %d, want exactly 1", n)
	}
}

func TestExceptionDeniedAndRevokedLeaveAlertsOpen(t *testing.T) {
	e, exc, apr := requestWeakKeyException(t)
	if _, err := e.svc.DecideApproval(ctx, approverP(e), apr.ID, false, "upgrade instead"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetException(ctx, e.owner, exc.ID); got.State != store.ExceptionDenied || e.alertState() != "open" {
		t.Fatalf("after deny: %s alert %q", got.State, e.alertState())
	}
	exc2, apr2, err := e.svc.RequestException(ctx, operatorP(e), weakKeyInput())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, e, apr2)
	if _, err := e.svc.RevokeException(ctx, approverP(e), exc2.ID, "firmware 9 is out"); err != nil {
		t.Fatal(err)
	}
	if e.alertState() != "open" || e.outboxCount("exception.revoked") != 1 {
		t.Fatalf("after revoke: %q", e.alertState())
	}
}

// What was requested and approved cannot be rewritten by the application.
func TestExceptionRecordsAreImmutable(t *testing.T) {
	e, exc, apr := requestWeakKeyException(t)
	err := e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE policy_exceptions SET rationale = 'rewritten' WHERE id = $1`, exc.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("rewriting an exception: %v", err)
	}
	err = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE approvals SET spec_sha256 = 'x' WHERE id = $1`, apr.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("rewriting an approval: %v", err)
	}
	approve(t, e, apr) // the state columns still work
	var actions string
	_ = e.db.Owner.QueryRow(ctx, `SELECT string_agg(action, ',' ORDER BY seq) FROM audit_events WHERE resource_id IN ($1, $2)`,
		exc.ID, apr.ID).Scan(&actions)
	if actions != "exceptions.request,approvals.approve" {
		t.Fatalf("audit history: %q", actions)
	}
}

// Acknowledging records that someone saw the alert. It never hides the
// finding or its metrics, and it does not last for ever.
func TestAcknowledgementIsNotRiskAcceptance(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.CreateChannel(ctx, e.owner, webhook("all")); err != nil {
		t.Fatal(err)
	}
	e.syncWeakKey(checks.Warning, "key-A")
	as, _ := e.svc.ListAlerts(ctx, e.owner, nil)
	var alertID string
	for _, a := range as {
		if a.Finding.SubjectID == excSubject {
			alertID = a.ID
		}
	}
	if err := e.svc.AckAlert(ctx, operatorP(e), alertID); err != nil {
		t.Fatal(err)
	}
	if e.alertState() != "acked" {
		t.Fatalf("after ack: %q", e.alertState())
	}
	fs, _ := e.svc.ListFindings(ctx, e.owner, store.FindingFilter{SubjectID: excSubject})
	if len(fs) != 1 || fs[0].ExceptionID != nil {
		t.Fatalf("an acked finding stays visible and is not accepted risk: %+v", fs)
	}
	m, err := e.svc.Overview(ctx, e.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range m {
		if x.Key == "open_alerts" && x.Denominator < 1 {
			t.Fatalf("acked alerts must still count: %+v", x)
		}
	}
	// After the policy's ackExpiry the alert opens again and notifies.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE alerts SET acked_at = now() - interval '8 days' WHERE id = $1`, alertID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.EscalateAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if e.alertState() != "open" || e.outboxCount("alert.ack_expired") != 1 {
		t.Fatalf("after ack expiry: %q, notifications %d", e.alertState(), e.outboxCount("alert.ack_expired"))
	}
}
