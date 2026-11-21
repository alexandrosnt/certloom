package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/alexandrosnt/certloom/internal/store"
)

// ErrSelfApproval is returned when someone tries to decide a request they
// made themselves, directly or through an API token they created.
var ErrSelfApproval = fmt.Errorf("%w: separation of duties: you cannot decide your own request", authz.ErrForbidden)

func approvalsRequired(pol *policy.Document) bool {
	return pol.Spec.Approvals.Deployments == policy.ApprovalRequired
}

// approvalNeeded reports whether a deployment spec created or changed by p
// must wait for someone else's approval.
func approvalNeeded(p authz.Principal, pol *policy.Document) bool {
	return !p.Can(authz.ManageDeployments) || approvalsRequired(pol)
}

// deploymentSpec resolves the deployment's effective spec.
func (s *Service) deploymentSpec(ctx context.Context, tx *store.Tx, d *store.Deployment) (store.DeploymentSpec, error) {
	iss, err := tx.GetIssuer(ctx, d.IssuerID)
	if err != nil {
		return store.DeploymentSpec{}, err
	}
	a, err := tx.GetAgent(ctx, d.AgentID)
	if err != nil {
		return store.DeploymentSpec{}, err
	}
	return store.BuildDeploymentSpec(d, iss, a), nil
}

// approvalProblem says why the deployment may not change its target now, or
// "" if it may. runSpec is the digest a run was started for, if any: the
// run may only continue while that exact spec is still approved.
func (s *Service) approvalProblem(ctx context.Context, tx *store.Tx, d *store.Deployment, required bool, runSpec *string) (problem, digest string, err error) {
	spec, err := s.deploymentSpec(ctx, tx, d)
	if err != nil {
		return "", "", err
	}
	digest = spec.SHA256()
	switch {
	case d.Approval != store.ApprovalApproved:
		return "deployment is not approved (approval: " + d.Approval + ")", digest, nil
	case !d.ApprovalCovers(digest, required) && d.ApprovedSpecSHA256 == nil:
		return "approvals are required and this deployment has never been approved; request approval", digest, nil
	case !d.ApprovalCovers(digest, required):
		return "deployment spec changed since it was approved; request approval", digest, nil
	case runSpec != nil && *runSpec != digest:
		return "deployment spec changed since the run started", digest, nil
	}
	return "", digest, nil
}

// notifyApproval sends approval events to policy approvals.channels, or to
// every channel when none are set.
func (s *Service) notifyApproval(ctx context.Context, tx *store.Tx, pol *policy.Document, d *store.Deployment, event, key, msg string) error {
	n := store.Notification{Event: event, OrgID: tx.OrgID, SubjectType: "deployment", SubjectID: d.ID,
		Subject: "deployment " + d.ID, Severity: "warning", Message: msg, At: s.now().UTC()}
	return tx.EnqueueNotificationTo(ctx, n, key, pol.Spec.Approvals.Channels)
}

// requestApproval marks the deployment pending and opens a request for spec.
func (s *Service) requestApproval(ctx context.Context, tx *store.Tx, d *store.Deployment, spec store.DeploymentSpec, actor string,
	pol *policy.Document) (*store.Approval, error) {
	if err := tx.SetDeploymentApproval(ctx, d.ID, "pending", nil); err != nil {
		return nil, err
	}
	d.Approval = "pending"
	a, err := tx.CreateApproval(ctx, d.ID, spec, actor, time.Duration(pol.Spec.Approvals.ExpireAfter))
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("%w: deployment already has an open approval request", store.ErrConflict)
		}
		return nil, err
	}
	msg := fmt.Sprintf("%s asks for approval of deployment %s (%s via %s); request %s expires %s", actor, d.ID,
		strings.Join(spec.SANs, ", "), spec.Issuer.DirectoryURL, a.ID, a.ExpiresAt.UTC().Format(time.RFC3339))
	return a, s.notifyApproval(ctx, tx, pol, d, "approval.requested", a.ID+":requested", msg)
}

// RequestDeploymentApproval opens a request for a deployment whose approval
// does not cover its current spec: denied, revoked, expired, changed, or
// created before approvals were required.
func (s *Service) RequestDeploymentApproval(ctx context.Context, p authz.Principal, deploymentID string) (*store.Approval, error) {
	perm := authz.ManageDeployments
	if !p.Can(perm) {
		perm = authz.RequestDeployments
	}
	var a *store.Approval
	err := s.tx(ctx, p, perm, func(tx *store.Tx) error {
		d, err := tx.GetDeployment(ctx, deploymentID, true)
		if err != nil {
			return err
		}
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		spec, err := s.deploymentSpec(ctx, tx, d)
		if err != nil {
			return err
		}
		if d.ApprovedSpecSHA256 != nil && d.ApprovalCovers(spec.SHA256(), true) {
			return invalid("deployment is already approved for its current spec")
		}
		if a, err = s.requestApproval(ctx, tx, d, spec, p.Actor, pv.Document); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "approvals.request", "approval", a.ID, map[string]any{"deployment": d.ID, "spec_sha256": a.SpecSHA256})
	})
	return a, err
}

// ListApprovals lists approval requests; state "" means all.
func (s *Service) ListApprovals(ctx context.Context, p authz.Principal, state string) (out []*store.Approval, err error) {
	switch state {
	case "", store.ApprovalRequested, store.ApprovalApproved, store.ApprovalDenied, store.ApprovalExpired, store.ApprovalRevoked:
	default:
		return nil, invalid("unknown approval state %q", state)
	}
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListApprovals(ctx, state, 200); return err })
	return out, err
}

// GetApproval returns one approval request.
func (s *Service) GetApproval(ctx context.Context, p authz.Principal, id string) (a *store.Approval, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { a, err = tx.GetApproval(ctx, id, false); return err })
	return a, err
}

// DecideApproval approves or denies a request. Only signed-in people decide,
// never the requester, and never someone whose API token made the request.
// The decision covers the spec digest recorded in the request; if the
// effective spec has changed since, the request can no longer be approved.
func (s *Service) DecideApproval(ctx context.Context, p authz.Principal, id string, approve bool, reason string) (*store.Approval, error) {
	if !strings.HasPrefix(p.Actor, "user:") {
		return nil, fmt.Errorf("%w: approvals must be decided by a signed-in person, not an API token", authz.ErrForbidden)
	}
	reason, err := checkReason(reason, !approve)
	if err != nil {
		return nil, err
	}
	var a *store.Approval
	err = s.tx(ctx, p, authz.ApproveRequests, func(tx *store.Tx) (err error) {
		if a, err = tx.GetApproval(ctx, id, true); err != nil {
			return err
		}
		if a.State != store.ApprovalRequested {
			return fmt.Errorf("%w: request is already %s", store.ErrConflict, a.State)
		}
		if !a.ExpiresAt.After(s.now()) {
			return fmt.Errorf("%w: request expired at %s", store.ErrConflict, a.ExpiresAt.UTC().Format(time.RFC3339))
		}
		if err := s.checkSeparation(ctx, tx, a.RequestedBy, p.Actor); err != nil {
			return err
		}
		d, err := tx.GetDeployment(ctx, a.ResourceID, true)
		if err != nil {
			return err
		}
		spec, err := s.deploymentSpec(ctx, tx, d)
		if err != nil {
			return err
		}
		if approve && spec.SHA256() != a.SpecSHA256 {
			return fmt.Errorf("%w: the deployment or its issuer or target changed after this request was made; ask for a new request", store.ErrConflict)
		}
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		state, action, dstate := store.ApprovalDenied, "approvals.deny", "denied"
		var digest *string
		if approve {
			state, action, dstate, digest = store.ApprovalApproved, "approvals.approve", "approved", &a.SpecSHA256
		}
		if err := tx.DecideApproval(ctx, a.ID, state, p.Actor, reason); err != nil {
			return err
		}
		if err := tx.SetDeploymentApproval(ctx, d.ID, dstate, digest); err != nil {
			return err
		}
		if approve && d.EndpointID != nil {
			if err := tx.SetEndpointLineage(ctx, *d.EndpointID, &d.LineageID, nil); err != nil {
				return err
			}
		}
		now := s.now()
		a.State, a.DecidedBy, a.DecidedAt, a.Reason = state, &p.Actor, &now, reason
		msg := fmt.Sprintf("%s %s request %s for deployment %s", p.Actor, state, a.ID, d.ID)
		if reason != "" {
			msg += ": " + reason
		}
		if err := s.notifyApproval(ctx, tx, pv.Document, d, "approval."+state, a.ID+":"+state, msg); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, action, "approval", a.ID, map[string]any{"deployment": d.ID, "spec_sha256": a.SpecSHA256,
			"requested_by": a.RequestedBy, "reason": reason})
	})
	return a, err
}

// RevokeDeploymentApproval withdraws a deployment's approval. Runs that have
// not changed the target yet stop at their next checkpoint. Revoking makes
// things safer, so it needs no second person, but it needs a reason.
func (s *Service) RevokeDeploymentApproval(ctx context.Context, p authz.Principal, deploymentID, reason string) (*store.Deployment, error) {
	reason, err := checkReason(reason, true)
	if err != nil {
		return nil, err
	}
	var d *store.Deployment
	err = s.tx(ctx, p, authz.ApproveRequests, func(tx *store.Tx) (err error) {
		if d, err = tx.GetDeployment(ctx, deploymentID, true); err != nil {
			return err
		}
		if d.Approval != store.ApprovalApproved {
			return fmt.Errorf("%w: deployment is %s, not approved", store.ErrConflict, d.Approval)
		}
		approvalID, err := tx.RevokeApproval(ctx, d.ID, p.Actor, reason)
		if err != nil {
			return err
		}
		if err := tx.SetDeploymentApproval(ctx, d.ID, store.ApprovalRevoked, nil); err != nil {
			return err
		}
		d.Approval = store.ApprovalRevoked
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("%s revoked the approval of deployment %s: %s", p.Actor, d.ID, reason)
		if err := s.notifyApproval(ctx, tx, pv.Document, d, "approval.revoked", d.ID+":revoked:"+s.now().Format(time.RFC3339Nano), msg); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "approvals.revoke", "deployment", d.ID, map[string]any{"approval": approvalID, "reason": reason})
	})
	return d, err
}

func checkReason(reason string, required bool) (string, error) {
	reason = strings.TrimSpace(reason)
	if required && reason == "" {
		return "", invalid("a reason is required")
	}
	if len(reason) > 1000 {
		return "", invalid("reason is longer than 1000 characters")
	}
	return reason, nil
}

// checkSeparation refuses a decision by the requester, or by whoever created
// the API token (or chain of tokens) that made the request. Identities are
// compared case-insensitively. Tokens minted by the bootstrap token trace
// back to no person and cannot be checked further; see ADR-0015.
func (s *Service) checkSeparation(ctx context.Context, tx *store.Tx, requestedBy, decider string) error {
	actor := requestedBy
	for range 10 {
		if strings.EqualFold(actor, decider) {
			return ErrSelfApproval
		}
		id, ok := strings.CutPrefix(actor, "token:")
		if !ok {
			return nil
		}
		by, err := tx.TokenCreatedBy(ctx, id)
		if err != nil {
			return err
		}
		actor = by
	}
	return fmt.Errorf("%w: token chain behind %s is too long to check", authz.ErrForbidden, requestedBy)
}

// expireApprovals closes overdue requests (called by the scheduler).
func (s *Service) expireApprovals(ctx context.Context, tx *store.Tx) error {
	ids, err := tx.ExpireApprovals(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.systemAudit(ctx, tx, workflowActor, "approvals.expire", "approval", id, nil); err != nil {
			return err
		}
	}
	return nil
}
