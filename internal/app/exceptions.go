package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/alexandrosnt/certloom/internal/store"
)

// exceptionReminder is how long before expiry the owners of an exception
// are reminded that alerts will come back.
const exceptionReminder = 7 * 24 * time.Hour

// ExceptionInput describes a requested policy exception. The accepted
// severity is always the finding's current severity: an exception can never
// accept more than what was seen.
type ExceptionInput struct {
	SubjectType, SubjectID, Check string
	Rationale                     string
	CompensatingControls          string
	// RiskOwner is the person accountable for the accepted risk.
	RiskOwner string
	// RemediationOwner, RemediationDue and TrackingRef describe the fix,
	// where one is possible.
	RemediationOwner string
	RemediationDue   *time.Time
	TrackingRef      string
	ExpiresAt        time.Time
}

func (in *ExceptionInput) validate(now time.Time) error {
	switch in.SubjectType {
	case "certificate", "endpoint", "lineage":
	default:
		return invalid("subject_type must be certificate, endpoint or lineage")
	}
	if !checks.KnownCheck(in.Check) {
		return invalid("unknown check %q", in.Check)
	}
	for _, f := range []*string{&in.Rationale, &in.CompensatingControls, &in.RiskOwner, &in.RemediationOwner, &in.TrackingRef} {
		*f = strings.TrimSpace(*f)
	}
	switch {
	case in.Rationale == "":
		return invalid("a rationale is required")
	case in.RiskOwner == "":
		return invalid("a risk_owner is required: the person accountable for accepting this risk")
	case len(in.Rationale) > 2000 || len(in.CompensatingControls) > 2000:
		return invalid("rationale and compensating_controls are limited to 2000 characters each")
	case len(in.RiskOwner) > 200 || len(in.RemediationOwner) > 200 || len(in.TrackingRef) > 200:
		return invalid("risk_owner, remediation_owner and tracking_ref are limited to 200 characters each")
	case in.RemediationDue != nil && in.RemediationDue.Before(now.Truncate(24*time.Hour)):
		return invalid("remediation_due is in the past")
	}
	return nil
}

// openFinding returns the open finding for one check on one subject.
func openFinding(ctx context.Context, tx *store.Tx, subjectType, subjectID, check string) (*store.Finding, error) {
	fs, err := tx.ListFindings(ctx, store.FindingFilter{SubjectType: subjectType, SubjectID: subjectID, Limit: 100})
	if err != nil {
		return nil, err
	}
	for i := range fs {
		if fs[i].Check == check {
			return &fs[i], nil
		}
	}
	return nil, nil
}

// RequestException asks to accept the risk of one open finding (one
// condition on one subject) until ExpiresAt. It takes effect only once
// someone else approves it (ADR-0015), and it suppresses the alert, never
// the finding.
func (s *Service) RequestException(ctx context.Context, p authz.Principal, in ExceptionInput) (*store.Exception, *store.Approval, error) {
	if err := in.validate(s.now()); err != nil {
		return nil, nil, err
	}
	var e *store.Exception
	var a *store.Approval
	err := s.tx(ctx, p, authz.RequestExceptions, func(tx *store.Tx) error {
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		if pv.Document.ExceptionProhibited(in.Check) {
			return invalid("policy does not allow exceptions for %s (exceptions.prohibitedChecks)", in.Check)
		}
		// Risk is accepted for something that exists and was looked at, not
		// in advance.
		f, err := openFinding(ctx, tx, in.SubjectType, in.SubjectID, in.Check)
		if err != nil {
			return err
		}
		switch {
		case f == nil:
			return invalid("no open %s finding for %s %s", in.Check, in.SubjectType, in.SubjectID)
		case f.Severity != "warning" && f.Severity != "critical":
			return invalid("the finding is %s; only warning and critical findings have an alert to suppress", f.Severity)
		case f.Fingerprint == "":
			return invalid("the finding predates condition fingerprints; wait for the next probe or sweep and try again")
		}
		now := s.now()
		maxDur := time.Duration(pv.Document.Spec.Exceptions.MaxDuration)
		if !in.ExpiresAt.After(now.Add(time.Hour)) || in.ExpiresAt.After(now.Add(maxDur)) {
			return invalid("expires_at must be between 1h and %s from now (policy exceptions.maxDuration)", policy.FormatDuration(maxDur))
		}
		evidence, err := json.Marshal(f)
		if err != nil {
			return err
		}
		e = &store.Exception{SubjectType: in.SubjectType, SubjectID: in.SubjectID, Check: in.Check, CheckVersion: f.CheckVersion,
			Fingerprint: f.Fingerprint, MaxSeverity: f.Severity, Rationale: in.Rationale, CompensatingControls: in.CompensatingControls,
			RiskOwner: in.RiskOwner, RemediationOwner: in.RemediationOwner, RemediationDue: in.RemediationDue, TrackingRef: in.TrackingRef,
			Evidence: evidence, ExpiresAt: in.ExpiresAt, RequestedBy: p.Actor}
		if err := tx.CreateException(ctx, e); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: an exception for this check and subject is already requested or active", store.ErrConflict)
			}
			return err
		}
		ttl := min(time.Duration(pv.Document.Spec.Approvals.ExpireAfter), e.ExpiresAt.Sub(now))
		if a, err = tx.CreateApproval(ctx, "exception", e.ID, e.Spec(), p.Actor, ttl); err != nil {
			return err
		}
		msg := fmt.Sprintf("%s asks to accept %s (%s) on %s %s until %s, risk owner %s: %s; request %s", p.Actor, e.Check, e.MaxSeverity,
			e.SubjectType, e.SubjectID, e.ExpiresAt.Format(time.DateOnly), e.RiskOwner, e.Rationale, a.ID)
		if err := s.notifyException(ctx, tx, pv.Document, e, "exception.requested", a.ID+":requested", msg); err != nil {
			return err
		}
		// The audit trail keeps the whole request, evidence included.
		return s.audit(ctx, tx, p, "exceptions.request", "exception", e.ID, map[string]any{"approval": a.ID, "spec": e.Spec(),
			"spec_sha256": a.SpecSHA256})
	})
	return e, a, err
}

// decideException applies an approval decision to the exception it covers.
// Before approving it checks again that the policy still allows it and that
// the finding is still the condition the requester described, at no worse
// a severity.
func (s *Service) decideException(ctx context.Context, tx *store.Tx, a *store.Approval, approve bool, decider string) (string, error) {
	e, err := tx.GetException(ctx, a.ResourceID, true)
	if err != nil {
		return "", err
	}
	subject := "exception " + e.ID
	if !approve {
		_, err := tx.EndException(ctx, e.ID, store.ExceptionDenied, decider, "approval denied")
		return subject, err
	}
	if e.Spec().SHA256() != a.SpecSHA256 {
		return "", fmt.Errorf("%w: the exception changed after this request was made", store.ErrConflict)
	}
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return "", err
	}
	if pv.Document.ExceptionProhibited(e.Check) {
		return "", fmt.Errorf("%w: policy no longer allows exceptions for %s; deny the request", store.ErrConflict, e.Check)
	}
	f, err := openFinding(ctx, tx, e.SubjectType, e.SubjectID, e.Check)
	if err != nil {
		return "", err
	}
	switch {
	case f == nil:
		return "", fmt.Errorf("%w: the finding is no longer open; nothing to accept", store.ErrConflict)
	case f.CheckVersion != e.CheckVersion || f.Fingerprint != e.Fingerprint:
		return "", fmt.Errorf("%w: the finding now describes a different condition than the request; deny it and request again", store.ErrConflict)
	case checks.Severity(f.Severity).Rank() > checks.Severity(e.MaxSeverity).Rank():
		return "", fmt.Errorf("%w: the finding is now %s, worse than the requested %s; deny it and request again", store.ErrConflict, f.Severity, e.MaxSeverity)
	}
	if err := tx.ActivateException(ctx, e.ID, decider); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", fmt.Errorf("%w: exception is no longer waiting for approval or has already ended", store.ErrConflict)
		}
		return "", err
	}
	return subject, nil
}

// ListExceptions lists exceptions; state "" means all.
func (s *Service) ListExceptions(ctx context.Context, p authz.Principal, state string) (out []*store.Exception, err error) {
	switch state {
	case "", store.ExceptionRequested, store.ExceptionActive, store.ExceptionDenied, store.ExceptionExpired, store.ExceptionRevoked:
	default:
		return nil, invalid("unknown exception state %q", state)
	}
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListExceptions(ctx, state, 500); return err })
	return out, err
}

// GetException returns one exception.
func (s *Service) GetException(ctx context.Context, p authz.Principal, id string) (e *store.Exception, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { e, err = tx.GetException(ctx, id, false); return err })
	return e, err
}

// RevokeException ends an active or requested exception early; suppressed
// alerts open again right away.
func (s *Service) RevokeException(ctx context.Context, p authz.Principal, id, reason string) (*store.Exception, error) {
	reason, err := checkReason(reason, true)
	if err != nil {
		return nil, err
	}
	var e *store.Exception
	err = s.tx(ctx, p, authz.ApproveRequests, func(tx *store.Tx) (err error) {
		if e, err = tx.GetException(ctx, id, true); err != nil {
			return err
		}
		if _, err := tx.EndException(ctx, e.ID, store.ExceptionRevoked, p.Actor, reason); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: exception is already %s", store.ErrConflict, e.State)
			}
			return err
		}
		e.State = store.ExceptionRevoked
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("%s revoked exception %s (%s on %s %s): %s; its alerts are active again", p.Actor, e.ID, e.Check,
			e.SubjectType, e.SubjectID, reason)
		if err := s.notifyException(ctx, tx, pv.Document, e, "exception.revoked", e.ID+":revoked", msg); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "exceptions.revoke", "exception", e.ID, map[string]any{"reason": reason})
	})
	return e, err
}

// SweepExceptions ends expired exceptions (alerts come back), closes
// requests nobody approved in time, and sends reminders before expiry.
func (s *Service) SweepExceptions(ctx context.Context) (int, error) {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return 0, err
	}
	ended := 0
	var errs []error
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			if err := tx.ExpireRequestedExceptions(ctx); err != nil {
				return err
			}
			// Reads already treat a lapsed suppression as open; this makes the
			// stored state match and catches anything no exception covers.
			if err := tx.ReopenUncovered(ctx); err != nil {
				return err
			}
			expired, remind, err := tx.DueExceptions(ctx, exceptionReminder)
			if err != nil || len(expired)+len(remind) == 0 {
				return err
			}
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			for _, e := range expired {
				if _, err := tx.EndException(ctx, e.ID, store.ExceptionExpired, "", "expired"); err != nil {
					return err
				}
				msg := fmt.Sprintf("exception %s (%s on %s %s) expired; its alerts are active again", e.ID, e.Check, e.SubjectType, e.SubjectID)
				if err := s.notifyException(ctx, tx, pv.Document, e, "exception.expired", e.ID+":expired", msg); err != nil {
					return err
				}
				if err := s.systemAudit(ctx, tx, workflowActor, "exceptions.expire", "exception", e.ID, nil); err != nil {
					return err
				}
				ended++
			}
			for _, e := range remind {
				msg := fmt.Sprintf("exception %s (%s on %s %s) expires %s; fix the finding or request a new exception",
					e.ID, e.Check, e.SubjectType, e.SubjectID, e.ExpiresAt.Format(time.DateOnly))
				if err := s.notifyException(ctx, tx, pv.Document, e, "exception.expiring", e.ID+":expiring", msg); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return ended, errors.Join(errs...)
}

// notifyException sends exception events to the approval channels.
func (s *Service) notifyException(ctx context.Context, tx *store.Tx, pol *policy.Document, e *store.Exception, event, key, msg string) error {
	n := store.Notification{Event: event, OrgID: tx.OrgID, SubjectType: e.SubjectType, SubjectID: e.SubjectID,
		Subject: e.SubjectType + " " + e.SubjectID, Severity: "warning", Message: msg, At: s.now().UTC()}
	return tx.EnqueueNotificationTo(ctx, n, key, pol.Spec.Approvals.Channels)
}

// endProhibitedExceptions revokes requested and active exceptions for checks
// the policy now prohibits; their alerts open again at once.
func (s *Service) endProhibitedExceptions(ctx context.Context, tx *store.Tx, pol *policy.Document, reason string) error {
	if len(pol.Spec.Exceptions.ProhibitedChecks) == 0 {
		return nil
	}
	for _, state := range []string{store.ExceptionRequested, store.ExceptionActive} {
		es, err := tx.ListExceptions(ctx, state, 10000)
		if err != nil {
			return err
		}
		for _, e := range es {
			if !pol.ExceptionProhibited(e.Check) {
				continue
			}
			if _, err := tx.EndException(ctx, e.ID, store.ExceptionRevoked, workflowActor, reason); err != nil {
				return err
			}
			msg := fmt.Sprintf("exception %s (%s on %s %s) ended: %s; its alerts are active again", e.ID, e.Check, e.SubjectType, e.SubjectID, reason)
			if err := s.notifyException(ctx, tx, pol, e, "exception.revoked", e.ID+":revoked", msg); err != nil {
				return err
			}
			if err := s.systemAudit(ctx, tx, workflowActor, "exceptions.revoke", "exception", e.ID, map[string]any{"reason": reason}); err != nil {
				return err
			}
		}
	}
	return nil
}
