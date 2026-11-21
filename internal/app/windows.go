package app

import (
	"context"
	"fmt"
	"time"

	"github.com/alexandrosnt/certloom/internal/ari"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/window"
)

// Emergency settings for a deployment whose maintenance window cannot be
// reached before the current certificate gets too close to expiry.
const (
	EmergencyBlock   = "block"
	EmergencyRenewal = "renew_outside_window"
)

// windowSkew lets a run scheduled for the window start proceed even if this
// process's clock is a few seconds behind the database's.
const windowSkew = 5 * time.Second

func checkWindow(spec, emergency string) error {
	if spec != "" {
		if _, err := window.Parse(spec); err != nil {
			return invalid("%v", err)
		}
	}
	switch emergency {
	case "", EmergencyBlock, EmergencyRenewal:
		return nil
	}
	return invalid("emergency must be %q or %q", EmergencyBlock, EmergencyRenewal)
}

func normWindow(spec string) string {
	if spec == "" {
		return ""
	}
	w, _ := window.Parse(spec)
	return w.String()
}

// SetDeploymentWindow changes when a deployment may activate certificates.
// An empty spec removes the window. Runs waiting for or blocked by the old
// setting are re-evaluated right away.
func (s *Service) SetDeploymentWindow(ctx context.Context, p authz.Principal, id, spec, emergency string) (*store.Deployment, error) {
	if err := checkWindow(spec, emergency); err != nil {
		return nil, err
	}
	if emergency == "" {
		emergency = EmergencyBlock
	}
	var d *store.Deployment
	err := s.tx(ctx, p, authz.ManageDeployments, func(tx *store.Tx) error {
		old, err := tx.GetDeployment(ctx, id, true)
		if err != nil {
			return err
		}
		spec = normWindow(spec)
		if err := tx.SetDeploymentWindow(ctx, id, spec, emergency); err != nil {
			return err
		}
		if r, err := tx.ActiveRunFor(ctx, id); err == nil && (r.State == store.RunWaitingWindow || r.State == store.RunBlocked) {
			if _, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, fmt.Sprintf("%s:window:%d", r.ID, s.now().UnixNano()),
				map[string]string{"run_id": r.ID}, time.Time{}); err != nil {
				return err
			}
		}
		if d, err = tx.GetDeployment(ctx, id, false); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "deployments.set_window", "deployment", id, map[string]any{
			"old_window": old.MaintenanceWindow, "old_emergency": old.WindowEmergency,
			"maintenance_window": spec, "window_emergency": emergency})
	})
	return d, err
}

// safetyDeadline is the latest time the certificate the run replaces may stay
// in service: its NotAfter minus the minimum lead. Zero when there is none.
func safetyDeadline(ctx context.Context, tx *store.Tx, r *store.Run) (time.Time, error) {
	if r.PreviousSHA256 == nil {
		return time.Time{}, nil
	}
	c, err := tx.GetCertificate(ctx, *r.PreviousSHA256)
	if err != nil {
		return time.Time{}, err
	}
	return c.X509.NotAfter.Add(-ari.MinLead(c.X509)), nil
}

// windowGate decides whether an issued run may activate its certificate now.
// It returns true to deploy. Otherwise it has parked the run: waiting for the
// next window (a job wakes it at the window start), or blocked because no
// window starts before the safety deadline. A blocked run raises a critical
// alert, unless the deployment's emergency setting allows activating outside
// the window, which is recorded in the audit trail.
func (s *Service) windowGate(ctx context.Context, tx *store.Tx, r *store.Run, d *store.Deployment) (bool, error) {
	if d.MaintenanceWindow == "" {
		return true, nil
	}
	w, err := window.Parse(d.MaintenanceWindow)
	if err != nil {
		return false, s.block(ctx, tx, r, "stored maintenance window is invalid: "+err.Error())
	}
	now := s.now()
	if w.Contains(now) || w.Contains(now.Add(windowSkew)) {
		return true, nil
	}
	next := w.Next(now)
	deadline, err := safetyDeadline(ctx, tx, r)
	if err != nil {
		return false, err
	}
	if deadline.IsZero() || next.Before(deadline) {
		if r.State != store.RunWaitingWindow || r.NextAttemptAt == nil || !r.NextAttemptAt.Equal(next) {
			r.State, r.NextAttemptAt = store.RunWaitingWindow, &next
			if err := tx.UpdateRun(ctx, r, fmt.Sprintf("waiting for maintenance window %q; activation at %s",
				w.String(), next.UTC().Format(time.RFC3339))); err != nil {
				return false, err
			}
		}
		// Unique key: the job running now may carry the previous wake-up key.
		_, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindAdvance, fmt.Sprintf("%s:window:%d", r.ID, s.now().UnixNano()),
			map[string]string{"run_id": r.ID}, next)
		return false, err
	}
	why := fmt.Sprintf("no maintenance window (%s) starts before the safety deadline %s (current certificate expires soon)",
		w.String(), deadline.UTC().Format(time.RFC3339))
	if d.WindowEmergency == EmergencyRenewal {
		r.State = store.RunIssued
		if err := tx.UpdateRun(ctx, r, why+"; activating outside the window as the deployment's emergency setting allows"); err != nil {
			return false, err
		}
		if err := s.systemAudit(ctx, tx, workflowActor, "renewals.window_override", "run", r.ID, map[string]any{
			"maintenance_window": w.String(), "deadline": deadline.UTC(), "next_window": next.UTC()}); err != nil {
			return false, err
		}
		return true, s.notifyRun(ctx, tx, r, "renewal.window_override", "warning", why)
	}
	return false, s.block(ctx, tx, r, why)
}

// block parks the run until an operator changes the window settings or
// cancels it. The alert is raised once, when the run becomes blocked.
func (s *Service) block(ctx context.Context, tx *store.Tx, r *store.Run, why string) error {
	if r.State == store.RunBlocked && r.Error == why {
		return nil
	}
	r.State, r.Error, r.NextAttemptAt = store.RunBlocked, why, nil
	if err := tx.UpdateRun(ctx, r, "blocked: "+why+"; change the window or set emergency renew_outside_window, or cancel the run"); err != nil {
		return err
	}
	if err := s.systemAudit(ctx, tx, workflowActor, "renewals.blocked", "run", r.ID, map[string]any{"reason": why}); err != nil {
		return err
	}
	return s.notifyRun(ctx, tx, r, "renewal.blocked", "critical", why)
}
