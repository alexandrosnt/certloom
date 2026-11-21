package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
)

// ---------- policy ----------

// GetPolicy returns the active policy (version 0 = built-in defaults).
func (s *Service) GetPolicy(ctx context.Context, p authz.Principal) (pv *store.PolicyVersion, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { pv, err = tx.ActivePolicy(ctx); return err })
	return pv, err
}

// PolicyChange counts certificates whose finding for a check changes severity.
type PolicyChange struct {
	Check string `json:"check"`
	From  string `json:"from"` // "" = no finding
	To    string `json:"to"`
	Count int    `json:"count"`
}

// PolicyPlan is the result of validating (and optionally applying) a policy.
type PolicyPlan struct {
	Applied        bool             `json:"applied"`
	Version        int              `json:"version,omitempty"`
	CurrentVersion int              `json:"current_version"`
	Evaluated      int              `json:"certificates_evaluated"`
	Changes        []PolicyChange   `json:"changes"`
	Document       *policy.Document `json:"document"`
}

// ApplyPolicy validates src, computes its impact on current certificate
// findings (plan), and stores it as a new version unless dryRun.
func (s *Service) ApplyPolicy(ctx context.Context, p authz.Principal, src []byte, dryRun bool) (*PolicyPlan, error) {
	doc, err := policy.Parse(src)
	if err != nil {
		return nil, invalid("%v", err)
	}
	plan := &PolicyPlan{Document: doc, Changes: []PolicyChange{}}
	err = s.tx(ctx, p, authz.ManagePolicy, func(tx *store.Tx) error {
		cur, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		plan.CurrentVersion = cur.Version
		oldP, newP := cur.Document.Checks(), doc.Checks()
		now := s.now()
		counts := map[PolicyChange]int{}
		var after string
		var afterNA time.Time
		for {
			certs, err := tx.ListCertificates(ctx, store.CertFilter{Limit: 500, AfterSHA256: after, AfterNotAfter: afterNA})
			if err != nil {
				return err
			}
			for _, c := range certs {
				plan.Evaluated++
				before, afterF := bySeverity(checks.Certificate(c.Certificate, now, oldP)), bySeverity(checks.Certificate(c.Certificate, now, newP))
				for _, chk := range union(before, afterF) {
					if before[chk] != afterF[chk] {
						counts[PolicyChange{Check: chk, From: before[chk], To: afterF[chk]}]++
					}
				}
			}
			if len(certs) < 500 {
				break
			}
			last := certs[len(certs)-1]
			after, afterNA = last.SHA256, last.NotAfter
		}
		for k, n := range counts {
			k.Count = n
			plan.Changes = append(plan.Changes, k)
		}
		sort.Slice(plan.Changes, func(i, j int) bool {
			a, b := plan.Changes[i], plan.Changes[j]
			if a.Check != b.Check {
				return a.Check < b.Check
			}
			return a.To+a.From < b.To+b.From
		})
		if dryRun {
			return nil
		}
		if plan.Version, err = tx.InsertPolicy(ctx, doc, string(src), p.Actor); err != nil {
			return err
		}
		plan.Applied = true
		if err := s.endProhibitedExceptions(ctx, tx, doc, fmt.Sprintf("policy version %d prohibits exceptions for this check", plan.Version)); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "policy.apply", "policy", fmt.Sprint(plan.Version), map[string]any{
			"version": plan.Version, "previous_version": cur.Version, "certificates_affected": len(plan.Changes)})
	})
	if err != nil {
		return nil, err
	}
	return plan, nil
}

func bySeverity(fs []checks.Finding) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		m[f.Check] = string(f.Severity)
	}
	return m
}

func union(a, b map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]string{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// ---------- escalation ----------

// EscalateAlerts re-notifies open (unacknowledged) alerts older than the
// org's escalation.after, once per interval, raising escalation_level.
func (s *Service) EscalateAlerts(ctx context.Context) (int, error) {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	var errs []error
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			now := s.now()
			// Acknowledging is not accepting the risk: an acked alert whose
			// finding is still open comes back, even with escalation off.
			ackFor := time.Duration(pv.Document.Spec.Alerts.AckExpiry)
			alertIDs, findingIDs, err := tx.ExpireAcks(ctx, ackFor)
			if err != nil {
				return err
			}
			for i, fid := range findingIDs {
				f, err := tx.GetFinding(ctx, fid)
				if err != nil {
					return err
				}
				n := notificationFor(org, "alert.ack_expired", f.SubjectType+" "+f.SubjectID, *f, now)
				n.Message = fmt.Sprintf("Acknowledged over %s ago and still open: %s", policy.FormatDuration(ackFor), f.Message)
				if err := tx.EnqueueNotification(ctx, n, alertIDs[i]+":ackexp:"+now.UTC().Format(time.RFC3339)); err != nil {
					return err
				}
			}
			after := time.Duration(pv.Document.Spec.Escalation.After)
			if after == 0 {
				return nil
			}
			rows, err := tx.Query(ctx, `UPDATE alerts a SET escalation_level = a.escalation_level + 1, last_escalated_at = $1
				WHERE a.state = 'open' AND a.created_at <= $2 AND (a.last_escalated_at IS NULL OR a.last_escalated_at <= $2)
				RETURNING a.id, a.finding_id, a.escalation_level`, now, now.Add(-after))
			if err != nil {
				return err
			}
			type esc struct {
				id, finding string
				level       int
			}
			escs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (esc, error) {
				var e esc
				err := r.Scan(&e.id, &e.finding, &e.level)
				return e, err
			})
			if err != nil {
				return err
			}
			for _, e := range escs {
				f, err := tx.GetFinding(ctx, e.finding)
				if err != nil {
					return err
				}
				n := notificationFor(org, "alert.escalated", f.SubjectType+" "+f.SubjectID, *f, now)
				n.Message = fmt.Sprintf("Unacknowledged for over %s (escalation %d): %s", policy.FormatDuration(after), e.level, f.Message)
				if err := tx.EnqueueNotificationTo(ctx, n, fmt.Sprintf("%s:esc%d", e.id, e.level), pv.Document.Spec.Escalation.Channels); err != nil {
					return err
				}
				total++
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return total, errors.Join(errs...)
}

// ---------- pruning ----------

// PruneResult reports what Prune removed.
type PruneResult struct {
	Observations, IdempotencyKeys, Sessions int64
}

// Prune deletes observations older than each org's retention (always keeping
// the latest observation per endpoint), idempotency keys older than 24h, and
// sessions that expired more than 7 days ago.
func (s *Service) Prune(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return res, err
	}
	var errs []error
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			cutoff := s.now().Add(-time.Duration(pv.Document.Spec.Retention.Observations))
			tag, err := tx.Exec(ctx, `DELETE FROM observations o WHERE o.observed_at < $1
				AND o.id <> (SELECT max(id) FROM observations x WHERE x.endpoint_id = o.endpoint_id)`, cutoff)
			if err != nil {
				return err
			}
			res.Observations += tag.RowsAffected()
			if tag, err = tx.Exec(ctx, `DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours'`); err != nil {
				return err
			}
			res.IdempotencyKeys += tag.RowsAffected()
			if tag, err = tx.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now() - interval '7 days'`); err != nil {
				return err
			}
			res.Sessions += tag.RowsAffected()
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return res, errors.Join(errs...)
}

func (s *Service) orgIDs(ctx context.Context) ([]string, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
