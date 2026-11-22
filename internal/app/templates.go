package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certtemplate"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Certificate templates (ADR-0020). Deployments reference a template; an
// apply re-resolves every deployment that uses it in the same transaction.

// TemplateChange is a deployment whose resolved values an apply changes.
type TemplateChange struct {
	Deployment    string   `json:"deployment"`
	Changed       []string `json:"changed"`
	NeedsApproval bool     `json:"needs_approval"`
}

// TemplateViolation is a deployment the new template would not allow.
type TemplateViolation struct {
	Deployment string   `json:"deployment"`
	Problems   []string `json:"problems"`
}

// TemplatePlan is the result of validating (and optionally applying) a template.
type TemplatePlan struct {
	Applied        bool                   `json:"applied"`
	Name           string                 `json:"name"`
	Version        int                    `json:"version,omitempty"`
	CurrentVersion int                    `json:"current_version"`
	Changes        []TemplateChange       `json:"changes"`
	Violations     []TemplateViolation    `json:"violations"`
	Document       *certtemplate.Document `json:"document"`
}

// resolved is what a deployment takes from its template.
type resolved struct {
	issuer    *store.Issuer
	challenge string
	keyAlg    string
}

func (s *Service) resolveTemplate(ctx context.Context, tx *store.Tx, doc *certtemplate.Document) (*store.Issuer, error) {
	iss, err := tx.GetIssuer(ctx, doc.Spec.Issuer)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("template issuer %q not found", doc.Spec.Issuer)
	}
	return iss, err
}

// ApplyTemplate validates src, computes its impact on the deployments using
// the template, and stores it as a new version unless dryRun. It refuses
// while any deployment would break the new constraints.
func (s *Service) ApplyTemplate(ctx context.Context, p authz.Principal, src []byte, dryRun bool) (*TemplatePlan, error) {
	doc, err := certtemplate.Parse(src)
	if err != nil {
		return nil, invalid("%v", err)
	}
	plan := &TemplatePlan{Name: doc.Metadata.Name, Document: doc, Changes: []TemplateChange{}, Violations: []TemplateViolation{}}
	err = s.tx(ctx, p, authz.ManageTemplates, func(tx *store.Tx) error {
		if err := tx.LockTemplate(ctx, doc.Metadata.Name); err != nil {
			return err
		}
		iss, err := s.resolveTemplate(ctx, tx, doc)
		if err != nil {
			return err
		}
		var deps []*store.Deployment
		cur, err := tx.GetTemplate(ctx, doc.Metadata.Name)
		switch {
		case err == nil:
			plan.CurrentVersion = cur.Version
			if deps, err = tx.DeploymentsUsingTemplate(ctx, cur.ID); err != nil {
				return err
			}
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		pv, err := tx.ActivePolicy(ctx)
		if err != nil {
			return err
		}
		needApproval := approvalNeeded(p, pv.Document)
		type update struct {
			d   *store.Deployment
			r   resolved
			chg TemplateChange
		}
		var updates []update
		for _, d := range deps {
			var problems []string
			r := resolved{issuer: iss, challenge: doc.Spec.Challenge, keyAlg: d.KeyAlgorithm}
			if iss.Native() {
				r.challenge = agentproto.ChallengeNone
			}
			if !slices.Contains(doc.Spec.KeyAlgorithms, d.KeyAlgorithm) {
				problems = append(problems, fmt.Sprintf("key algorithm %s is no longer allowed", d.KeyAlgorithm))
			}
			problems = append(problems, doc.CheckNames(d.SANs)...)
			if len(problems) > 0 {
				plan.Violations = append(plan.Violations, TemplateViolation{Deployment: d.ID, Problems: problems})
				continue
			}
			chg := TemplateChange{Deployment: d.ID}
			if d.IssuerID != iss.ID {
				chg.Changed = append(chg.Changed, "issuer")
			}
			if d.Challenge != r.challenge {
				chg.Changed = append(chg.Changed, "challenge")
			}
			if len(chg.Changed) == 0 {
				continue
			}
			chg.NeedsApproval = needApproval && d.Approval != store.ApprovalDenied && d.Approval != store.ApprovalRevoked
			plan.Changes = append(plan.Changes, chg)
			updates = append(updates, update{d, r, chg})
		}
		if dryRun {
			return nil
		}
		if len(plan.Violations) > 0 {
			return invalid("%d deployment(s) would break the new template; fix them or the template first (see the plan)", len(plan.Violations))
		}
		id, v, err := tx.SaveTemplate(ctx, doc, string(src), p.Actor)
		if err != nil {
			return err
		}
		plan.Version, plan.Applied = v, true
		for _, u := range updates {
			if err := s.reresolveDeployment(ctx, tx, p, pv, u.d, u.r, u.chg.NeedsApproval); err != nil {
				return err
			}
			if err := s.audit(ctx, tx, p, "deployments.template_resolve", "deployment", u.d.ID, map[string]any{"template": id,
				"version": v, "changed": u.chg.Changed, "issuer": u.r.issuer.ID, "challenge": u.r.challenge, "needs_approval": u.chg.NeedsApproval}); err != nil {
				return err
			}
		}
		if err := s.emit(ctx, tx, "template.applied", fmt.Sprintf("%s:%d", id, v), map[string]any{"template_id": id, "name": doc.Metadata.Name,
			"version": v, "deployments_changed": len(plan.Changes)}); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "templates.apply", "template", id, map[string]any{"name": doc.Metadata.Name, "version": v,
			"previous_version": plan.CurrentVersion, "deployments_changed": len(plan.Changes)})
	})
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// reresolveDeployment stores the new values and settles the approval: a spec
// that was covered gets the new digest when the applier may approve it,
// otherwise it waits for a new approval.
func (s *Service) reresolveDeployment(ctx context.Context, tx *store.Tx, p authz.Principal, pv *store.PolicyVersion,
	d *store.Deployment, r resolved, needApproval bool) error {
	if err := tx.SetDeploymentResolved(ctx, d.ID, r.issuer.ID, r.challenge, r.keyAlg); err != nil {
		return err
	}
	d.IssuerID, d.Challenge, d.KeyAlgorithm = r.issuer.ID, r.challenge, r.keyAlg
	if d.Approval == store.ApprovalDenied || d.Approval == store.ApprovalRevoked {
		return nil
	}
	if err := tx.SupersedeApprovals(ctx, "deployment", d.ID, "deployment spec changed by a template apply"); err != nil {
		return err
	}
	spec, err := s.deploymentSpec(ctx, tx, d)
	if err != nil {
		return err
	}
	if needApproval {
		_, err := s.requestApproval(ctx, tx, d, spec, p.Actor, pv.Document)
		return err
	}
	digest := spec.SHA256()
	return tx.SetDeploymentApproval(ctx, d.ID, store.ApprovalApproved, &digest)
}

// ListTemplates lists templates at their current versions.
func (s *Service) ListTemplates(ctx context.Context, p authz.Principal) (out []*store.Template, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListTemplates(ctx); return err })
	return out, err
}

// GetTemplate returns one template.
func (s *Service) GetTemplate(ctx context.Context, p authz.Principal, ref string) (t *store.Template, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { t, err = tx.GetTemplate(ctx, ref); return err })
	return t, err
}

// DeleteTemplate removes a template no deployment uses.
func (s *Service) DeleteTemplate(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageTemplates, func(tx *store.Tx) error {
		t, err := tx.GetTemplate(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteTemplate(ctx, t.ID); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: template %s is used by %d deployment(s)", store.ErrConflict, t.Name, t.Deployments)
			}
			return err
		}
		return s.audit(ctx, tx, p, "templates.delete", "template", t.ID, map[string]any{"name": t.Name, "version": t.Version})
	})
}

// templateForDeployment applies a template to a new deployment's input and
// returns the template, or nil when none is used.
func templateForDeployment(ctx context.Context, tx *store.Tx, in *DeploymentInput) (*store.Template, error) {
	if in.Template == "" {
		return nil, nil
	}
	t, err := tx.GetTemplate(ctx, in.Template)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("template %q not found", in.Template)
	}
	if err != nil {
		return nil, err
	}
	s := t.Document.Spec
	iss, err := tx.GetIssuer(ctx, s.Issuer)
	if err != nil {
		return nil, invalid("template %s: issuer %q not found", t.Name, s.Issuer)
	}
	if in.Issuer != "" && in.Issuer != iss.Name && in.Issuer != iss.ID {
		return nil, invalid("template %s fixes the issuer to %s", t.Name, iss.Name)
	}
	if in.Challenge != "" && in.Challenge != s.Challenge {
		return nil, invalid("template %s fixes the challenge to %s", t.Name, s.Challenge)
	}
	if in.KeyAlgorithm != "" && !slices.Contains(s.KeyAlgorithms, in.KeyAlgorithm) {
		return nil, invalid("template %s does not allow key algorithm %s", t.Name, in.KeyAlgorithm)
	}
	if p := t.Document.CheckNames(in.SANs); len(p) > 0 {
		return nil, invalid("template %s: %s", t.Name, p[0])
	}
	in.Issuer, in.Challenge = iss.ID, s.Challenge
	if in.KeyAlgorithm == "" {
		in.KeyAlgorithm = s.KeyAlgorithms[0]
	}
	if in.Window == "" {
		in.Window = s.MaintenanceWindow
	}
	return t, nil
}
