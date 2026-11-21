package web

import (
	"context"
	"net/http"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Pages for the automated renewal side: agents, deployments and runs.

type agentRow struct {
	A           *store.Agent
	Health      string
	Deployments int
}

// healthClass maps an agent health string to a badge class.
func healthClass(h string) string {
	switch h {
	case "active":
		return "ok"
	case "stale", "never-seen":
		return "warning"
	case "offline", "revoked":
		return "critical"
	}
	return "info"
}

// runClass maps a run state to a badge class. Unknown states fall back to a
// neutral badge so new states render without changes here.
func runClass(state string) string {
	switch state {
	case store.RunVerified:
		return "ok"
	case store.RunFailed, store.RunRolledBack:
		return "critical"
	case store.RunCancelled:
		return "info"
	case store.RunRetryScheduled, store.RunRollingBack:
		return "warning"
	}
	return "info"
}

// cancellable reports whether to offer a Cancel button for a run. The
// service makes the final decision; here we only hide the button for final
// states and for states where the target may already have been changed.
func cancellable(state string) bool {
	if store.Terminal(state) {
		return false
	}
	switch state {
	case store.RunDeploying, store.RunVerifying, store.RunRollingBack:
		return false
	}
	return true
}

// names resolves lineage, agent and issuer ids to display names.
type names struct {
	Lineage, Agent, Issuer map[string]string
}

func (u *UI) loadNames(ctx context.Context, p authz.Principal) (*names, error) {
	n := &names{Lineage: map[string]string{}, Agent: map[string]string{}, Issuer: map[string]string{}}
	ls, err := u.svc.ListLineages(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, l := range ls {
		n.Lineage[l.ID] = l.Name
	}
	as, err := u.svc.ListAgents(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		n.Agent[a.ID] = a.Name
	}
	is, err := u.svc.ListIssuers(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, i := range is {
		n.Issuer[i.ID] = i.Name
	}
	return n, nil
}

func nameOr(m map[string]string, id string) string {
	if v, ok := m[id]; ok && v != "" {
		return v
	}
	return id
}

type deploymentRow struct {
	D       *store.Deployment
	Lineage string
	Agent   string
	Issuer  string
	LastRun *store.Run
}

func (u *UI) deploymentRows(ctx context.Context, p authz.Principal) ([]deploymentRow, map[string]deploymentRow, error) {
	ds, err := u.svc.ListDeployments(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	n, err := u.loadNames(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	runs, err := u.svc.ListRuns(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	last := map[string]*store.Run{}
	for _, r := range runs { // newest first
		if _, ok := last[r.DeploymentID]; !ok {
			last[r.DeploymentID] = r
		}
	}
	rows := make([]deploymentRow, 0, len(ds))
	byID := make(map[string]deploymentRow, len(ds))
	for _, d := range ds {
		row := deploymentRow{D: d, Lineage: nameOr(n.Lineage, d.LineageID), Agent: nameOr(n.Agent, d.AgentID),
			Issuer: nameOr(n.Issuer, d.IssuerID), LastRun: last[d.ID]}
		rows = append(rows, row)
		byID[d.ID] = row
	}
	return rows, byID, nil
}

func (u *UI) agents(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	as, err := u.svc.ListAgents(r.Context(), p)
	if err != nil {
		return err
	}
	ds, err := u.svc.ListDeployments(r.Context(), p)
	if err != nil {
		return err
	}
	count := map[string]int{}
	for _, d := range ds {
		count[d.AgentID]++
	}
	now := time.Now()
	rows := make([]agentRow, 0, len(as))
	for _, a := range as {
		rows = append(rows, agentRow{A: a, Health: a.Health(now), Deployments: count[a.ID]})
	}
	return u.render(w, r, "agents", p, "Agents", "agents", rows)
}

func (u *UI) agent(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	as, err := u.svc.ListAgents(r.Context(), p)
	if err != nil {
		return err
	}
	var a *store.Agent
	for _, x := range as {
		if x.ID == r.PathValue("id") {
			a = x
		}
	}
	if a == nil {
		return store.ErrNotFound
	}
	rows, _, err := u.deploymentRows(r.Context(), p)
	if err != nil {
		return err
	}
	mine := rows[:0]
	for _, d := range rows {
		if d.D.AgentID == a.ID {
			mine = append(mine, d)
		}
	}
	return u.render(w, r, "agent", p, a.Name, "agents", map[string]any{"A": a, "Health": a.Health(time.Now()),
		"Deployments": mine})
}

func (u *UI) deployments(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	rows, _, err := u.deploymentRows(r.Context(), p)
	if err != nil {
		return err
	}
	return u.render(w, r, "deployments", p, "Deployments", "deployments", map[string]any{"Deployments": rows,
		"CanRenew": p.Can(authz.RunRenewals)})
}

func (u *UI) renew(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	run, err := u.svc.RequestRenewal(r.Context(), p, r.PathValue("id"))
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/runs/"+run.ID+"?flash=Renewal+started", http.StatusSeeOther)
	return nil
}

func (u *UI) runs(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	runs, err := u.svc.ListRuns(r.Context(), p)
	if err != nil {
		return err
	}
	_, deps, err := u.deploymentRows(r.Context(), p)
	if err != nil {
		return err
	}
	return u.render(w, r, "runs", p, "Runs", "runs", map[string]any{"Runs": runs, "Deps": deps})
}

func (u *UI) run(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	run, err := u.svc.GetRun(r.Context(), p, r.PathValue("id"))
	if err != nil {
		return err
	}
	_, deps, err := u.deploymentRows(r.Context(), p)
	if err != nil {
		return err
	}
	dep, ok := deps[run.DeploymentID]
	return u.render(w, r, "run", p, "Run "+run.ID, "runs", map[string]any{"R": run, "Dep": dep, "HasDep": ok,
		"CanCancel": p.Can(authz.RunRenewals) && cancellable(run.State)})
}

func (u *UI) cancelRun(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	id := r.PathValue("id")
	if err := u.svc.CancelRun(r.Context(), p, id); err != nil {
		return err
	}
	http.Redirect(w, r, "/runs/"+id+"?flash=Run+cancelled", http.StatusSeeOther)
	return nil
}
