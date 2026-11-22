package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// storedInventory is what is kept of an inventory: observations, not the
// certificate files, which go into the certificate inventory instead.
type storedInventory struct {
	Certbot    []agentproto.CertbotLineage  `json:"certbot,omitempty"`
	IIS        []agentproto.IISBinding      `json:"iis,omitempty"`
	WinACME    []agentproto.WinACMERenewal  `json:"win_acme,omitempty"`
	Kubernetes *agentproto.KubeInventory    `json:"kubernetes,omitempty"`
	Cloud      *agentproto.CloudInventory   `json:"cloud,omitempty"`
	Plugins    []agentproto.PluginInventory `json:"plugins,omitempty"`
}

// importObservations stores an agent's IIS, win-acme and Kubernetes
// observations, imports the certificates they carry and syncs drift and
// Kubernetes findings. It returns the number of new certificates.
func (s *Service) importObservations(ctx context.Context, tx *store.Tx, agentID string, inv agentproto.InventoryOutput) (int, error) {
	if len(inv.IIS) == 0 && len(inv.WinACME) == 0 && inv.Kubernetes == nil && inv.Cloud == nil && len(inv.Certbot) == 0 && len(inv.Plugins) == 0 {
		return 0, nil
	}
	now := s.now()
	n := 0
	importPEM := func(chain, source string) error {
		if chain == "" {
			return nil
		}
		parsed, err := certparse.Parse([]byte(chain), secret.Value{})
		if err != nil {
			return nil //nolint:nilerr // unparsable observed data is skipped
		}
		for _, c := range parsed.Certificates {
			ins, err := tx.UpsertCertificate(ctx, c, source)
			if err != nil {
				return err
			}
			if ins {
				n++
			}
		}
		return nil
	}
	for i := range inv.IIS {
		if err := importPEM(inv.IIS[i].ChainPEM, "agent"); err != nil {
			return n, err
		}
		inv.IIS[i].ChainPEM = "" // the stored copy stays small
	}
	if inv.Kubernetes != nil {
		for _, c := range inv.Kubernetes.Certificates {
			if err := importPEM(c.ChainPEM, "kubernetes"); err != nil {
				return n, err
			}
		}
	}
	if inv.Cloud != nil {
		for _, o := range inv.Cloud.Objects {
			if err := importPEM(o.ChainPEM, o.Provider); err != nil {
				return n, err
			}
		}
	}
	// Plugin items are imported under source "plugin"; the stored copy keeps
	// where they were found and what uses them, not the PEMs.
	var plugins []agentproto.PluginInventory
	for _, pi := range inv.Plugins {
		items := make([]agentproto.PluginItem, 0, len(pi.Items))
		for _, it := range pi.Items {
			if err := importPEM(it.PEM, "plugin"); err != nil {
				return n, err
			}
			it.PEM = ""
			items = append(items, it)
		}
		pi.Items = items
		plugins = append(plugins, pi)
	}
	stored := storedInventory{Certbot: inv.Certbot, IIS: inv.IIS, WinACME: inv.WinACME, Kubernetes: inv.Kubernetes, Cloud: inv.Cloud, Plugins: plugins}
	if stored.Kubernetes != nil {
		k := *stored.Kubernetes
		k.Certificates = slices.Clone(k.Certificates)
		for i := range k.Certificates {
			k.Certificates[i].ChainPEM = ""
		}
		stored.Kubernetes = &k
	}
	if stored.Cloud != nil {
		c := *stored.Cloud
		c.Objects = slices.Clone(c.Objects)
		for i := range c.Objects {
			c.Objects[i].ChainPEM = ""
		}
		stored.Cloud = &c
	}
	if err := tx.SaveAgentInventory(ctx, agentID, stored, now); err != nil {
		return n, err
	}
	if inv.IIS != nil {
		if err := s.syncIISDrift(ctx, tx, agentID, inv.IIS, now); err != nil {
			return n, err
		}
	}
	if inv.Kubernetes != nil {
		if err := s.syncKube(ctx, tx, agentID, inv.Kubernetes, now); err != nil {
			return n, err
		}
	}
	if inv.Cloud != nil {
		if err := s.syncCloud(ctx, tx, agentID, inv.Cloud, now); err != nil {
			return n, err
		}
	}
	return n, nil
}

// syncIISDrift compares each IIS deployment of the agent with what HTTP.sys
// serves. Deployments with a run in progress are skipped: their binding is
// expected to change.
func (s *Service) syncIISDrift(ctx context.Context, tx *store.Tx, agentID string, seen []agentproto.IISBinding, now time.Time) error {
	a, err := tx.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}
	deps, err := tx.ListDeployments(ctx)
	if err != nil {
		return err
	}
	for _, d := range deps {
		if d.AgentID != agentID || !d.Enabled {
			continue
		}
		var tgt *agentproto.Target
		for i := range a.Capabilities.Targets {
			if a.Capabilities.Targets[i].Name == d.Target {
				tgt = &a.Capabilities.Targets[i]
			}
		}
		if tgt == nil || tgt.Type != agentproto.TargetIIS {
			continue
		}
		if _, err := tx.ActiveRunFor(ctx, d.ID); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		l, err := tx.LineageByRef(ctx, d.LineageID)
		if err != nil {
			return err
		}
		current := ""
		if l.CurrentSHA256 != nil {
			current = *l.CurrentSHA256
		}
		var obs []checks.ObservedBinding
		for _, b := range tgt.Bindings {
			o := checks.ObservedBinding{Binding: b}
			for _, x := range seen {
				if strings.EqualFold(x.Site, tgt.Site) && strings.EqualFold(x.Binding, b) {
					o.InSite, o.CertHash, o.CertSHA256 = true, x.CertHash, x.CertSHA256
				}
			}
			obs = append(obs, o)
		}
		res, err := tx.SyncFindings(ctx, "deployment", d.ID, checks.IISBindingDrift(current, obs), now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, a.Name+" "+tgt.Site+" ("+d.Target+")", res, now); err != nil {
			return err
		}
	}
	return nil
}

// kubeSubject names an observed Kubernetes object as a finding subject.
func kubeSubject(agentID, kind, namespace, name string) string {
	return agentID + "/" + kind + "/" + namespace + "/" + name
}

// syncKube raises findings for the cluster's certificates, the issuers they
// use and trust bundles, and resolves findings of objects that are gone.
// Kinds the agent could not list keep their findings.
func (s *Service) syncKube(ctx context.Context, tx *store.Tx, agentID string, k *agentproto.KubeInventory, now time.Time) error {
	present := map[string]bool{}
	sync := func(kind, ns, name string, fs []checks.Finding) error {
		id := kubeSubject(agentID, kind, ns, name)
		present[id] = true
		res, err := tx.SyncFindings(ctx, "k8s_object", id, fs, now)
		if err != nil {
			return err
		}
		label := k.Cluster + " " + kind + " " + strings.TrimPrefix(ns+"/"+name, "/")
		return notifySync(ctx, tx, label, res, now)
	}
	users := map[string]int{}
	for _, c := range k.Certificates {
		ns := ""
		if c.IssuerKind == "Issuer" {
			ns = c.Namespace // an Issuer is namespaced, a ClusterIssuer is not
		}
		users[c.IssuerKind+"/"+ns+"/"+c.IssuerName]++
		if err := sync("Certificate", c.Namespace, c.Name, checks.KubeCertificate(c, now, 0)); err != nil {
			return err
		}
	}
	for _, is := range k.Issuers {
		kind := "ClusterIssuer"
		if is.Namespace != "" {
			kind = "Issuer"
		}
		var fs []checks.Finding
		if n := users[kind+"/"+is.Namespace+"/"+is.Name]; n > 0 {
			fs = checks.KubeIssuer(is, n)
		}
		if err := sync(kind, is.Namespace, is.Name, fs); err != nil {
			return err
		}
	}
	for _, b := range k.Bundles {
		if err := sync("Bundle", "", b.Name, checks.KubeBundle(b)); err != nil {
			return err
		}
	}
	failed := strings.Join(k.Errors, " ")
	open, err := tx.OpenFindingSubjects(ctx, "k8s_object", agentID+"/")
	if err != nil {
		return err
	}
	for _, id := range open {
		if present[id] {
			continue
		}
		kind, _, _ := strings.Cut(strings.TrimPrefix(id, agentID+"/"), "/")
		if strings.Contains(failed, strings.ToLower(kind)+"s:") {
			continue // not listed this time, so not known to be gone
		}
		res, err := tx.SyncFindings(ctx, "k8s_object", id, nil, now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, k.Cluster+" "+strings.TrimPrefix(id, agentID+"/"), res, now); err != nil {
			return err
		}
	}
	return nil
}

// RequestDueInventories queues inventory tasks for agents that asked for
// periodic inventories (in-cluster agents, IIS hosts).
func (s *Service) RequestDueInventories(ctx context.Context) error {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			now := s.now()
			due, err := tx.AgentsDueInventory(ctx, now)
			if err != nil {
				return err
			}
			for _, id := range due {
				if _, err := s.queueInventory(ctx, tx, id); err != nil {
					return err
				}
				if err := tx.MarkInventoryRequested(ctx, id, now); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// AgentInventory returns an agent's last stored observations.
func (s *Service) AgentInventory(ctx context.Context, p authz.Principal, ref string) (out map[string]any, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, ref)
		if err != nil {
			return err
		}
		data, at, err := tx.AgentInventory(ctx, a.ID)
		if err != nil {
			return err
		}
		out = map[string]any{"agent_id": a.ID, "reported_at": at, "inventory": data}
		return nil
	})
	return out, err
}
