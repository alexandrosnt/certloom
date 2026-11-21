package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/store"
)

// cloudSubject names an observed cloud object as a finding subject. The
// scope is part of it so findings in a scope that could not be read are
// recognisable by prefix.
func cloudSubject(agentID, provider, scope, id string) string {
	return agentID + "/" + provider + "/" + scope + "/" + id
}

// syncCloud raises renewal and adoption findings for cloud objects and
// resolves findings of objects that are gone. Objects in scopes the agent
// could not read keep their findings.
func (s *Service) syncCloud(ctx context.Context, tx *store.Tx, agentID string, c *agentproto.CloudInventory, now time.Time) error {
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return err
	}
	pol := pv.Document.Checks()
	present := map[string]bool{}
	for _, o := range c.Objects {
		fs := checks.CloudObject(o, now, pol)
		stale, err := staleConsumers(ctx, tx, o)
		if err != nil {
			return err
		}
		fs = append(fs, checks.CloudVersionNotAdopted(o, now, stale)...)
		id := cloudSubject(agentID, o.Provider, o.Scope, o.ID)
		present[id] = true
		res, err := tx.SyncFindings(ctx, "cloud_object", id, fs, now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, checks.CloudLabel(o), res, now); err != nil {
			return err
		}
	}
	var unread []string
	for _, e := range c.Errors {
		unread = append(unread, cloudSubject(agentID, e.Provider, e.Scope, ""))
	}
	open, err := tx.OpenFindingSubjects(ctx, "cloud_object", agentID+"/")
	if err != nil {
		return err
	}
	for _, id := range open {
		if present[id] || hasAnyPrefix(id, unread) {
			continue
		}
		res, err := tx.SyncFindings(ctx, "cloud_object", id, nil, now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, strings.TrimPrefix(id, agentID+"/"), res, now); err != nil {
			return err
		}
	}
	return nil
}

// staleConsumers lists probed endpoints that serve the previous enabled
// version of a versioned certificate.
func staleConsumers(ctx context.Context, tx *store.Tx, o agentproto.CloudObject) ([]string, error) {
	if len(o.Versions) < 2 || !o.Versions[0].Enabled || o.Versions[0].SHA256 == "" {
		return nil, nil
	}
	prev := ""
	for _, v := range o.Versions[1:] {
		if v.Enabled && v.SHA256 != "" {
			prev = v.SHA256
			break
		}
	}
	if prev == "" || prev == o.Versions[0].SHA256 {
		return nil, nil
	}
	eps, err := tx.EndpointsServing(ctx, prev)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range eps {
		name := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if e.SNI != "" && e.SNI != e.Host {
			name += " (" + e.SNI + ")"
		}
		out = append(out, name)
	}
	return out, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func cloudCount(c *agentproto.CloudInventory) int {
	if c == nil {
		return 0
	}
	return len(c.Objects)
}
