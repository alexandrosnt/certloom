package app

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/cagraph"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// linkBatch and linkBatches bound the backfill done by one sweep.
const (
	linkBatch   = 1000
	linkBatches = 50
)

// storeBundle adds the CA certificates of an issuer's CA bundle to the
// inventory, so the roots above a private CA's chain are known.
func storeBundle(ctx context.Context, tx *store.Tx, bundle string) error {
	if strings.TrimSpace(bundle) == "" {
		return nil
	}
	parsed, err := certparse.Parse([]byte(bundle), secret.Value{})
	if err != nil {
		return invalid("ca_bundle: %s", err.Error())
	}
	for _, c := range parsed.Certificates {
		if !c.IsCA {
			continue
		}
		if _, err := tx.UpsertCertificate(ctx, c, "issuer"); err != nil {
			return err
		}
	}
	return nil
}

// linkPending links certificates stored before the CA inventory existed.
func linkPending(ctx context.Context, tx *store.Tx) error {
	for range linkBatches {
		n, err := tx.LinkPendingCertificates(ctx, linkBatch)
		if err != nil || n < linkBatch {
			return err
		}
	}
	return nil
}

// chainView answers "when does the chain above this certificate end".
type chainView struct {
	graph  *cagraph.Graph
	issuer map[string]string // leaf sha256 -> authority key
}

func loadChainView(ctx context.Context, tx *store.Tx, now time.Time) (*chainView, error) {
	g, err := tx.AuthorityGraph(ctx)
	if err != nil {
		return nil, err
	}
	m, err := tx.LeafIssuers(ctx, now)
	if err != nil {
		return nil, err
	}
	return &chainView{graph: g, issuer: m}, nil
}

func (v *chainView) findings(c *certparse.Certificate, now time.Time) []checks.Finding {
	k, ok := v.issuer[c.SHA256]
	if !ok {
		return nil
	}
	exp, ok := v.graph.Expiry(k)
	if !ok {
		return nil
	}
	return checks.ChainOutlived(c, exp, now)
}

// inUse returns the authorities that sign, directly or through
// intermediates, a lineage's current certificate or a served leaf.
func inUse(ctx context.Context, tx *store.Tx, g *cagraph.Graph) (map[string]bool, error) {
	direct, err := tx.AuthoritiesInUse(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, k := range direct {
		for _, a := range g.Ancestors(k) {
			out[a] = true
		}
	}
	return out, nil
}

// syncAuthorities evaluates ca_expiring for every authority in use and
// resolves it for authorities no longer in use.
func (s *Service) syncAuthorities(ctx context.Context, tx *store.Tx, g *cagraph.Graph, now time.Time, pol checks.Policy) error {
	used, err := inUse(ctx, tx, g)
	if err != nil {
		return err
	}
	open, err := tx.OpenAuthorityFindings(ctx)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(used)+len(open))
	for k := range used {
		keys = append(keys, k)
	}
	for _, k := range open {
		if !used[k] {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		a := g.Get(k)
		var fs []checks.Finding
		if used[k] && a != nil {
			in := checks.AuthorityInput{Key: k, Subject: a.Subject, Root: a.Root, Expiry: a.Expiry, Now: now, Policy: pol}
			if fs = checks.Authority(in); len(fs) > 0 {
				// Only authorities near expiry need the trust lookup.
				in.PubliclyTrusted = s.publiclyTrusted(ctx, tx, a)
				fs = checks.Authority(in)
			}
		}
		res, err := tx.SyncFindings(ctx, "authority", k, fs, now)
		if err != nil {
			return err
		}
		label := k
		if a != nil {
			label = a.Subject
		}
		if err := notifySync(ctx, tx, label, res, now); err != nil {
			return err
		}
	}
	return nil
}

// publiclyTrusted reports whether any copy of the authority chains to the
// trust anchors used for endpoint checks (the system roots by default).
func (s *Service) publiclyTrusted(ctx context.Context, tx *store.Tx, a *cagraph.Authority) bool {
	inters, err := tx.KnownIntermediates(ctx)
	if err != nil {
		return false
	}
	pool := x509.NewCertPool()
	for _, c := range inters {
		pool.AddCert(c)
	}
	for _, cp := range a.Copies {
		row, err := tx.GetCertificate(ctx, cp.SHA256)
		if err != nil {
			continue
		}
		at := cp.NotAfter.Add(-time.Second)
		if n := s.now(); n.Before(at) {
			at = n
		}
		_, err = row.X509.Verify(x509.VerifyOptions{Roots: s.Roots, Intermediates: pool, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err == nil {
			return true
		}
	}
	return false
}

// ---------- queries ----------

// AuthoritySummary is one authority with what depends on it.
type AuthoritySummary struct {
	*cagraph.Authority
	InUse  bool `json:"in_use"`
	Leaves int  `json:"leaves"` // unexpired certificates it signs directly
}

// AuthorityFilter narrows ListAuthorities.
type AuthorityFilter struct {
	Roots         bool
	Intermediates bool
	InUse         bool
}

// ListAuthorities lists CA authorities, soonest expiry first.
func (s *Service) ListAuthorities(ctx context.Context, p authz.Principal, f AuthorityFilter) (out []AuthoritySummary, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		g, err := tx.AuthorityGraph(ctx)
		if err != nil {
			return err
		}
		used, err := inUse(ctx, tx, g)
		if err != nil {
			return err
		}
		leaves, err := tx.CountLeavesUnder(ctx, s.now())
		if err != nil {
			return err
		}
		out = []AuthoritySummary{}
		for _, a := range g.All() {
			if (f.Roots && !a.Root) || (f.Intermediates && a.Root) || (f.InUse && !used[a.Key]) {
				continue
			}
			out = append(out, AuthoritySummary{Authority: a, InUse: used[a.Key], Leaves: leaves[a.Key]})
		}
		return nil
	})
	return out, err
}

// resolveAuthority accepts a full key or a unique prefix of at least 8
// characters.
func resolveAuthority(g *cagraph.Graph, ref string) (*cagraph.Authority, error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if a := g.Get(ref); a != nil {
		return a, nil
	}
	if len(ref) < 8 {
		return nil, store.ErrNotFound
	}
	var found *cagraph.Authority
	for _, a := range g.All() {
		if strings.HasPrefix(a.Key, ref) {
			if found != nil {
				return nil, invalid("authority prefix %q is ambiguous", ref)
			}
			found = a
		}
	}
	if found == nil {
		return nil, store.ErrNotFound
	}
	return found, nil
}

// ImpactLineage is a lineage whose current certificate chains through the
// authority.
type ImpactLineage struct {
	store.LeafLink
	ChainExpiry time.Time `json:"chain_expiry"`
	// Outlives is true when the certificate is valid after its chain ends:
	// it must be renewed before ChainExpiry.
	Outlives    bool                  `json:"outlives_chain"`
	Deployments []store.LineageDeploy `json:"deployments,omitempty"`
}

// AuthorityImpact is everything that depends on one authority.
type AuthorityImpact struct {
	Authority *cagraph.Authority   `json:"authority"`
	InUse     bool                 `json:"in_use"`
	Below     []string             `json:"authorities_below,omitempty"`
	Lineages  []ImpactLineage      `json:"lineages"`
	Endpoints []store.EndpointLink `json:"endpoints"`
	Issuers   []string             `json:"issuers,omitempty"` // issuer ids of the affected deployments
}

// GetAuthorityImpact lists what chains through an authority.
func (s *Service) GetAuthorityImpact(ctx context.Context, p authz.Principal, ref string) (out *AuthorityImpact, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		g, err := tx.AuthorityGraph(ctx)
		if err != nil {
			return err
		}
		a, err := resolveAuthority(g, ref)
		if err != nil {
			return err
		}
		out, err = s.impact(ctx, tx, g, a)
		return err
	})
	return out, err
}

func (s *Service) impact(ctx context.Context, tx *store.Tx, g *cagraph.Graph, a *cagraph.Authority) (*AuthorityImpact, error) {
	keys := g.Descendants(a.Key)
	used, err := inUse(ctx, tx, g)
	if err != nil {
		return nil, err
	}
	out := &AuthorityImpact{Authority: a, InUse: used[a.Key], Below: keys[1:], Lineages: []ImpactLineage{}}
	leaves, err := tx.LineagesUnder(ctx, keys)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(leaves))
	for _, l := range leaves {
		ids = append(ids, l.LineageID)
	}
	deps, err := tx.DeploymentsForLineages(ctx, ids)
	if err != nil {
		return nil, err
	}
	issuers := map[string]bool{}
	for _, l := range leaves {
		exp, _ := g.Expiry(l.IssuerKey)
		il := ImpactLineage{LeafLink: l, ChainExpiry: exp, Outlives: l.NotAfter.After(exp), Deployments: deps[l.LineageID]}
		for _, d := range il.Deployments {
			issuers[d.IssuerID] = true
		}
		out.Lineages = append(out.Lineages, il)
	}
	for id := range issuers {
		out.Issuers = append(out.Issuers, id)
	}
	slices.Sort(out.Issuers)
	if out.Endpoints, err = tx.EndpointsUnder(ctx, keys); err != nil {
		return nil, err
	}
	if out.Endpoints == nil {
		out.Endpoints = []store.EndpointLink{}
	}
	return out, nil
}

// PlanItem is one authority that expires within the planning window.
type PlanItem struct {
	Key       string    `json:"key"`
	Subject   string    `json:"subject"`
	Root      bool      `json:"root"`
	Expiry    time.Time `json:"expiry"`
	Lineages  int       `json:"lineages"`
	Outliving int       `json:"outliving_lineages"`
	Endpoints int       `json:"endpoints"`
	// RenewBy is when outliving lineages must have been renewed.
	RenewBy *time.Time `json:"renew_by,omitempty"`
}

// AuthorityPlan lists authorities in use that expire within the window.
func (s *Service) AuthorityPlan(ctx context.Context, p authz.Principal, within time.Duration) (out []PlanItem, err error) {
	if within <= 0 || within > 10*365*24*time.Hour {
		return nil, invalid("window must be between 1s and 10 years")
	}
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		g, err := tx.AuthorityGraph(ctx)
		if err != nil {
			return err
		}
		used, err := inUse(ctx, tx, g)
		if err != nil {
			return err
		}
		horizon := s.now().Add(within)
		out = []PlanItem{}
		for _, a := range g.All() {
			if !used[a.Key] || a.Expiry.After(horizon) {
				continue
			}
			im, err := s.impact(ctx, tx, g, a)
			if err != nil {
				return err
			}
			it := PlanItem{Key: a.Key, Subject: a.Subject, Root: a.Root, Expiry: a.Expiry, Lineages: len(im.Lineages), Endpoints: len(im.Endpoints)}
			for _, l := range im.Lineages {
				if l.Outlives {
					it.Outliving++
					if it.RenewBy == nil || l.ChainExpiry.Before(*it.RenewBy) {
						t := l.ChainExpiry
						it.RenewBy = &t
					}
				}
			}
			out = append(out, it)
		}
		return nil
	})
	return out, err
}

// RenewAffectedResult reports what renew-affected did per deployment.
type RenewAffectedResult struct {
	Authority string          `json:"authority"`
	DryRun    bool            `json:"dry_run"`
	Items     []RenewAffected `json:"items"`
}

// RenewAffected is one deployment considered for renewal.
type RenewAffected struct {
	DeploymentID string `json:"deployment_id"`
	LineageName  string `json:"lineage"`
	RunID        string `json:"run_id,omitempty"`
	// Skipped says why no run was started.
	Skipped string `json:"skipped,omitempty"`
}

// RenewAffectedDeployments starts a renewal run for each enabled deployment
// whose current certificate chains through the authority and outlives the
// chain (or every such deployment with all). Each run is started on its
// own, so one refusal does not stop the others.
func (s *Service) RenewAffectedDeployments(ctx context.Context, p authz.Principal, ref string, all, dryRun bool) (*RenewAffectedResult, error) {
	var im *AuthorityImpact
	err := s.tx(ctx, p, authz.RunRenewals, func(tx *store.Tx) error {
		g, err := tx.AuthorityGraph(ctx)
		if err != nil {
			return err
		}
		a, err := resolveAuthority(g, ref)
		if err != nil {
			return err
		}
		im, err = s.impact(ctx, tx, g, a)
		return err
	})
	if err != nil {
		return nil, err
	}
	res := &RenewAffectedResult{Authority: im.Authority.Key, DryRun: dryRun, Items: []RenewAffected{}}
	var started []string
	for _, l := range im.Lineages {
		if !all && !l.Outlives {
			continue
		}
		for _, d := range l.Deployments {
			it := RenewAffected{DeploymentID: d.ID, LineageName: l.LineageName}
			switch {
			case !d.Enabled:
				it.Skipped = "deployment is disabled"
			case dryRun:
			default:
				err := s.tx(ctx, p, authz.RunRenewals, func(tx *store.Tx) error {
					r, err := s.startRun(ctx, tx, d.ID, "ca_rollover", p.Actor)
					if err != nil {
						return err
					}
					it.RunID = r.ID
					return nil
				})
				switch {
				case err == nil:
					started = append(started, it.RunID)
				case errors.Is(err, ErrInvalid), errors.Is(err, store.ErrConflict):
					it.Skipped = err.Error()
				default:
					return nil, err
				}
			}
			res.Items = append(res.Items, it)
		}
	}
	if dryRun {
		return res, nil
	}
	err = s.tx(ctx, p, authz.RunRenewals, func(tx *store.Tx) error {
		return s.audit(ctx, tx, p, "authorities.renew_affected", "authority", im.Authority.Key, map[string]any{
			"subject": im.Authority.Subject, "all": all, "runs": started, "considered": len(res.Items)})
	})
	return res, err
}
