package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/cagraph"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

const (
	maxBundleAnchors = 500
	trustTaskTTL     = 24 * time.Hour
	// trustResend is how long an unconfirmed version waits before it is sent again.
	trustResend = time.Hour
)

// TrustStoreRef names a trust store on an agent.
type TrustStoreRef struct {
	Agent string `json:"agent"`
	Store string `json:"store"`
}

// TrustBundleInput is the desired state of a bundle (ADR-0030).
type TrustBundleInput struct {
	Name    string
	Team    string
	Anchors []string // PEM; an entry may hold several certificates
	Stores  []TrustStoreRef
	// BaseVersion, when set, must equal the current version.
	BaseVersion *int
	DryRun      bool
	Force       bool
	Reason      string
}

// TrustAnchorInfo describes an anchor in a plan.
type TrustAnchorInfo struct {
	SHA256   string    `json:"sha256"`
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
}

// TrustPlan is what applying a bundle changes.
type TrustPlan struct {
	Bundle        string            `json:"bundle"`
	FromVersion   int               `json:"from_version"`
	ToVersion     int               `json:"to_version"`
	Added         []TrustAnchorInfo `json:"added"`
	Removed       []TrustAnchorInfo `json:"removed"`
	StoresAdded   []TrustStoreRef   `json:"stores_added"`
	StoresRemoved []TrustStoreRef   `json:"stores_removed"`
	// Blockers are why removing anchors is unsafe now; apply refuses them
	// unless forced.
	Blockers []string `json:"blockers"`
	Applied  bool     `json:"applied"`
	Forced   bool     `json:"forced,omitempty"`
}

func anchorDigest(hashes []string) string {
	h := sha256.New()
	for _, s := range hashes {
		h.Write([]byte(s))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func parseAnchors(pems []string) ([]*certparse.Certificate, error) {
	seen := map[string]bool{}
	var out []*certparse.Certificate
	for _, p := range pems {
		res, err := certparse.Parse([]byte(p), secret.Value{})
		if err != nil {
			return nil, invalid("anchor: %s", err.Error())
		}
		if res.PrivateKeySeen {
			return nil, invalid("anchors must not contain private keys")
		}
		for _, c := range res.Certificates {
			if !c.IsCA {
				return nil, invalid("anchor %s is not a CA certificate", c.Subject)
			}
			if !seen[c.SHA256] {
				seen[c.SHA256] = true
				out = append(out, c)
			}
		}
	}
	if len(out) > maxBundleAnchors {
		return nil, invalid("a bundle holds at most %d anchors", maxBundleAnchors)
	}
	slices.SortFunc(out, func(a, b *certparse.Certificate) int { return strings.Compare(a.SHA256, b.SHA256) })
	return out, nil
}

func validBundleName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// ApplyTrustBundle plans and, unless DryRun, applies a bundle's desired state:
// a new version when the anchors change, the store assignments, and a
// trust.apply task for every store that has not confirmed the version.
func (s *Service) ApplyTrustBundle(ctx context.Context, p authz.Principal, in TrustBundleInput) (*TrustPlan, error) {
	if !validBundleName(in.Name) {
		return nil, invalid("name must be 1-64 characters of a-z, 0-9, - and _")
	}
	if in.Force && strings.TrimSpace(in.Reason) == "" {
		return nil, invalid("--force needs a reason")
	}
	anchors, err := parseAnchors(in.Anchors)
	if err != nil {
		return nil, err
	}
	plan := &TrustPlan{Bundle: in.Name, Added: []TrustAnchorInfo{}, Removed: []TrustAnchorInfo{}, StoresAdded: []TrustStoreRef{},
		StoresRemoved: []TrustStoreRef{}, Blockers: []string{}}
	var blocked error
	err = s.tx(ctx, p, authz.ManageTrust, func(tx *store.Tx) error {
		b, err := tx.GetTrustBundle(ctx, in.Name, true)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var cur []string
		var assigned []*store.TrustAssignment
		if b != nil {
			plan.FromVersion = b.CurrentVersion
			if b.CurrentVersion > 0 {
				v, err := tx.GetTrustBundleVersion(ctx, b.ID, b.CurrentVersion)
				if err != nil {
					return err
				}
				cur = v.Anchors
			}
			if assigned, err = tx.TrustAssignments(ctx, b.ID); err != nil {
				return err
			}
		}
		if in.BaseVersion != nil && *in.BaseVersion != plan.FromVersion {
			return fmt.Errorf("%w: bundle %s is at version %d, not %d; plan again", store.ErrConflict, in.Name, plan.FromVersion, *in.BaseVersion)
		}
		var teamID *string
		if in.Team != "" {
			t, err := tx.TeamByRef(ctx, in.Team)
			if err != nil {
				return err
			}
			teamID = &t.ID
		}

		want := make([]string, 0, len(anchors))
		for _, c := range anchors {
			want = append(want, c.SHA256)
			if !slices.Contains(cur, c.SHA256) {
				plan.Added = append(plan.Added, TrustAnchorInfo{SHA256: c.SHA256, Subject: c.Subject, NotAfter: c.NotAfter})
			}
		}
		var removed []*store.CertificateRow
		for _, h := range cur {
			if slices.Contains(want, h) {
				continue
			}
			c, err := tx.GetCertificate(ctx, h)
			if err != nil {
				return err
			}
			removed = append(removed, c)
			plan.Removed = append(plan.Removed, TrustAnchorInfo{SHA256: h, Subject: c.Subject, NotAfter: c.NotAfter})
		}
		changed := b == nil || b.CurrentVersion == 0 || anchorDigest(want) != anchorDigest(cur)
		plan.ToVersion = plan.FromVersion
		if changed {
			plan.ToVersion = plan.FromVersion + 1
		}

		wantStores, err := s.resolveTrustStores(ctx, tx, in.Stores, b)
		if err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, a := range assigned {
			ref := TrustStoreRef{Agent: a.AgentName, Store: a.Store}
			if _, ok := wantStores[a.AgentID+"/"+a.Store]; ok {
				keep[a.AgentID+"/"+a.Store] = true
			} else {
				plan.StoresRemoved = append(plan.StoresRemoved, ref)
			}
		}
		for k, ref := range wantStores {
			if !keep[k] {
				plan.StoresAdded = append(plan.StoresAdded, ref.ref)
			}
		}
		slices.SortFunc(plan.StoresAdded, func(a, b TrustStoreRef) int { return strings.Compare(a.Agent+"/"+a.Store, b.Agent+"/"+b.Store) })

		if len(removed) > 0 {
			if plan.Blockers, err = s.removalBlockers(ctx, tx, removed, assigned); err != nil {
				return err
			}
		}
		if len(plan.Blockers) > 0 && !in.Force {
			blocked = fmt.Errorf("%w: removing anchors now is unsafe: %s (use --force with a reason to override)", store.ErrConflict,
				strings.Join(plan.Blockers, "; "))
			return nil
		}
		plan.Forced = in.Force && len(plan.Blockers) > 0
		if in.DryRun {
			return nil
		}

		if b == nil {
			if b, err = tx.CreateTrustBundle(ctx, in.Name, teamID); err != nil {
				return err
			}
		}
		for _, c := range anchors {
			if _, err := tx.UpsertCertificate(ctx, c, "trust_bundle"); err != nil {
				return err
			}
		}
		if changed {
			v := &store.TrustBundleVersion{BundleID: b.ID, Version: plan.ToVersion, Anchors: want, Digest: anchorDigest(want), CreatedBy: p.Actor}
			if plan.Forced {
				v.ForceReason = in.Reason
			}
			if err := tx.AddTrustBundleVersion(ctx, v); err != nil {
				return err
			}
		}
		for _, a := range assigned {
			if !keep[a.AgentID+"/"+a.Store] {
				if err := tx.DeleteTrustAssignment(ctx, a.ID); err != nil {
					return err
				}
			}
		}
		for k, ws := range wantStores {
			if !keep[k] {
				if err := tx.AddTrustAssignment(ctx, b.ID, ws.agentID, ws.ref.Store); err != nil {
					return err
				}
			}
		}
		if err := s.sendDueTrust(ctx, tx, b.ID, time.Time{}); err != nil {
			return err
		}
		plan.Applied = true
		detail := map[string]any{"version": plan.ToVersion, "added": plan.Added, "removed": plan.Removed,
			"stores_added": plan.StoresAdded, "stores_removed": plan.StoresRemoved}
		if plan.Forced {
			detail["forced"], detail["reason"], detail["blockers"] = true, in.Reason, plan.Blockers
		}
		return s.audit(ctx, tx, p, "trust_bundles.apply", "trust_bundle", b.ID, detail)
	})
	if err != nil {
		return nil, err
	}
	if blocked != nil && !in.DryRun {
		return plan, blocked
	}
	return plan, nil
}

type resolvedStore struct {
	agentID string
	ref     TrustStoreRef
}

// resolveTrustStores checks that each store exists on its agent in manage
// mode and is not bound to another bundle.
func (s *Service) resolveTrustStores(ctx context.Context, tx *store.Tx, refs []TrustStoreRef, b *store.TrustBundle) (map[string]resolvedStore, error) {
	out := map[string]resolvedStore{}
	for _, r := range refs {
		a, err := tx.GetAgent(ctx, r.Agent)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", r.Agent, err)
		}
		i := slices.IndexFunc(a.Capabilities.TrustStores, func(t agentproto.TrustStoreInfo) bool { return t.Name == r.Store })
		switch {
		case i < 0:
			return nil, invalid("agent %s does not report a trust store %q (add it to trust_stores in the agent config)", a.Name, r.Store)
		case a.Capabilities.TrustStores[i].Mode != agentproto.TrustManage:
			return nil, invalid("trust store %s on %s is observe-only", r.Store, a.Name)
		}
		if cur, err := tx.TrustAssignmentFor(ctx, a.ID, r.Store); err == nil && (b == nil || cur.BundleID != b.ID) {
			return nil, fmt.Errorf("%w: %s/%s already receives bundle %s", store.ErrConflict, a.Name, r.Store, cur.BundleName)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		out[a.ID+"/"+r.Store] = resolvedStore{agentID: a.ID, ref: TrustStoreRef{Agent: a.Name, Store: r.Store}}
	}
	return out, nil
}

// removalBlockers lists why removing anchors would break something: a CA
// in use still chains to the anchor, or a store has not confirmed the
// current version (which may carry the successor).
func (s *Service) removalBlockers(ctx context.Context, tx *store.Tx, removed []*store.CertificateRow, assigned []*store.TrustAssignment) ([]string, error) {
	g, err := tx.AuthorityGraph(ctx)
	if err != nil {
		return nil, err
	}
	used, err := inUse(ctx, tx, g)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, c := range removed {
		k := cagraph.Key(c.X509)
		if used[k] {
			out = append(out, fmt.Sprintf("%s is still above certificates in use (certloom ca impact %s)", c.Subject, k[:16]))
		}
	}
	for _, a := range assigned {
		if a.ConfirmedVersion != a.CurrentVersion {
			out = append(out, fmt.Sprintf("%s/%s has not confirmed version %d", a.AgentName, a.Store, a.CurrentVersion))
		}
	}
	return out, nil
}

// sendDueTrust queues trust.apply for assignments of bundleID (all when
// empty) that have not confirmed the current version and were not sent it
// after resendBefore.
func (s *Service) sendDueTrust(ctx context.Context, tx *store.Tx, bundleID string, resendBefore time.Time) error {
	due, err := tx.TrustAssignmentsDue(ctx, resendBefore)
	if err != nil {
		return err
	}
	versions := map[string]*store.TrustBundleVersion{}
	for _, a := range due {
		if bundleID != "" && a.BundleID != bundleID {
			continue
		}
		v, ok := versions[a.BundleID]
		if !ok {
			if v, err = tx.GetTrustBundleVersion(ctx, a.BundleID, a.CurrentVersion); err != nil {
				return err
			}
			versions[a.BundleID] = v
		}
		p := agentproto.TrustApplyPayload{Store: a.Store, Bundle: a.BundleName, Version: v.Version, Digest: v.Digest, Anchors: []string{}}
		for _, h := range v.Anchors {
			c, err := tx.GetCertificate(ctx, h)
			if err != nil {
				return err
			}
			p.Anchors = append(p.Anchors, string(pemEncode(c.DER)))
		}
		t, err := s.signTask(tx.OrgID, a.AgentID, agentproto.TaskTrustApply, "", 0, p, trustTaskTTL)
		if err != nil {
			return err
		}
		env, err := agentproto.Sign(s.PKI.TaskKey, t)
		if err != nil {
			return err
		}
		if err := tx.InsertTask(ctx, t, env, nil); err != nil {
			return err
		}
		if err := tx.MarkTrustSent(ctx, a.ID, v.Version, s.now()); err != nil {
			return err
		}
	}
	return nil
}

// SendDueTrustBundles re-sends versions that stores have not confirmed.
func (s *Service) SendDueTrustBundles(ctx context.Context) error {
	if s.PKI == nil {
		return nil
	}
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			return s.sendDueTrust(ctx, tx, "", s.now().Add(-trustResend))
		}); err != nil {
			return err
		}
	}
	return nil
}

// importTrustResult records the answer to trust.apply and re-evaluates the
// store's findings.
func (s *Service) importTrustResult(ctx context.Context, tx *store.Tx, id AgentIdentity, task *store.AgentTask, res agentproto.Result) error {
	var t agentproto.Task
	if err := json.Unmarshal(task.Envelope.Task, &t); err != nil {
		return nil //nolint:nilerr // our own task; nothing to record if unreadable
	}
	var p agentproto.TrustApplyPayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil //nolint:nilerr // as above
	}
	now := s.now()
	if !res.OK {
		msg := res.Error
		if msg == "" {
			msg = "trust.apply failed"
		}
		return tx.ConfirmTrust(ctx, id.AgentID, p.Store, 0, msg, now)
	}
	var out agentproto.TrustApplyOutput
	if err := json.Unmarshal(res.Output, &out); err != nil || out.Digest != p.Digest {
		return tx.ConfirmTrust(ctx, id.AgentID, p.Store, 0, "agent answered for a different bundle version", now)
	}
	if err := tx.ConfirmTrust(ctx, id.AgentID, p.Store, p.Version, "", now); err != nil {
		return err
	}
	return s.syncTrustStores(ctx, tx, id.AgentID, []agentproto.TrustStoreState{out.State}, false)
}

// importTrustStates stores the anchors reported in an inventory and syncs
// findings; stores no longer reported lose their findings.
func (s *Service) importTrustStates(ctx context.Context, tx *store.Tx, agentID string, states []agentproto.TrustStoreState) ([]agentproto.TrustStoreState, error) {
	stored := make([]agentproto.TrustStoreState, 0, len(states))
	for _, st := range states {
		for _, a := range st.Anchors {
			res, err := certparse.Parse([]byte(a.PEM), secret.Value{})
			if err != nil {
				continue
			}
			for _, c := range res.Certificates {
				if _, err := tx.UpsertCertificate(ctx, c, "trust_store"); err != nil {
					return nil, err
				}
			}
		}
		cp := st
		cp.Anchors = make([]agentproto.TrustAnchor, 0, len(st.Anchors))
		for _, a := range st.Anchors {
			a.PEM = ""
			cp.Anchors = append(cp.Anchors, a)
		}
		stored = append(stored, cp)
	}
	return stored, s.syncTrustStores(ctx, tx, agentID, states, true)
}

func (s *Service) syncTrustStores(ctx context.Context, tx *store.Tx, agentID string, states []agentproto.TrustStoreState, complete bool) error {
	now := s.now()
	inBundles, err := tx.AnchorsInBundles(ctx)
	if err != nil {
		return err
	}
	rootsInUse, err := rootsInUse(ctx, tx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, st := range states {
		id := agentID + "/" + st.Name
		seen[id] = true
		if st.Error != "" {
			continue // an unreadable store keeps its last findings
		}
		in := checks.TrustStoreInput{State: st, InBundles: inBundles, RootsInUse: rootsInUse, Now: now}
		if a, err := tx.TrustAssignmentFor(ctx, agentID, st.Name); err == nil {
			in.Assigned, in.Bundle, in.CurrentVersion, in.ConfirmedVersion, in.SentAt = true, a.BundleName, a.CurrentVersion, a.ConfirmedVersion, a.SentAt
			v, err := tx.GetTrustBundleVersion(ctx, a.BundleID, a.CurrentVersion)
			if err != nil {
				return err
			}
			in.Desired = map[string]bool{}
			for _, h := range v.Anchors {
				in.Desired[h] = true
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		res, err := tx.SyncFindings(ctx, "trust_store", id, checks.TrustStore(in), now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, id, res, now); err != nil {
			return err
		}
	}
	if !complete {
		return nil
	}
	open, err := tx.OpenFindingSubjects(ctx, "trust_store", agentID+"/")
	if err != nil {
		return err
	}
	for _, id := range open {
		if seen[id] {
			continue
		}
		res, err := tx.SyncFindings(ctx, "trust_store", id, nil, now)
		if err != nil {
			return err
		}
		if err := notifySync(ctx, tx, id, res, now); err != nil {
			return err
		}
	}
	return nil
}

// rootsInUse maps anchor hashes to true when the anchor's authority is in use.
func rootsInUse(ctx context.Context, tx *store.Tx) (map[string]bool, error) {
	g, err := tx.AuthorityGraph(ctx)
	if err != nil {
		return nil, err
	}
	used, err := inUse(ctx, tx, g)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k := range used {
		if a := g.Get(k); a != nil {
			for _, c := range a.Copies {
				out[c.SHA256] = true
			}
		}
	}
	return out, nil
}

// privateRoots returns the roots for trust checks: the configured or system
// roots plus every anchor of a trust bundle. It returns base unchanged when
// there are no bundles.
func (s *Service) privateRoots(ctx context.Context, tx *store.Tx) (*x509.CertPool, error) {
	ders, err := tx.PrivateAnchors(ctx)
	if err != nil || len(ders) == 0 {
		return s.Roots, err
	}
	var pool *x509.CertPool
	if s.Roots != nil {
		pool = s.Roots.Clone()
	} else if pool, err = x509.SystemCertPool(); err != nil {
		pool = x509.NewCertPool()
	}
	for _, der := range ders {
		if c, err := x509.ParseCertificate(der); err == nil {
			pool.AddCert(c)
		}
	}
	return pool, nil
}

// privateKeys returns the authority keys of the trust bundle anchors.
func privateKeys(ctx context.Context, tx *store.Tx) (map[string]bool, error) {
	ders, err := tx.PrivateAnchors(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, der := range ders {
		if c, err := x509.ParseCertificate(der); err == nil {
			out[cagraph.Key(c)] = true
		}
	}
	return out, nil
}

// ---------- queries ----------

// TrustBundleView is a bundle with its current anchors and stores.
type TrustBundleView struct {
	*store.TrustBundle
	Anchors     []TrustAnchorInfo        `json:"anchors"`
	Digest      string                   `json:"digest,omitempty"`
	Assignments []*store.TrustAssignment `json:"stores"`
}

// ListTrustBundles lists bundles.
func (s *Service) ListTrustBundles(ctx context.Context, p authz.Principal) (out []*store.TrustBundle, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListTrustBundles(ctx); return err })
	return out, err
}

// GetTrustBundle returns a bundle's current version and store status.
func (s *Service) GetTrustBundle(ctx context.Context, p authz.Principal, ref string) (out *TrustBundleView, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		b, err := tx.GetTrustBundle(ctx, ref, false)
		if err != nil {
			return err
		}
		out = &TrustBundleView{TrustBundle: b, Anchors: []TrustAnchorInfo{}}
		if b.CurrentVersion > 0 {
			v, err := tx.GetTrustBundleVersion(ctx, b.ID, b.CurrentVersion)
			if err != nil {
				return err
			}
			out.Digest = v.Digest
			for _, h := range v.Anchors {
				c, err := tx.GetCertificate(ctx, h)
				if err != nil {
					return err
				}
				out.Anchors = append(out.Anchors, TrustAnchorInfo{SHA256: h, Subject: c.Subject, NotAfter: c.NotAfter})
			}
		}
		out.Assignments, err = tx.TrustAssignments(ctx, b.ID)
		return err
	})
	return out, err
}

// TrustStatus lists every assigned store with its confirmed version.
func (s *Service) TrustStatus(ctx context.Context, p authz.Principal) (out []*store.TrustAssignment, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.TrustAssignments(ctx, ""); return err })
	return out, err
}

// DeleteTrustBundle removes a bundle that no store receives any more. Stores
// keep their anchors; unassign them first by applying the bundle without them.
func (s *Service) DeleteTrustBundle(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageTrust, func(tx *store.Tx) error {
		b, err := tx.GetTrustBundle(ctx, ref, true)
		if err != nil {
			return err
		}
		as, err := tx.TrustAssignments(ctx, b.ID)
		if err != nil {
			return err
		}
		if len(as) > 0 {
			return fmt.Errorf("%w: bundle %s is still assigned to %d store(s)", store.ErrConflict, b.Name, len(as))
		}
		if err := tx.DeleteTrustBundle(ctx, b.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "trust_bundles.delete", "trust_bundle", b.ID, map[string]any{"name": b.Name})
	})
}
