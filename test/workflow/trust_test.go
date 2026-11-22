package workflow

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

type trustEnv struct {
	*env
	bundlePath, watchPath string
	w                     *caWorld
	rogue                 *testpki.Cert
}

func newTrustEnv(t *testing.T) *trustEnv {
	te := &trustEnv{}
	te.env = newEnvWith(t, testpki.Options{}, func(c *agent.Config) {
		te.bundlePath = filepath.Join(c.StateDir, "ca-bundle.pem")
		te.watchPath = filepath.Join(c.StateDir, "watched.pem")
		c.TrustStores = []agent.TrustStoreConfig{
			{Name: "bundle", Type: agentproto.TrustPEM, Path: te.bundlePath},
			{Name: "watch", Type: agentproto.TrustPEM, Path: te.watchPath, Mode: agentproto.TrustObserve},
		}
	})
	te.w = newCAWorld(t, te.env)
	te.rogue = testpki.Issue(t, nil, testpki.Options{CommonName: "Unknown Root", IsCA: true})
	if err := os.WriteFile(te.watchPath, te.rogue.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return te
}

func (te *trustEnv) apply(in app.TrustBundleInput) (*app.TrustPlan, error) {
	if in.Name == "" {
		in.Name = "corp"
	}
	if in.Stores == nil {
		in.Stores = []app.TrustStoreRef{{Agent: "web-01", Store: "bundle"}}
	}
	return te.svc.ApplyTrustBundle(ctx, te.owner, in)
}

func (te *trustEnv) poll() {
	te.t.Helper()
	if _, err := te.agent.PollOnce(ctx, 0); err != nil {
		te.t.Fatal(err)
	}
}

func (te *trustEnv) inventory() {
	te.t.Helper()
	if _, err := te.svc.RequestInventoryScan(ctx, te.owner, "web-01"); err != nil {
		te.t.Fatal(err)
	}
	te.poll()
}

func (te *trustEnv) status() *store.TrustAssignment {
	te.t.Helper()
	st, err := te.svc.TrustStatus(ctx, te.owner)
	if err != nil || len(st) != 1 {
		te.t.Fatalf("status: %v %+v", err, st)
	}
	return st[0]
}

func pems(cs ...*testpki.Cert) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c.PEM()))
	}
	return out
}

func TestTrustBundleDeliveryAndDrift(t *testing.T) {
	te := newTrustEnv(t)
	w := te.w

	// An observe-only store cannot be assigned.
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.oldRoot), Stores: []app.TrustStoreRef{{Agent: "web-01", Store: "watch"}}}); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("observe store assigned: %v", err)
	}
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.apiLeaf)}); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("leaf accepted as anchor: %v", err)
	}

	plan, err := te.apply(app.TrustBundleInput{Anchors: pems(w.oldRoot, w.newRoot)})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Applied || plan.ToVersion != 1 || len(plan.Added) != 2 || len(plan.StoresAdded) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	if st := te.status(); st.SentVersion != 1 || st.ConfirmedVersion != 0 {
		t.Fatalf("before delivery: %+v", st)
	}
	te.poll()
	if st := te.status(); st.ConfirmedVersion != 1 || st.LastError != "" {
		t.Fatalf("after delivery: %+v", st)
	}
	b, _ := os.ReadFile(te.bundlePath)
	if !strings.Contains(string(b), "Old Root") || !strings.Contains(string(b), "New Root") {
		t.Fatalf("bundle file:\n%s", b)
	}

	// Same anchors again: no new version.
	if plan, err = te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot, w.oldRoot)}); err != nil || plan.ToVersion != 1 {
		t.Fatalf("no-op apply: %+v %v", plan, err)
	}

	te.inventory()
	bundleID, watchID := te.agentID()+"/bundle", te.agentID()+"/watch"
	if got := te.finding("trust_store", watchID, "trust_store_unknown_anchor"); got != "warning" {
		t.Errorf("unknown anchor in watched store: %q", got)
	}
	if got := te.finding("trust_store", bundleID, "trust_store_drift"); got != "" {
		t.Errorf("in-sync store has drift %q", got)
	}

	// Someone drops the old root from the file: the old root still signs
	// certificates in use, so the drift is critical.
	if err := os.WriteFile(te.bundlePath, w.newRoot.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	te.inventory()
	if got := te.finding("trust_store", bundleID, "trust_store_drift"); got != "critical" {
		t.Errorf("missing in-use root: drift %q, want critical", got)
	}
	// The next delivery repairs the store and resolves the finding.
	if _, err := te.db.Owner.Exec(ctx, `UPDATE trust_assignments SET confirmed_version = 0, sent_at = now() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.SendDueTrustBundles(ctx); err != nil {
		t.Fatal(err)
	}
	te.poll()
	if got := te.finding("trust_store", bundleID, "trust_store_drift"); got != "" {
		t.Errorf("drift after repair: %q", got)
	}

	// Approving the rogue root by putting it in a bundle clears the finding.
	if _, err := te.apply(app.TrustBundleInput{Name: "extra", Anchors: pems(te.rogue), Stores: []app.TrustStoreRef{}}); err != nil {
		t.Fatal(err)
	}
	te.inventory()
	if got := te.finding("trust_store", watchID, "trust_store_unknown_anchor"); got != "" {
		t.Errorf("approved anchor still unknown: %q", got)
	}
}

func TestTrustBundleRemovalSafety(t *testing.T) {
	te := newTrustEnv(t)
	w := te.w
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.oldRoot, w.newRoot)}); err != nil {
		t.Fatal(err)
	}

	// Not yet confirmed and the old root still in use: both block.
	dry, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Blockers) != 2 || len(dry.Removed) != 1 || dry.Applied {
		t.Fatalf("dry run: %+v", dry)
	}
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot)}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("unsafe removal: %v", err)
	}
	te.poll()
	if dry, _ = te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), DryRun: true}); len(dry.Blockers) != 1 {
		t.Fatalf("after confirmation only the in-use CA should block: %v", dry.Blockers)
	}

	base := 0
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), BaseVersion: &base, Force: true, Reason: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale base version: %v", err)
	}
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), Force: true}); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("force without reason: %v", err)
	}
	op := te.principal("user:op", store.RoleOperator)
	if _, err := te.svc.ApplyTrustBundle(ctx, op, app.TrustBundleInput{Name: "corp", Anchors: pems(w.newRoot)}); err == nil {
		t.Fatal("operator applied a bundle")
	}

	plan, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), Force: true, Reason: "old root compromised"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Forced || plan.ToVersion != 2 {
		t.Fatalf("forced plan: %+v", plan)
	}
	var reason string
	_ = te.db.Owner.QueryRow(ctx, `SELECT detail->>'reason' FROM audit_events WHERE action = 'trust_bundles.apply' ORDER BY seq DESC LIMIT 1`).Scan(&reason)
	if reason != "old root compromised" {
		t.Errorf("audit reason %q", reason)
	}
	te.poll()
	if b, _ := os.ReadFile(te.bundlePath); strings.Contains(string(b), "Old Root") {
		t.Error("old root still in the bundle file")
	}

	// Once nothing chains to it and every store confirmed, removal is free.
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.oldRoot, w.newRoot)}); err != nil {
		t.Fatal(err)
	}
	te.poll()
	if _, err := te.db.Owner.Exec(ctx, `UPDATE lineages SET current_sha256 = NULL`); err != nil {
		t.Fatal(err)
	}
	if plan, err = te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot)}); err != nil || plan.Forced || len(plan.Blockers) != 0 {
		t.Fatalf("free removal: %+v %v", plan, err)
	}

	if err := te.svc.DeleteTrustBundle(ctx, te.owner, "corp"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete of an assigned bundle: %v", err)
	}
	if _, err := te.apply(app.TrustBundleInput{Anchors: pems(w.newRoot), Stores: []app.TrustStoreRef{}}); err != nil {
		t.Fatal(err)
	}
	if err := te.svc.DeleteTrustBundle(ctx, te.owner, "corp"); err != nil {
		t.Fatal(err)
	}
}

func (e *env) agentID() string {
	e.t.Helper()
	var id string
	if err := e.db.Owner.QueryRow(ctx, `SELECT id FROM agents WHERE name = 'web-01'`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}
