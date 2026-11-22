package workflow

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/cagraph"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// caWorld is a rollover in progress:
//
//	old root (20 days left) --signs--> issuing CA I (copy B) and legacy CA J
//	new root (10 years)     --signs--> issuing CA I (copy A, 5 years)
//
// Lineage "api" is under I and renews in time; lineage "www" (the env's
// deployment) is under J and outlives it.
type caWorld struct {
	oldRoot, newRoot, iA, iB, j, apiLeaf, wwwLeaf *testpki.Cert
}

func (e *env) store(certs ...*testpki.Cert) {
	e.t.Helper()
	err := e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		for _, c := range certs {
			pc, err := certparse.FromX509(c.Cert)
			if err != nil {
				return err
			}
			if _, err := tx.UpsertCertificate(ctx, pc, "import"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sweep() {
	e.t.Helper()
	_, _ = e.db.Owner.Exec(ctx, `DELETE FROM jobs WHERE kind = $1`, app.JobKindCertSweep)
	if err := e.svc.ScheduleCertSweeps(ctx); err != nil {
		e.t.Fatal(err)
	}
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	js, err := q.Claim(ctx, []string{app.JobKindCertSweep}, 1)
	if err != nil || len(js) != 1 {
		e.t.Fatalf("claim sweep: %v %d", err, len(js))
	}
	if err := e.svc.RunCertSweep(ctx, js[0]); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) finding(subjectType, subjectID, check string) string {
	e.t.Helper()
	var sev string
	err := e.db.Owner.QueryRow(ctx, `SELECT severity FROM findings WHERE subject_type = $1 AND subject_id = $2 AND check_id = $3
		AND resolved_at IS NULL`, subjectType, subjectID, check).Scan(&sev)
	if err != nil {
		return ""
	}
	return sev
}

// crossSign issues a copy of ca (same subject and key) under issuer.
func crossSign(t *testing.T, ca, issuer *testpki.Cert, notAfter time.Time) *testpki.Cert {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), RawSubject: ca.Cert.RawSubject, SubjectKeyId: ca.Cert.SubjectKeyId,
		NotBefore: ca.Cert.NotBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, ca.Key.Public(), issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testpki.Cert{Cert: c, DER: der, Key: ca.Key}
}

func newCAWorld(t *testing.T, e *env) *caWorld {
	now := time.Now()
	w := &caWorld{}
	w.oldRoot = testpki.Issue(t, nil, testpki.Options{CommonName: "Old Root", IsCA: true, NotAfter: now.AddDate(0, 0, 20)})
	w.newRoot = testpki.Issue(t, nil, testpki.Options{CommonName: "New Root", IsCA: true, NotAfter: now.AddDate(10, 0, 0)})
	w.iA = testpki.Issue(t, w.newRoot, testpki.Options{CommonName: "Issuing CA", IsCA: true, NotAfter: now.AddDate(5, 0, 0)})
	w.iB = crossSign(t, w.iA, w.oldRoot, now.AddDate(1, 0, 0))
	w.j = testpki.Issue(t, w.oldRoot, testpki.Options{CommonName: "Legacy CA", IsCA: true, NotAfter: now.AddDate(2, 0, 0)})
	w.apiLeaf = testpki.Issue(t, w.iA, testpki.Options{CommonName: "api.wf.test", DNSNames: []string{"api.wf.test"}, NotAfter: now.AddDate(0, 0, 90)})
	w.wwwLeaf = testpki.Issue(t, w.j, testpki.Options{CommonName: "www.wf.test", DNSNames: []string{"www.wf.test"}, NotAfter: now.AddDate(0, 0, 90)})

	// Leaves before their CAs: storing a CA links what waits for it.
	e.store(w.apiLeaf, w.wwwLeaf)
	e.store(w.iA, w.iB, w.j, w.oldRoot, w.newRoot)
	if _, err := e.svc.CreateLineage(ctx, e.owner, "api", "", sha(w.apiLeaf)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE lineages SET current_sha256 = $1 WHERE name = 'www'`, sha(w.wwwLeaf)); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestCAInventoryLinksAndFindings(t *testing.T) {
	e := newEnv(t)
	w := newCAWorld(t, e)
	iKey, jKey, oldKey := cagraph.Key(w.iA.Cert), cagraph.Key(w.j.Cert), cagraph.Key(w.oldRoot.Cert)

	links := func() map[string]string {
		rows, err := e.db.Owner.Query(ctx, `SELECT sha256, coalesce(issuer_ca_key, '') FROM certificates`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[string]string{}
		for rows.Next() {
			var s, k string
			if err := rows.Scan(&s, &k); err != nil {
				t.Fatal(err)
			}
			m[s] = k
		}
		return m
	}
	check := func(m map[string]string) {
		t.Helper()
		want := map[*testpki.Cert]string{w.apiLeaf: iKey, w.wwwLeaf: jKey, w.iA: cagraph.Key(w.newRoot.Cert), w.iB: oldKey, w.j: oldKey, w.oldRoot: oldKey}
		for c, k := range want {
			if m[sha(c)] != k {
				t.Errorf("%s linked to %q, want %q", c.Cert.Subject.CommonName, m[sha(c)], k)
			}
		}
	}
	check(links())

	// Rows from before the CA inventory are linked by the sweep.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE certificates SET ca_key = NULL, issuer_ca_key = NULL, issuer_link_pending = true`); err != nil {
		t.Fatal(err)
	}
	e.sweep()
	check(links())

	if got := e.finding("authority", oldKey, "ca_expiring"); got != "critical" {
		t.Errorf("old root ca_expiring = %q, want critical", got)
	}
	if got := e.finding("certificate", sha(w.wwwLeaf), "chain_outlived"); got != "critical" {
		t.Errorf("www chain_outlived = %q, want critical", got)
	}
	if got := e.finding("certificate", sha(w.apiLeaf), "chain_outlived"); got != "" {
		t.Errorf("api chain_outlived = %q: its CA has a path under the new root", got)
	}
	if got := e.finding("authority", iKey, "ca_expiring"); got != "" {
		t.Errorf("issuing CA ca_expiring = %q", got)
	}

	list, err := e.svc.ListAuthorities(ctx, e.owner, app.AuthorityFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]app.AuthoritySummary{}
	for _, a := range list {
		byKey[a.Key] = a
	}
	i := byKey[iKey]
	if i.Authority == nil || len(i.Copies) != 2 || len(i.Parents) != 2 || !i.InUse || i.Leaves != 1 {
		t.Fatalf("issuing CA summary: %+v", i)
	}
	if d := time.Until(i.Expiry); d < 4*365*24*time.Hour {
		t.Errorf("issuing CA expiry %v: the new-root path should count", i.Expiry)
	}
	if j := byKey[jKey]; time.Until(j.Expiry) > 21*24*time.Hour {
		t.Errorf("legacy CA expiry %v should be cut to the old root", j.Expiry)
	}
	roots, _ := e.svc.ListAuthorities(ctx, e.owner, app.AuthorityFilter{Roots: true, InUse: true})
	if len(roots) != 2 {
		t.Errorf("in-use roots = %d, want old and new", len(roots))
	}

	// Once nothing depends on the old hierarchy, its finding resolves.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE lineages SET current_sha256 = NULL WHERE name IN ('www', 'api')`); err != nil {
		t.Fatal(err)
	}
	e.sweep()
	if got := e.finding("authority", oldKey, "ca_expiring"); got != "" {
		t.Errorf("old root still has ca_expiring %q after nothing uses it", got)
	}
}

func TestCAImpactPlanAndRenewAffected(t *testing.T) {
	e := newEnv(t)
	w := newCAWorld(t, e)
	oldKey, jKey := cagraph.Key(w.oldRoot.Cert), cagraph.Key(w.j.Cert)

	im, err := e.svc.GetAuthorityImpact(ctx, e.owner, oldKey[:12])
	if err != nil {
		t.Fatal(err)
	}
	if len(im.Below) != 2 || len(im.Lineages) != 2 {
		t.Fatalf("old root impact: below %v lineages %+v", im.Below, im.Lineages)
	}
	for _, l := range im.Lineages {
		switch l.LineageName {
		case "www":
			if !l.Outlives || len(l.Deployments) != 1 || l.Deployments[0].ID != e.dep.ID {
				t.Errorf("www: %+v", l)
			}
		case "api":
			if l.Outlives {
				t.Errorf("api should renew in time: %+v", l)
			}
		}
	}
	if len(im.Issuers) != 1 {
		t.Errorf("issuers = %v", im.Issuers)
	}
	if _, err := e.svc.GetAuthorityImpact(ctx, e.owner, "abc"); err == nil {
		t.Error("a short prefix must not resolve")
	}

	plan, err := e.svc.AuthorityPlan(ctx, e.owner, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, p := range plan {
		keys = append(keys, p.Key)
		if p.Key == oldKey && (p.Lineages != 2 || p.Outliving != 1 || p.RenewBy == nil) {
			t.Errorf("old root plan item: %+v", p)
		}
	}
	if strings.Join(keys, ",") != oldKey+","+jKey && strings.Join(keys, ",") != jKey+","+oldKey {
		t.Errorf("plan keys = %v, want old root and legacy CA", keys)
	}

	dry, err := e.svc.RenewAffectedDeployments(ctx, e.owner, jKey, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Items) != 1 || dry.Items[0].RunID != "" || dry.Items[0].DeploymentID != e.dep.ID {
		t.Fatalf("dry run: %+v", dry.Items)
	}
	res, err := e.svc.RenewAffectedDeployments(ctx, e.owner, jKey, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].RunID == "" {
		t.Fatalf("renew: %+v", res.Items)
	}
	again, err := e.svc.RenewAffectedDeployments(ctx, e.owner, jKey, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Items) != 1 || again.Items[0].Skipped == "" {
		t.Fatalf("second renew should skip the active run: %+v", again.Items)
	}
	var n int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'authorities.renew_affected'`).Scan(&n)
	if n != 2 {
		t.Errorf("audit events = %d", n)
	}
	if r := e.pump(res.Items[0].RunID); r.State != store.RunVerified {
		t.Fatalf("run %s: %s", r.State, r.Error)
	}

	viewer := e.principal("user:viewer", store.RoleViewer)
	if _, err := e.svc.RenewAffectedDeployments(ctx, viewer, jKey, false, true); err == nil {
		t.Error("viewer must not renew")
	}
}

func TestCAPages(t *testing.T) {
	e := newEnv(t)
	w := newCAWorld(t, e)
	jKey := cagraph.Key(w.j.Cert)
	base := e.uiServer()

	viewer := e.uiLogin(base, store.RoleViewer)
	_, body := viewer.get("/authorities")
	if !strings.Contains(body, "Legacy CA") || !strings.Contains(body, "Old Root") {
		t.Fatalf("authorities page:\n%s", body)
	}
	_, body = viewer.get("/authorities/" + jKey)
	if !strings.Contains(body, "renew before") || strings.Contains(body, "renew-affected") {
		t.Fatalf("viewer authority page must list www to renew and offer no renew form:\n%s", body)
	}

	op := e.uiLogin(base, store.RoleOperator)
	resp, body := op.post("/authorities/"+jKey+"/renew-affected", url.Values{"csrf": {op.csrf()}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Started 1 renewal runs") {
		t.Fatalf("renew-affected: %d\n%s", resp.StatusCode, body)
	}
}
