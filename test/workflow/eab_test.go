package workflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// eabHMAC derives a test HMAC key from plain text, so the secret scanner does
// not flag it and the test can search for it where it must not appear.
func eabHMAC(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// issueRecorder records issue payloads and answers like an agent that
// registered the requested account slot.
type issueRecorder struct {
	e        *env
	payloads []agentproto.IssuePayload
	reject   bool
}

func (r *issueRecorder) handle(c context.Context, task *agentproto.Task) (any, error) {
	var p agentproto.IssuePayload
	_ = json.Unmarshal(task.Payload, &p)
	r.payloads = append(r.payloads, p)
	if r.reject {
		return agentproto.IssueOutput{ProblemType: "urn:ietf:params:acme:error:unauthorized", EABRejected: true},
			errors.New("acme account registration: unauthorized (simulated)")
	}
	out, err := r.e.fakeIssue(c, task)
	if o, ok := out.(agentproto.IssueOutput); ok {
		o.AccountSlot = p.AccountSlot
		out = o
	}
	return out, err
}

func (r *issueRecorder) last() agentproto.IssuePayload { return r.payloads[len(r.payloads)-1] }

func (e *env) renewOnce(depID string) *store.Run {
	e.t.Helper()
	run, err := e.svc.RequestRenewal(ctx, e.owner, depID)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.pump(run.ID)
}

// heartbeatAs sends the agent's last heartbeat again with changes.
func (e *env) heartbeatAs(agentID string, mod func(*agentproto.Heartbeat)) {
	e.t.Helper()
	var hb agentproto.Heartbeat
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, agentID)
		hb = a.Capabilities
		return err
	})
	mod(&hb)
	if err := e.svc.AgentHeartbeat(ctx, app.AgentIdentity{OrgID: e.owner.OrgID, AgentID: agentID}, hb); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) keyStates(issuer string) map[string]string {
	e.t.Helper()
	ks, err := e.svc.ListEABKeys(ctx, e.owner, issuer)
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[string]string{}
	for _, k := range ks {
		m[k.KID] = k.State
	}
	return m
}

func (e *env) openFinding(check string) bool {
	var n int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE subject_type = 'issuer' AND check_id = $1 AND resolved_at IS NULL`,
		check).Scan(&n)
	return n > 0
}

// enrollSecond enrolls another agent with a www target and gives it a
// deployment on the fake issuer.
func (e *env) enrollSecond(name string) (*agent.Agent, *store.Deployment) {
	e.t.Helper()
	tok, err := e.svc.CreateEnrollmentToken(ctx, e.owner, "", time.Hour, e.srv.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	dir := e.t.TempDir()
	cfg := &agent.Config{Server: e.srv.URL, StateDir: dir, Name: name, Targets: []agent.TargetConfig{{
		Name: "www", Type: "nginx", LiveLink: filepath.Join(dir, "live", "www"), Webroot: filepath.Join(dir, "webroot"),
		TestCommand: []string{"true"}, ReloadCommand: []string{"true"}, VerifyAddress: "127.0.0.1:1",
		AllowedSANs: []string{"www2.wf.test"}}}}
	if _, err := agent.Enroll(ctx, cfg, tok.Token, tok.CAHash, "host-"+name); err != nil {
		e.t.Fatal(err)
	}
	a, err := agent.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = a.Close() })
	if err := a.Heartbeat(ctx); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.CreateLineage(ctx, e.owner, "www2", "", ""); err != nil {
		e.t.Fatal(err)
	}
	d, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www2", Agent: name, Target: "www",
		Issuer: "fake", SANs: []string{"www2.wf.test"}})
	if err != nil {
		e.t.Fatal(err)
	}
	return a, d
}

func TestReusableEABIsSealedUntilRegistered(t *testing.T) {
	e := newEnv(t)
	rec := &issueRecorder{e: e}
	e.agent.SetHandler(agentproto.TaskIssue, rec.handle)
	hmac := eabHMAC("reusable eab hmac for the workflow test")

	operator := authz.Principal{OrgID: e.owner.OrgID, Actor: "user:op", Role: store.RoleOperator}
	if _, err := e.svc.SetIssuerEAB(ctx, operator, "fake", app.EABInput{Mode: store.EABReusable, KID: "kid-1",
		HMAC: secret.FromString(hmac)}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator set EAB: %v", err)
	}
	for _, bad := range []app.EABInput{
		{Mode: store.EABReusable, KID: "kid-1"},                                      // no HMAC stored yet
		{Mode: store.EABReusable, KID: "kid-1", HMAC: secret.FromString("not b64!")}, // not base64url
		{Mode: store.EABSingleUse, KID: "kid-1"},                                     // kid belongs to reusable
		{Mode: "sometimes"},
	} {
		if _, err := e.svc.SetIssuerEAB(ctx, e.owner, "fake", bad); !errors.Is(err, app.ErrInvalid) {
			t.Fatalf("%+v accepted: %v", bad, err)
		}
	}
	iss, err := e.svc.SetIssuerEAB(ctx, e.owner, "fake", app.EABInput{Mode: store.EABReusable, KID: "kid-1", HMAC: secret.FromString(hmac)})
	if err != nil || !iss.HasEABHMAC || iss.EABMode != store.EABReusable {
		t.Fatalf("%+v %v", iss, err)
	}
	list, _ := e.svc.ListIssuers(ctx, e.owner)
	if b, _ := json.Marshal(list); strings.Contains(string(b), hmac) || strings.Contains(string(b), "ciphertext") {
		t.Fatalf("issuer list exposes the key: %s", b)
	}

	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified {
		t.Fatalf("state %s err %q", r.State, r.Error)
	}
	p := rec.last()
	slot := agentproto.AccountSlot(iss.ID)
	if p.AccountSlot != slot || p.EAB == nil || p.EAB.KID != "kid-1" || len(p.EAB.Sealed) == 0 {
		t.Fatalf("payload: slot %q eab %+v", p.AccountSlot, p.EAB)
	}
	for _, q := range []string{`SELECT count(*) FROM agent_tasks WHERE envelope::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM issuers WHERE position(convert_to($1, 'UTF8') in eab_hmac_ciphertext) > 0`} {
		var n int
		if err := e.db.Owner.QueryRow(ctx, q, hmac).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d %v", q, n, err)
		}
	}
	var delivered int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'issuers.eab_delivered'`).Scan(&delivered)
	if delivered != 1 {
		t.Fatalf("delivery audited %d times", delivered)
	}

	// Once the agent reports the account, the key is no longer sent.
	e.heartbeatAs(e.dep.AgentID, func(hb *agentproto.Heartbeat) { hb.ACMEAccounts = []string{slot} })
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || rec.last().EAB != nil || rec.last().AccountSlot != slot {
		t.Fatalf("state %s, eab %+v", r.State, rec.last().EAB)
	}

	// Mode change to none: back to the account for the directory.
	if _, err := e.svc.SetIssuerEAB(ctx, e.owner, "fake", app.EABInput{Mode: store.EABNone}); err != nil {
		t.Fatal(err)
	}
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || rec.last().AccountSlot != "" || rec.last().EAB != nil {
		t.Fatalf("mode none: %+v", rec.last())
	}
}

func TestSingleUseEABPool(t *testing.T) {
	e := newEnv(t)
	rec := &issueRecorder{e: e}
	e.agent.SetHandler(agentproto.TaskIssue, rec.handle)
	if _, err := e.svc.AddEABKey(ctx, e.owner, "fake", "k0", secret.FromString(eabHMAC("pool key zero for the test")), nil); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("key added to a reusable/none issuer: %v", err)
	}
	if _, err := e.svc.SetIssuerEAB(ctx, e.owner, "fake", app.EABInput{Mode: store.EABSingleUse}); err != nil {
		t.Fatal(err)
	}

	// Empty pool: the run fails at once with a clear reason and a finding opens.
	if r := e.renewOnce(e.dep.ID); r.State != store.RunFailed || !strings.Contains(r.Error, "no unused single-use EAB key") {
		t.Fatalf("empty pool: %s %q", r.State, r.Error)
	}
	if err := e.svc.SweepEABPools(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.openFinding("eab_pool") {
		t.Fatal("no eab_pool finding for an empty pool")
	}

	soon := time.Now().Add(time.Hour) // inside the minimum validity: never handed out
	add := func(kid string, exp *time.Time) {
		t.Helper()
		if _, err := e.svc.AddEABKey(ctx, e.owner, "fake", kid, secret.FromString(eabHMAC("pool key "+kid+" for the test")), exp); err != nil {
			t.Fatal(err)
		}
	}
	add("k-short", &soon)
	later := time.Now().Add(7 * 24 * time.Hour)
	add("k1", &later)
	add("k2", nil)
	add("k3", nil)
	if _, err := e.svc.AddEABKey(ctx, e.owner, "fake", "k1", secret.FromString(eabHMAC("duplicate kid")), nil); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if err := e.svc.SweepEABPools(ctx); err != nil {
		t.Fatal(err)
	}
	if e.openFinding("eab_pool") {
		t.Fatal("eab_pool finding stays open with keys available")
	}

	// A refused key fails the run without retry and is marked failed.
	rec.reject = true
	if r := e.renewOnce(e.dep.ID); r.State != store.RunFailed || !strings.Contains(r.Error, "External Account Binding") {
		t.Fatalf("rejected: %s %q", r.State, r.Error)
	}
	if n := len(rec.payloads); n != 1 || rec.last().EAB.KID != "k1" {
		t.Fatalf("issue calls %d, kid %+v", n, rec.last().EAB)
	}
	if s := e.keyStates("fake"); s["k1"] != "failed" || s["k-short"] != "available" {
		t.Fatalf("states %v", s)
	}

	// Next run claims the next key; success consumes it.
	rec.reject = false
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || rec.last().EAB.KID != "k2" {
		t.Fatalf("state %s kid %+v", r.State, rec.last().EAB)
	}
	if s := e.keyStates("fake"); s["k2"] != "consumed" {
		t.Fatalf("states %v", s)
	}
	// Before the heartbeat reports the account, the consumed key still counts.
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || rec.last().EAB != nil {
		t.Fatalf("second renewal: %s %+v", r.State, rec.last().EAB)
	}

	// A second agent gets a different key; a consumed key cannot be deleted.
	_, d2 := e.enrollSecond("web-02")
	var p2 agentproto.IssuePayload
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		iss, _ := tx.GetIssuer(ctx, "fake")
		k, err := tx.ClaimEABKey(ctx, iss.ID, d2.AgentID, time.Now().Add(2*time.Hour))
		if k != nil {
			p2.EAB = &agentproto.SealedEAB{KID: k.KID}
		}
		return err
	})
	if p2.EAB == nil || p2.EAB.KID != "k3" {
		t.Fatalf("second agent claimed %+v", p2.EAB)
	}
	if err := e.svc.DeleteEABKey(ctx, e.owner, "fake", "k2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("consumed key deleted: %v", err)
	}
	if err := e.svc.DeleteEABKey(ctx, e.owner, "fake", "k1"); err != nil {
		t.Fatalf("failed key not deletable: %v", err)
	}
	// The heartbeat path also consumes a claim.
	e.heartbeatAs(d2.AgentID, func(hb *agentproto.Heartbeat) { hb.ACMEAccounts = []string{rec.last().AccountSlot} })
	if s := e.keyStates("fake"); s["k3"] != "consumed" {
		t.Fatalf("states after heartbeat %v", s)
	}
}

func TestEABHostControl(t *testing.T) {
	e := newEnv(t)
	rec := &issueRecorder{e: e}
	e.agent.SetHandler(agentproto.TaskIssue, rec.handle)
	if _, err := e.svc.SetIssuerEAB(ctx, e.owner, "fake", app.EABInput{Mode: store.EABSingleUse}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddEABKey(ctx, e.owner, "fake", "k1", secret.FromString(eabHMAC("host control key for the test")), nil); err != nil {
		t.Fatal(err)
	}

	// The host refuses central EAB and has no key of its own: fail early.
	e.heartbeatAs(e.dep.AgentID, func(hb *agentproto.Heartbeat) { hb.NoCentralEAB = true })
	if r := e.renewOnce(e.dep.ID); r.State != store.RunFailed || !strings.Contains(r.Error, "refuses central EAB") || len(rec.payloads) != 0 {
		t.Fatalf("opt-out: %s %q", r.State, r.Error)
	}
	// With a host-local key for the directory, nothing is sent or claimed.
	e.heartbeatAs(e.dep.AgentID, func(hb *agentproto.Heartbeat) { hb.LocalEAB = []string{"https://acme.invalid/dir"} })
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || rec.last().EAB != nil || rec.last().AccountSlot == "" {
		t.Fatalf("local eab: %s %+v", r.State, rec.last())
	}
	if s := e.keyStates("fake"); s["k1"] != "available" {
		t.Fatalf("key claimed for a host with its own key: %v", s)
	}
}
