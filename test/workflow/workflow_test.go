// Package workflow tests the renewal workflow end to end without Docker:
// real control plane, real mTLS agent listener, real enrolled agent with its
// task verification and local state, only the issue/deploy/verify handlers
// are replaced with fakes so every failure branch can be forced.
package workflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentapi"
	"github.com/alexandrosnt/certloom/internal/agentpki"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/ari"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/kek"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

var ctx = context.Background()

type env struct {
	t     *testing.T
	db    *storetest.DB
	svc   *app.Service
	srv   *httptest.Server
	agent *agent.Agent
	owner authz.Principal
	ca    *testpki.Cert
	dep   *store.Deployment

	issueCalls atomic.Int32
	issueFail  atomic.Int32 // fail this many issue calls first
	issueRL    atomic.Int64 // next issue call is rate limited with this Retry-After (seconds)
	deployMode atomic.Value // "ok", "rolledback", "fail"
	verifyMode atomic.Value // "match", "mismatch"
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvOld(t, testpki.Options{})
}

// newEnvOld is newEnv with control over the validity of the certificate the
// renewal replaces.
func newEnvOld(t *testing.T, oldOpts testpki.Options) *env {
	t.Helper()
	return newEnvWith(t, oldOpts, nil)
}

// newEnvWith lets a test adjust the agent config before enrollment.
func newEnvWith(t *testing.T, oldOpts testpki.Options, mod func(*agent.Config)) *env {
	t.Helper()
	db := storetest.New(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	k, _ := kek.New(key)
	pki, err := agentpki.LoadOrCreate(ctx, db.Pool, k)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &app.Service{DB: db.DB, Prober: probe.New(), Log: log, PKI: pki}
	e := &env{t: t, db: db, svc: svc, ca: testpki.Issue(t, nil, testpki.Options{CommonName: "fake acme ca", IsCA: true})}
	e.deployMode.Store("ok")
	e.verifyMode.Store("match")

	as := &agentapi.Server{Svc: svc, Log: log}
	tcfg, err := as.TLSConfig([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewUnstartedServer(as.Handler())
	e.srv.TLS = tcfg
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)

	org, _ := db.CreateOrg(ctx, "wf")
	e.owner = authz.Principal{OrgID: org.ID, Actor: "user:owner", Role: store.RoleOwner}
	tok, err := svc.CreateEnrollmentToken(ctx, e.owner, "", time.Hour, e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &agent.Config{Server: e.srv.URL, StateDir: dir, Name: "web-01", Targets: []agent.TargetConfig{{
		Name: "www", Type: "nginx", LiveLink: filepath.Join(dir, "live", "www"), Webroot: filepath.Join(dir, "webroot"),
		TestCommand: []string{"true"}, ReloadCommand: []string{"true"}, VerifyAddress: "127.0.0.1:1",
		AllowedSANs: []string{"www.wf.test", "*.wf.test"}}}}
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Enroll(ctx, cfg, tok.Token, tok.CAHash, "host-1"); err != nil {
		t.Fatal(err)
	}
	if e.agent, err = agent.New(cfg, log); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.agent.Close() })
	e.agent.SetHandler(agentproto.TaskIssue, e.fakeIssue)
	e.agent.SetHandler(agentproto.TaskDeploy, e.fakeDeploy)
	e.agent.SetHandler(agentproto.TaskVerify, e.fakeVerify)
	e.agent.SetHandler(agentproto.TaskRollback, func(context.Context, *agentproto.Task) (any, error) { return map[string]string{}, nil })
	if err := e.agent.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}

	// Lineage with a current (expiring) certificate, issuer, deployment.
	oldOpts.CommonName, oldOpts.DNSNames = "www.wf.test", []string{"www.wf.test"}
	old := testpki.Issue(t, e.ca, oldOpts)
	pc, _ := certparse.FromX509(old.Cert)
	_ = db.WithOrg(ctx, org.ID, func(tx *store.Tx) error { _, err := tx.UpsertCertificate(ctx, pc, "import"); return err })
	if _, err := svc.CreateLineage(ctx, e.owner, "www", "", pc.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateIssuer(ctx, e.owner, &store.Issuer{Name: "fake", DirectoryURL: "https://acme.invalid/dir", AgreeTOS: true}, secret.Value{}); err != nil {
		t.Fatal(err)
	}
	if e.dep, err = svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www",
		Issuer: "fake", SANs: []string{"www.wf.test"}}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) fakeIssue(_ context.Context, t *agentproto.Task) (any, error) {
	e.issueCalls.Add(1)
	if ra := e.issueRL.Swap(0); ra > 0 {
		return agentproto.IssueOutput{ProblemType: "urn:ietf:params:acme:error:rateLimited", RetryAfterSeconds: ra},
			errors.New("acme: 429 urn:ietf:params:acme:error:rateLimited (simulated)")
	}
	if e.issueFail.Load() > 0 {
		e.issueFail.Add(-1)
		return nil, errors.New("acme: urn:ietf:params:acme:error:rateLimited (simulated)")
	}
	var p agentproto.IssuePayload
	_ = json.Unmarshal(t.Payload, &p)
	c := testpki.Issue(e.t, e.ca, testpki.Options{CommonName: p.SANs[0], DNSNames: p.SANs})
	return agentproto.IssueOutput{ChainPEM: string(c.PEM())}, nil
}

func (e *env) fakeDeploy(context.Context, *agentproto.Task) (any, error) {
	switch e.deployMode.Load() {
	case "rolledback":
		return agentproto.DeployOutput{RolledBack: true}, errors.New("nginx -t failed (simulated)")
	case "fail":
		return nil, errors.New("disk full (simulated)")
	}
	return agentproto.DeployOutput{}, nil
}

func (e *env) fakeVerify(_ context.Context, t *agentproto.Task) (any, error) {
	var p agentproto.VerifyPayload
	_ = json.Unmarshal(t.Payload, &p)
	if e.verifyMode.Load() == "mismatch" {
		return agentproto.VerifyOutput{ServedSHA256: strings.Repeat("0", 64), Match: false}, nil
	}
	return agentproto.VerifyOutput{ServedSHA256: p.ExpectedSHA256, Match: true}, nil
}

// pump runs control-plane jobs and agent polls until the run is terminal.
func (e *env) pump(runID string) *store.Run {
	e.t.Helper()
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	for range 60 {
		// Retries are scheduled minutes ahead; pull them in for the test.
		// (Owner connection: workflow_runs is under row-level security.)
		_, _ = e.db.Owner.Exec(ctx, `UPDATE workflow_runs SET next_attempt_at = now() WHERE state = 'retry_scheduled'`)
		_, _ = e.db.Owner.Exec(ctx, `UPDATE jobs SET run_at = now() WHERE state = 'pending'`)
		js, err := q.Claim(ctx, []string{app.JobKindAdvance}, 10)
		if err != nil {
			e.t.Fatal(err)
		}
		for _, j := range js {
			if err := e.svc.RunAdvance(ctx, j); err != nil {
				e.t.Fatalf("advance: %v", err)
			}
		}
		if _, err := e.agent.PollOnce(ctx, 0); err != nil {
			e.t.Fatalf("agent poll: %v", err)
		}
		r, err := e.svc.GetRun(ctx, e.owner, runID)
		if err != nil {
			e.t.Fatal(err)
		}
		if store.Terminal(r.State) {
			return r
		}
	}
	r, _ := e.svc.GetRun(ctx, e.owner, runID)
	e.t.Fatalf("run did not finish: %+v", r)
	return nil
}

func steps(r *store.Run) string {
	var s []string
	for _, st := range r.Steps {
		s = append(s, st.State)
	}
	return strings.Join(s, ">")
}

func TestHappyPathVerifiedAndLineageUpdated(t *testing.T) {
	e := newEnv(t)
	run, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	if err != nil {
		t.Fatal(err)
	}
	r := e.pump(run.ID)
	if r.State != store.RunVerified || r.IssuedSHA256 == nil {
		t.Fatalf("state %s err %q steps %s", r.State, r.Error, steps(r))
	}
	if got := steps(r); got != "planned>issuing>issued>deploying>verifying>verified" {
		t.Fatalf("timeline: %s", got)
	}
	l, _ := e.svc.GetLineage(ctx, e.owner, "www")
	if *l.CurrentSHA256 != *r.IssuedSHA256 || l.ManagementLevel != "verified" {
		t.Fatalf("lineage not updated: %+v", l)
	}
	ds, _ := e.svc.ListDeployments(ctx, e.owner)
	if ds[0].RenewAt == nil || !ds[0].RenewAt.After(time.Now()) {
		t.Fatalf("next renewal not scheduled: %+v", ds[0])
	}
	// The issue task carried the RFC 9773 "replaces" id of the previous certificate.
	var payload []byte
	_ = e.db.Owner.QueryRow(ctx, `SELECT envelope->>'task' FROM agent_tasks WHERE type = 'acme.issue'`).Scan(&payload)
	var env struct{}
	_ = env
	var tsk agentproto.Task
	raw, _ := decodeB64(string(payload))
	_ = json.Unmarshal(raw, &tsk)
	var ip agentproto.IssuePayload
	_ = json.Unmarshal(tsk.Payload, &ip)
	if ip.ReplacesCertID == "" {
		t.Fatal("issue task lacks replaces cert id")
	}
	// A second renewal cannot start while... (it is terminal now), but two at once are refused.
	if _, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID); err != nil {
		t.Fatalf("new run after completion: %v", err)
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("concurrent run: want conflict, got %v", err)
	}
}

func TestIssueRetriesThenSucceeds(t *testing.T) {
	e := newEnv(t)
	e.issueFail.Store(2)
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	r := e.pump(run.ID)
	if r.State != store.RunVerified || r.Attempt != 3 || e.issueCalls.Load() != 3 {
		t.Fatalf("state %s attempt %d calls %d steps %s", r.State, r.Attempt, e.issueCalls.Load(), steps(r))
	}
	if !strings.Contains(steps(r), "retry_scheduled") {
		t.Fatalf("no retry recorded: %s", steps(r))
	}
}

func TestIssueGivesUpAfterMaxAttempts(t *testing.T) {
	e := newEnv(t)
	e.issueFail.Store(10)
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	r := e.pump(run.ID)
	if r.State != store.RunFailed || e.issueCalls.Load() != 3 || !strings.Contains(r.Error, "rateLimited") {
		t.Fatalf("state %s calls %d err %q", r.State, e.issueCalls.Load(), r.Error)
	}
	// Nothing was deployed.
	if strings.Contains(steps(r), "deploying") {
		t.Fatalf("deployed after failed issuance: %s", steps(r))
	}
}

func TestActivationFailureAgentRolledBack(t *testing.T) {
	e := newEnv(t)
	e.deployMode.Store("rolledback")
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	r := e.pump(run.ID)
	if r.State != store.RunRolledBack || !strings.Contains(r.Error, "nginx -t") {
		t.Fatalf("state %s err %q", r.State, r.Error)
	}
	l, _ := e.svc.GetLineage(ctx, e.owner, "www")
	if l.CurrentSHA256 == nil || *l.CurrentSHA256 == *r.IssuedSHA256 {
		t.Fatal("lineage must keep the previous certificate after rollback")
	}
}

func TestVerificationMismatchTriggersRollback(t *testing.T) {
	e := newEnv(t)
	e.verifyMode.Store("mismatch")
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	r := e.pump(run.ID)
	if r.State != store.RunRolledBack || !strings.Contains(steps(r), "rolling_back") || !strings.Contains(r.Error, "local verification") {
		t.Fatalf("state %s err %q steps %s", r.State, r.Error, steps(r))
	}
}

func TestUnknownDeployOutcomeRollsBack(t *testing.T) {
	e := newEnv(t)
	e.deployMode.Store("fail")
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	r := e.pump(run.ID)
	if r.State != store.RunRolledBack || !strings.Contains(steps(r), "rolling_back") {
		t.Fatalf("state %s steps %s", r.State, steps(r))
	}
}

// The control plane is unreachable when the agent finishes issuance; the
// agent keeps the result and delivers it later. Exactly one ACME order.
func TestResultSurvivesControlPlaneOutage(t *testing.T) {
	e := newEnv(t)
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	js, _ := q.Claim(ctx, []string{app.JobKindAdvance}, 10)
	for _, j := range js {
		_ = e.svc.RunAdvance(ctx, j)
	}
	// Agent fetches the task, then the control plane goes away before the result is posted.
	var tl agentproto.TaskList
	fetch(t, e, &tl)
	if len(tl.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tl.Tasks))
	}
	url := e.srv.URL
	e.srv.Close()
	e.agent.Execute(ctx, tl.Tasks[0])
	if _, err := e.agent.PollOnce(ctx, 0); err == nil {
		t.Fatal("poll should fail while the control plane is down")
	}
	// Control plane comes back (new process, same database).
	restart(t, e, url)
	r := e.pump(run.ID)
	if r.State != store.RunVerified || e.issueCalls.Load() != 1 {
		t.Fatalf("state %s, issue calls %d (want exactly 1)", r.State, e.issueCalls.Load())
	}
}

func TestRevokedAgentIsRefusedAndRunFails(t *testing.T) {
	e := newEnv(t)
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	if err := e.svc.RevokeAgent(ctx, e.owner, "web-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.agent.PollOnce(ctx, 0); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("revoked agent poll: %v", err)
	}
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	js, _ := q.Claim(ctx, []string{app.JobKindAdvance}, 10)
	for _, j := range js {
		_ = e.svc.RunAdvance(ctx, j)
	}
	r, _ := e.svc.GetRun(ctx, e.owner, run.ID)
	if r.State != store.RunFailed || !strings.Contains(r.Error, "revoked") {
		t.Fatalf("state %s err %q", r.State, r.Error)
	}
}

func TestDeploymentSANsMustBeAllowedByAgent(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www", Issuer: "fake",
		SANs: []string{"evil.example.com"}})
	if !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "allowed_sans") {
		t.Fatalf("want allowed_sans rejection, got %v", err)
	}
	if app.SANAllowed("a.b.wf.test", []string{"*.wf.test"}, false) || !app.SANAllowed("a.wf.test", []string{"*.wf.test"}, false) {
		t.Fatal("wildcard allowlist must match exactly one label")
	}
}

func TestDeploymentEndpointByHost(t *testing.T) {
	refs := []string{"API.wf.test", "api.wf.test:443", ""}
	e := newEnvWith(t, testpki.Options{}, func(c *agent.Config) {
		for i := range refs {
			tg := c.Targets[0]
			tg.Name, tg.LiveLink = fmt.Sprintf("api%d", i), filepath.Join(c.StateDir, "live", fmt.Sprintf("api%d", i))
			c.Targets = append(c.Targets, tg)
		}
	})
	if _, err := e.svc.CreateScope(ctx, e.owner, "wf", store.ScopeConfig{AllowHosts: []string{"*.wf.test"}}); err != nil {
		t.Fatal(err)
	}
	ep, err := e.svc.AddEndpoint(ctx, e.owner, app.AddEndpointInput{Host: "api.wf.test", Scope: "wf"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateLineage(ctx, e.owner, "api", "", ""); err != nil {
		t.Fatal(err)
	}
	refs[2] = ep.ID
	for i, ref := range refs {
		d, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "api", Agent: "web-01", Target: fmt.Sprintf("api%d", i),
			Issuer: "fake", SANs: []string{"api.wf.test"}, Endpoint: ref})
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if d.EndpointID == nil || *d.EndpointID != ep.ID {
			t.Fatalf("%s: endpoint %v, want %s", ref, d.EndpointID, ep.ID)
		}
	}
	for _, ref := range []string{"api.wf.test:8443", "other.wf.test"} {
		_, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "api", Agent: "web-01", Target: "www",
			Issuer: "fake", SANs: []string{"api.wf.test"}, Endpoint: ref})
		if !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("%s: want not found, got %v", ref, err)
		}
	}
}

func TestEnrollmentTokenIsSingleUseAndCAIsPinned(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.svc.CreateEnrollmentToken(ctx, e.owner, "", time.Hour, e.srv.URL)
	cfg := *e.agent.Config()
	cfg.StateDir, cfg.Name = t.TempDir(), "web-02"
	// Wrong CA hash: the agent refuses to talk to the server at all.
	if _, err := agent.Enroll(ctx, &cfg, tok.Token, "sha256:"+strings.Repeat("ab", 32), "h"); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong CA hash: %v", err)
	}
	if _, err := agent.Enroll(ctx, &cfg, tok.Token, tok.CAHash, "h"); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir, cfg.Name = t.TempDir(), "web-03"
	if _, err := agent.Enroll(ctx, &cfg, tok.Token, tok.CAHash, "h"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("token reuse: %v", err)
	}
}

// ---- helpers ----

func fetch(t *testing.T, e *env, out *agentproto.TaskList) {
	t.Helper()
	// Use the agent's own mTLS identity via a poll-less fetch: execute nothing.
	h := sha256.Sum256(nil)
	_ = hex.EncodeToString(h[:])
	tasks, err := e.svc.AgentPoll(ctx, app.AgentIdentity{OrgID: e.owner.OrgID, AgentID: e.agent.ID()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	out.Tasks = tasks
}

func restart(t *testing.T, e *env, url string) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	as := &agentapi.Server{Svc: e.svc, Log: log}
	tcfg, err := as.TLSConfig([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(as.Handler())
	srv.TLS = tcfg
	// Listen on the same address the agent is configured for.
	addr := strings.TrimPrefix(url, "https://")
	ln, err := netListen(addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	srv.Listener = ln
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.srv = srv
}

var _ = http.StatusOK

func TestRateLimitHonorsRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.issueRL.Store(3600)
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	// The issue task fails with the CA's Retry-After.
	e.step(3)
	r, _ := e.svc.GetRun(ctx, e.owner, run.ID)
	if r.State != store.RunRetryScheduled || r.NextAttemptAt == nil {
		t.Fatalf("want retry_scheduled, got %s (%s)", r.State, steps(r))
	}
	if d := time.Until(*r.NextAttemptAt); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("next attempt in %s, want about 1h (the CA's Retry-After)", d)
	}
	if last := r.Steps[len(r.Steps)-1].Detail; !strings.Contains(last, "Retry-After 1h0m0s") {
		t.Fatalf("timeline does not mention Retry-After: %q", last)
	}
	// After the wait, issuance succeeds and the rate-limited try did not count.
	r = e.pump(run.ID)
	if r.State != store.RunVerified || r.Attempt != 1 || e.issueCalls.Load() != 2 {
		t.Fatalf("state %s attempt %d calls %d (%s)", r.State, r.Attempt, e.issueCalls.Load(), steps(r))
	}
}

// step runs a few rounds of control-plane jobs and agent polls.
func (e *env) step(rounds int) {
	e.t.Helper()
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	for range rounds {
		js, err := q.Claim(ctx, []string{app.JobKindAdvance}, 10)
		if err != nil {
			e.t.Fatal(err)
		}
		for _, j := range js {
			if err := e.svc.RunAdvance(ctx, j); err != nil {
				e.t.Fatalf("advance: %v", err)
			}
		}
		if _, err := e.agent.PollOnce(ctx, 0); err != nil {
			e.t.Fatal(err)
		}
	}
}

// windowInTwoDays returns a one-hour UTC window two days from now and its start.
func windowInTwoDays() (string, time.Time) {
	day := time.Now().UTC().AddDate(0, 0, 2)
	start := time.Date(day.Year(), day.Month(), day.Day(), 3, 0, 0, 0, time.UTC)
	return day.Weekday().String()[:3] + " 03:00-04:00 UTC", start
}

func TestMaintenanceWindowDefersActivation(t *testing.T) {
	e := newEnv(t)
	spec, start := windowInTwoDays()
	if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, e.dep.ID, spec, ""); err != nil {
		t.Fatal(err)
	}
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	e.step(4)
	r, _ := e.svc.GetRun(ctx, e.owner, run.ID)
	if r.State != store.RunWaitingWindow || r.IssuedSHA256 == nil || r.NextAttemptAt == nil || !r.NextAttemptAt.Equal(start) {
		t.Fatalf("want waiting_window until %s with an issued cert, got %s next %v (%s)", start, r.State, r.NextAttemptAt, steps(r))
	}
	if strings.Contains(steps(r), "deploying") {
		t.Fatal("deployed outside the window")
	}
	// Waking up early (before the window) changes nothing.
	e.step(2)
	if r, _ = e.svc.GetRun(ctx, e.owner, run.ID); r.State != store.RunWaitingWindow {
		t.Fatalf("early wake-up: %s", r.State)
	}
	// Inside the window the run deploys and verifies.
	e.svc.Now = func() time.Time { return start.Add(10 * time.Minute) }
	r = e.pump(run.ID)
	if r.State != store.RunVerified {
		t.Fatalf("in window: %s (%s)", r.State, steps(r))
	}
}

func TestMaintenanceWindowPastDeadlineBlocksThenEmergency(t *testing.T) {
	// The current certificate expires in 5 days: with a 7-day minimum lead
	// the safety deadline has passed, so no future window is acceptable.
	now := time.Now()
	e := newEnvOld(t, testpki.Options{NotBefore: now.Add(-85 * 24 * time.Hour), NotAfter: now.Add(5 * 24 * time.Hour)})
	spec, _ := windowInTwoDays()
	if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, e.dep.ID, spec, app.EmergencyBlock); err != nil {
		t.Fatal(err)
	}
	run, _ := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	e.step(4)
	r, _ := e.svc.GetRun(ctx, e.owner, run.ID)
	if r.State != store.RunBlocked || !strings.Contains(r.Error, "safety deadline") {
		t.Fatalf("want blocked, got %s %q (%s)", r.State, r.Error, steps(r))
	}
	var alerts int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'renewals.blocked'`).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("want one renewals.blocked audit event, got %d", alerts)
	}
	// Still blocked on re-evaluation, without a second alert.
	e.step(2)
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'renewals.blocked'`).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("blocked event repeated: %d", alerts)
	}
	// The owner allows emergency activation: the run proceeds right away.
	if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, e.dep.ID, spec, app.EmergencyRenewal); err != nil {
		t.Fatal(err)
	}
	r = e.pump(run.ID)
	if r.State != store.RunVerified || !strings.Contains(steps(r), "blocked") {
		t.Fatalf("after emergency override: %s (%s)", r.State, steps(r))
	}
	var overrides int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'renewals.window_override'`).Scan(&overrides)
	if overrides != 1 {
		t.Fatalf("want the override in the audit trail, got %d", overrides)
	}
}

func TestInvalidWindowRejected(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, e.dep.ID, "Mon 02:00-05:00 Nowhere/City", ""); err == nil {
		t.Fatal("unknown zone accepted")
	}
	if _, err := e.svc.SetDeploymentWindow(ctx, e.owner, e.dep.ID, "", "sometimes"); err == nil {
		t.Fatal("unknown emergency mode accepted")
	}
}

// blockingTransport holds every request until release is closed, then fails it.
type blockingTransport struct{ started, release chan struct{} }

func (b *blockingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return nil, errors.New("acme directory unavailable")
}

// An ARI check that started before a renewal finished must not overwrite the
// schedule the renewal set for its new certificate.
func TestARICheckDoesNotOverwriteNewerCertificate(t *testing.T) {
	e := newEnv(t)
	bt := &blockingTransport{started: make(chan struct{}, 1), release: make(chan struct{})}
	e.svc.ARI = &ari.Client{HTTP: &http.Client{Transport: bt}}

	if _, err := e.svc.ScheduleRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	js, err := q.Claim(ctx, []string{app.JobKindARICheck}, 1)
	if err != nil || len(js) != 1 {
		t.Fatalf("claim ari check: %v %d", err, len(js))
	}
	done := make(chan error, 1)
	go func() { done <- e.svc.RunARICheck(ctx, js[0]) }()
	<-bt.started // the check has read the old certificate and is asking the CA

	run, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.pump(run.ID); r.State != store.RunVerified {
		t.Fatalf("renewal: %s %q", r.State, r.Error)
	}
	close(bt.release)
	if err := <-done; err != nil {
		t.Fatalf("ari check: %v", err)
	}

	ds, _ := e.svc.ListDeployments(ctx, e.owner)
	d := ds[0]
	if !strings.Contains(d.RenewReason, "until ARI is checked") {
		t.Fatalf("stale ARI result overwrote the new certificate's schedule: %q", d.RenewReason)
	}
	if d.ARINextAt == nil || d.ARINextAt.After(time.Now()) {
		t.Fatalf("a fresh ARI check should still be due, next check %v", d.ARINextAt)
	}
}
