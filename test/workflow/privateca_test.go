package workflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/privateca"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

const vaultToken = "hvs.test-token-never-returned"

// fakeCA stands in for Vault: it signs CSRs with the env's CA.
type fakeCA struct {
	e        *env
	stateDir string
	calls    atomic.Int32
	fail     atomic.Pointer[privateca.Error] // returned by the next call
	csrs     []*x509.CertificateRequest
}

func (f *fakeCA) Sign(_ context.Context, csrPEM string, sans []string) (string, error) {
	f.calls.Add(1)
	if err := f.fail.Swap(nil); err != nil {
		return "", err
	}
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return "", err
	}
	f.csrs = append(f.csrs, csr)
	leaf := testpki.IssueWithKey(f.e.t, f.e.ca, pubOnly{csr.PublicKey}, testpki.Options{CommonName: sans[0], DNSNames: csr.DNSNames})
	return string(leaf.PEM()), nil
}

// privateCAEnv adds a target "pki" and a Vault issuer "vault" whose client
// is replaced by fakeCA.
func privateCAEnv(t *testing.T) (*env, *fakeCA) {
	var stateDir string
	e := newEnvWith(t, testpki.Options{}, func(c *agent.Config) {
		stateDir = c.StateDir
		c.Targets = append(c.Targets, agent.TargetConfig{Name: "pki", Type: "nginx", LiveLink: filepath.Join(c.StateDir, "live", "pki"),
			TestCommand: []string{"true"}, ReloadCommand: []string{"true"}, VerifyAddress: "127.0.0.1:1",
			AllowedSANs: []string{"pki.wf.test", "*.pki.wf.test"}})
	})
	ca := &fakeCA{e: e, stateDir: stateDir}
	e.svc.CASigner = func(iss *store.Issuer, cred secret.Value) (privateca.Signer, error) {
		if iss.Kind != store.IssuerVault || cred.RevealString() != vaultToken {
			return nil, errors.New("signer built with the wrong issuer or credential")
		}
		return ca, nil
	}
	iss := &store.Issuer{Name: "vault", Kind: store.IssuerVault, DirectoryURL: "https://vault.wf.test:8200", CABundle: string(e.ca.PEM()),
		Settings: store.IssuerSettings{Mount: "pki_int", Role: "web", AuthMethod: privateca.VaultToken}}
	if err := e.svc.CreateIssuer(ctx, e.owner, iss, secret.FromString(vaultToken)); err != nil {
		t.Fatal(err)
	}
	return e, ca
}

func (e *env) pkiDeployment(sans ...string) *store.Deployment {
	e.t.Helper()
	d, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "pki", Issuer: "vault", SANs: sans})
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) renew(depID string) *store.Run {
	e.t.Helper()
	run, err := e.svc.RequestRenewal(ctx, e.owner, depID)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.pump(run.ID)
}

func TestNativeIssuerSignsAgentCSR(t *testing.T) {
	e, ca := privateCAEnv(t)
	d := e.pkiDeployment("pki.wf.test", "*.pki.wf.test") // wildcards need no DNS-01 here
	if d.Challenge != agentproto.ChallengeNone {
		t.Fatalf("challenge %q, want none", d.Challenge)
	}
	spec := e.spec(d.ID)
	if spec.Issuer.Kind != "vault" || spec.Issuer.Mount != "pki_int" || spec.Issuer.Role != "web" || spec.Challenge != "" {
		t.Fatalf("spec issuer: %+v", spec.Issuer)
	}

	r := e.renew(d.ID)
	if r.State != store.RunVerified {
		t.Fatalf("state %s err %q steps %s", r.State, r.Error, steps(r))
	}
	if got := steps(r); got != "planned>issuing>signing>issued>deploying>verifying>verified" {
		t.Fatalf("timeline: %s", got)
	}
	if ca.calls.Load() != 1 {
		t.Fatalf("CA called %d times", ca.calls.Load())
	}

	// The key the CSR was made with is the one the agent kept for the deploy step.
	b, err := os.ReadFile(filepath.Join(ca.stateDir, "certs", "pki", r.ID, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.csrs[0].PublicKey.(*ecdsa.PublicKey).Equal(k.(crypto.Signer).Public()) {
		t.Fatal("CSR key is not the run key")
	}

	// The credential never leaves the control plane in clear.
	var leaked int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM agent_tasks WHERE envelope::text LIKE '%'||$1||'%'`, vaultToken).Scan(&leaked)
	iss, err := e.svc.GetIssuer(ctx, e.owner, "vault")
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(iss)
	if leaked != 0 || strings.Contains(string(j), vaultToken) || !iss.HasCredential {
		t.Fatalf("credential exposed (tasks %d) or missing: %s", leaked, j)
	}
	var used int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'issuers.credential_used'`).Scan(&used)
	if used != 1 {
		t.Fatalf("credential use audited %d times", used)
	}
}

func TestNativeIssuerRefusalFailsWithoutRetry(t *testing.T) {
	e, ca := privateCAEnv(t)
	d := e.pkiDeployment("pki.wf.test")
	ca.fail.Store(&privateca.Error{Status: 400, Permanent: true, Msg: "pki.wf.test not allowed by this role"})
	r := e.renew(d.ID)
	if r.State != store.RunFailed || !strings.Contains(r.Error, "not allowed by this role") || ca.calls.Load() != 1 {
		t.Fatalf("state %s err %q calls %d", r.State, r.Error, ca.calls.Load())
	}
}

func TestNativeIssuerOutageIsRetried(t *testing.T) {
	e, ca := privateCAEnv(t)
	d := e.pkiDeployment("pki.wf.test")
	ca.fail.Store(&privateca.Error{Status: 503, Msg: "Vault is sealed"})
	r := e.renew(d.ID)
	if r.State != store.RunVerified || ca.calls.Load() != 2 || r.Attempt != 2 {
		t.Fatalf("state %s err %q calls %d attempt %d steps %s", r.State, r.Error, ca.calls.Load(), r.Attempt, steps(r))
	}
}

func TestNativeIssuerRejectsForeignCSR(t *testing.T) {
	e, ca := privateCAEnv(t)
	d := e.pkiDeployment("pki.wf.test")
	// A compromised or buggy agent asks for more than the deployment covers.
	e.agent.SetHandler(agentproto.TaskCSR, func(context.Context, *agentproto.Task) (any, error) {
		h := testpki.NewHierarchy(t, "x")
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"pki.wf.test", "bank.example"}}, h.Leaf.Key)
		return agentproto.CSROutput{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}, nil
	})
	r := e.renew(d.ID)
	if r.State != store.RunFailed || !strings.Contains(r.Error, "agent CSR rejected") || ca.calls.Load() != 0 {
		t.Fatalf("state %s err %q calls %d", r.State, r.Error, ca.calls.Load())
	}
}

func TestNativeIssuerNeedsCSRCapableAgent(t *testing.T) {
	e, _ := privateCAEnv(t)
	a, _ := e.svc.ListAgents(ctx, e.owner)
	e.heartbeatAs(a[0].ID, func(hb *agentproto.Heartbeat) {
		hb.Tasks = slices.DeleteFunc(hb.Tasks, func(t string) bool { return t == agentproto.TaskCSR })
	})
	_, err := e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "pki", Issuer: "vault", SANs: []string{"pki.wf.test"}})
	if err == nil || !strings.Contains(err.Error(), agentproto.TaskCSR) {
		t.Fatalf("old agent accepted: %v", err)
	}
	_, err = e.svc.CreateDeployment(ctx, e.owner, app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "pki", Issuer: "vault",
		SANs: []string{"pki.wf.test"}, Challenge: "dns-01"})
	if err == nil || !strings.Contains(err.Error(), "does not apply") {
		t.Fatalf("challenge with native issuer: %v", err)
	}
}

func TestNativeIssuerValidationAndCredentialRotation(t *testing.T) {
	e, ca := privateCAEnv(t)
	bundle := string(e.ca.PEM())
	bad := map[string]*store.Issuer{
		"no role": {Kind: "vault", DirectoryURL: "https://v.test", CABundle: bundle, Settings: store.IssuerSettings{Mount: "pki", AuthMethod: "token"}},
		"dot mount": {Kind: "vault", DirectoryURL: "https://v.test", CABundle: bundle,
			Settings: store.IssuerSettings{Mount: "pki/../sys", Role: "web", AuthMethod: "token"}},
		"approle without role_id": {Kind: "vault", DirectoryURL: "https://v.test", CABundle: bundle,
			Settings: store.IssuerSettings{Mount: "pki", Role: "web", AuthMethod: "approle"}},
		"http url":  {Kind: "vault", DirectoryURL: "http://v.test", CABundle: bundle, Settings: store.IssuerSettings{Mount: "pki", Role: "web", AuthMethod: "token"}},
		"url path":  {Kind: "vault", DirectoryURL: "https://v.test/v1", CABundle: bundle, Settings: store.IssuerSettings{Mount: "pki", Role: "web", AuthMethod: "token"}},
		"no bundle": {Kind: "vault", DirectoryURL: "https://v.test", Settings: store.IssuerSettings{Mount: "pki", Role: "web", AuthMethod: "token"}},
		"tos":       {Kind: "vault", DirectoryURL: "https://v.test", CABundle: bundle, AgreeTOS: true, Settings: store.IssuerSettings{Mount: "pki", Role: "web", AuthMethod: "token"}},
		"stepca key not a JWK": {Kind: "stepca", DirectoryURL: "https://ca.test", CABundle: bundle,
			Settings: store.IssuerSettings{Provisioner: "certloom"}},
		"acme with credential": {DirectoryURL: "https://acme.test/dir", AgreeTOS: true},
		"unknown kind":         {Kind: "adcs", DirectoryURL: "https://ca.test", CABundle: bundle},
	}
	for name, iss := range bad {
		iss.Name = "bad"
		if err := e.svc.CreateIssuer(ctx, e.owner, iss, secret.FromString("x")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := e.svc.UpdateIssuer(ctx, e.owner, "fake", app.IssuerPatch{CABundle: &bundle}); err == nil {
		t.Error("ca_bundle accepted on an ACME issuer")
	}

	// A rotated credential is what the next signing call uses.
	if _, err := e.svc.SetIssuerCredential(ctx, e.owner, "vault", secret.FromString("hvs.rotated")); err != nil {
		t.Fatal(err)
	}
	d := e.pkiDeployment("pki.wf.test")
	r := e.renew(d.ID)
	if r.State != store.RunFailed || !strings.Contains(r.Error, "wrong issuer or credential") || ca.calls.Load() != 0 {
		t.Fatalf("state %s err %q", r.State, r.Error)
	}
	if _, err := e.svc.SetIssuerCredential(ctx, e.owner, "fake", secret.FromString("x")); err == nil {
		t.Error("credential accepted on an ACME issuer")
	}
}

// pubOnly lets testpki issue for a key it only has the public half of.
type pubOnly struct{ pub crypto.PublicKey }

func (p pubOnly) Public() crypto.PublicKey { return p.pub }
func (pubOnly) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("public key only")
}
