package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/http/webroot"
	"github.com/go-acme/lego/v5/registration"
)

// runDir is where a run's key and certificate live.
func (a *Agent) runDir(target, run string) string {
	return filepath.Join(a.cfg.StateDir, "certs", target, run)
}

// loadOrCreateKey returns the run's private key, creating it (0600) once.
// Re-running an issue task for the same run reuses the key.
func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("corrupt key file " + path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return k.(crypto.Signer), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, os.Rename(tmp, path)
}

func (a *Agent) handleIssue(ctx context.Context, t *agentproto.Task) (any, error) {
	tgt, ok := a.cfg.target(t.Target)
	if !ok {
		return nil, fmt.Errorf("unknown target %q", t.Target)
	}
	var p agentproto.IssuePayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil, err
	}
	if p.RunID == "" || len(p.SANs) == 0 {
		return nil, errors.New("issue task needs run_id and sans")
	}
	// Empty means the default, for control planes older than this field.
	if p.KeyAlgorithm != "" && p.KeyAlgorithm != agentproto.KeyECDSAP256 {
		return nil, fmt.Errorf("unsupported key algorithm %q", p.KeyAlgorithm)
	}
	dns01 := p.Challenge == agentproto.ChallengeDNS01
	if p.Challenge != "" && p.Challenge != agentproto.ChallengeHTTP01 && !dns01 {
		return nil, fmt.Errorf("unsupported challenge %q", p.Challenge)
	}
	for _, san := range p.SANs {
		if !agentproto.SANAllowed(san, tgt.AllowedSANs, dns01) { // the control plane is not trusted with this decision
			return nil, fmt.Errorf("SAN %q is not in this host's allowed_sans for target %s", san, tgt.Name)
		}
	}
	if !dns01 && tgt.Webroot == "" {
		return nil, fmt.Errorf("target %s has no webroot for HTTP-01", tgt.Name)
	}
	if !p.AgreeTOS {
		return nil, errors.New("issuer terms of service not accepted")
	}
	dir := a.runDir(tgt.Name, p.RunID)
	key, err := loadOrCreateKey(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: p.SANs[0]}, DNSNames: p.SANs}, key)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	client, err := a.acmeClient(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := a.setChallenge(client, tgt, dns01); err != nil {
		return nil, err
	}
	req := certificate.ObtainForCSRRequest{CSR: csr, Bundle: true, Profile: p.Profile, ReplacesCertID: p.ReplacesCertID}
	res, err := client.Certificate.ObtainForCSR(ctx, req)
	if err != nil && req.ReplacesCertID != "" && replacesRejected(err) {
		a.log.Warn("order with replaces was refused; ordering without it",
			"target", tgt.Name, "run", p.RunID, "replaces", req.ReplacesCertID, "error", err)
		req.ReplacesCertID = ""
		res, err = client.Certificate.ObtainForCSR(ctx, req)
	}
	if err != nil {
		return issueFailure(err), fmt.Errorf("acme: %w", err)
	}
	// Keep a copy beside the key; deploy writes the chain the control plane validated.
	if err := os.WriteFile(filepath.Join(dir, "issued.pem"), res.Certificate, 0o644); err != nil { //nolint:gosec // public certificate chain
		return nil, err
	}
	return agentproto.IssueOutput{ChainPEM: string(res.Certificate)}, nil
}

// setChallenge registers exactly one solver, so lego cannot fall back to
// another challenge type than the one that was approved.
func (a *Agent) setChallenge(client *lego.Client, tgt *TargetConfig, dns01 bool) error {
	if !dns01 {
		prov, err := webroot.NewHTTPProvider(tgt.Webroot)
		if err != nil {
			return err
		}
		return client.Challenge.SetHTTP01Provider(prov)
	}
	mux, err := newDNSMux(a.cfg.DNSSolvers, a.log)
	if err != nil {
		return err
	}
	return client.Challenge.SetDNS01Provider(mux)
}

// issueFailure extracts what the control plane needs to schedule the next
// attempt: the ACME problem type and, for rate limits, the CA's Retry-After.
func issueFailure(err error) any {
	out := agentproto.IssueOutput{}
	var rl *acme.RateLimitedError
	if errors.As(err, &rl) {
		out.ProblemType = acme.RateLimitedErrorType
		out.RetryAfterSeconds = int64(rl.RetryAfter.Round(time.Second) / time.Second)
	}
	var pd *acme.ProblemDetails
	if out.ProblemType == "" && errors.As(err, &pd) {
		out.ProblemType = pd.Type
	}
	if out.ProblemType == "" {
		return nil
	}
	return out
}

// acmeAccount implements registration.User; the account key is separate
// from every certificate key and stays on this host.
type acmeAccount struct {
	Email        string                `json:"email"`
	Registration *acme.ExtendedAccount `json:"registration"`
	key          crypto.Signer
}

func (u *acmeAccount) GetEmail() string                       { return u.Email }
func (u *acmeAccount) GetRegistration() *acme.ExtendedAccount { return u.Registration }
func (u *acmeAccount) GetPrivateKey() crypto.Signer           { return u.key }

func (a *Agent) acmeHTTPClient() (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if a.cfg.ACMECAFile != "" {
		b, err := os.ReadFile(a.cfg.ACMECAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("acme_ca_file has no certificates")
		}
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}, nil
}

func (a *Agent) acmeClient(ctx context.Context, p agentproto.IssuePayload) (*lego.Client, error) {
	h := sha256.Sum256([]byte(p.DirectoryURL))
	dir := filepath.Join(a.cfg.StateDir, "acme", hex.EncodeToString(h[:8]))
	key, err := loadOrCreateKey(filepath.Join(dir, "account.key"))
	if err != nil {
		return nil, err
	}
	acct := &acmeAccount{Email: p.Email, key: key}
	if b, err := os.ReadFile(filepath.Join(dir, "account.json")); err == nil {
		_ = json.Unmarshal(b, acct)
	}
	hc, err := a.acmeHTTPClient()
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(acct)
	cfg.CADirURL, cfg.HTTPClient, cfg.UserAgent = p.DirectoryURL, hc, "certloom-agent"
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme directory: %w", err)
	}
	if acct.Registration == nil {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: p.AgreeTOS})
		if err != nil {
			return nil, fmt.Errorf("acme account registration: %w", err)
		}
		acct.Registration = reg
		b, _ := json.Marshal(acct)
		if err := os.WriteFile(filepath.Join(dir, "account.json"), b, 0o600); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// replacesRejected reports whether an order may have been refused because of
// its RFC 9773 "replaces" hint: the predecessor was already replaced (e.g. by
// an order that was later rolled back), comes from another CA or the staging
// environment, or was issued to a different account. The hint is optional, so
// such an order is placed once more without it.
func replacesRejected(err error) bool {
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) {
		return false
	}
	switch pd.Type {
	case acme.AlreadyReplacedErrorType, acme.MalformedErrorType, acme.UnauthorizedErrorType:
		return true
	}
	return false
}
