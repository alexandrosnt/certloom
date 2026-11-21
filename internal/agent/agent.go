package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/version"
)

// identity is persisted under state_dir after enrollment.
type identity struct {
	AgentID       string `json:"agent_id"`
	OrgID         string `json:"org_id"`
	TaskPublicKey []byte `json:"task_public_key"`
}

// Agent is a running agent.
type Agent struct {
	cfg   *Config
	log   *slog.Logger
	state *State
	id    identity

	mu     sync.Mutex
	client *http.Client
	cert   *x509.Certificate
	// HPKE sealing keys (seal.go)
	sealPriv, sealPub, sealPrev []byte

	// Handlers can be replaced in tests.
	handlers map[string]func(context.Context, *agentproto.Task) (any, error)
}

func (a *Agent) path(name string) string { return filepath.Join(a.cfg.StateDir, name) }

func newKeyCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

// pinnedTLS trusts only a server whose chain contains a CA certificate with
// the given SHA-256 ("sha256:<hex>") and whose leaf is signed by it.
func pinnedTLS(caHash, serverName string) *tls.Config {
	want := strings.TrimPrefix(strings.ToLower(caHash), "sha256:")
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection pinning below
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				s := sha256.Sum256(c.Raw)
				if hex.EncodeToString(s[:]) != want {
					continue
				}
				pool := x509.NewCertPool()
				pool.AddCert(c)
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: serverName})
				return err
			}
			return errors.New("server did not present the pinned CA (check --ca-hash)")
		}}
}

// Enroll performs one-time enrollment and writes the identity to state_dir.
func Enroll(ctx context.Context, cfg *Config, token, caHash, hostname string) (string, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "agent.json")); err == nil {
		return "", errors.New("this agent is already enrolled (remove state_dir to re-enroll)")
	}
	u, err := url.Parse(cfg.Server)
	if err != nil {
		return "", err
	}
	keyPEM, csrPEM, err := newKeyCSR("")
	if err != nil {
		return "", err
	}
	name := cfg.Name
	if name == "" {
		name = hostname
	}
	body, _ := json.Marshal(agentproto.EnrollRequest{Token: token, CSRPEM: string(csrPEM), Name: name, Hostname: hostname})
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: pinnedTLS(caHash, u.Hostname())}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Server+agentproto.PathEnroll, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("enrollment rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var er agentproto.EnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		return "", err
	}
	// The CA returned must be the one we pinned.
	blk, _ := pem.Decode([]byte(er.CAPEM))
	if blk == nil {
		return "", errors.New("enrollment response lacks CA")
	}
	if s := sha256.Sum256(blk.Bytes); "sha256:"+hex.EncodeToString(s[:]) != strings.ToLower(caHash) {
		return "", errors.New("enrollment response CA does not match --ca-hash")
	}
	files := map[string][]byte{"agent.key": keyPEM, "agent.crt": []byte(er.CertPEM), "ca.pem": []byte(er.CAPEM)}
	idb, _ := json.Marshal(identity{AgentID: er.AgentID, OrgID: er.OrgID, TaskPublicKey: er.TaskPublicKey})
	files["agent.json"] = idb
	for n, b := range files {
		mode := os.FileMode(0o644)
		if n == "agent.key" {
			mode = 0o600
		}
		if err := writeAtomic(filepath.Join(cfg.StateDir, n), b, mode); err != nil {
			return "", err
		}
	}
	return er.AgentID, nil
}

// New loads an enrolled agent.
func New(cfg *Config, log *slog.Logger) (*Agent, error) {
	a := &Agent{cfg: cfg, log: log}
	setDNSResolvers(cfg.Resolvers)
	b, err := os.ReadFile(a.path("agent.json"))
	if err != nil {
		return nil, fmt.Errorf("not enrolled (run `certloom-agent enroll`): %w", err)
	}
	if err := json.Unmarshal(b, &a.id); err != nil {
		return nil, err
	}
	if len(a.id.TaskPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid task public key in agent.json")
	}
	if a.state, err = OpenState(cfg.StateDir); err != nil {
		return nil, err
	}
	if err := a.loadSealKey(); err != nil {
		return nil, fmt.Errorf("sealing key: %w", err)
	}
	if err := a.loadClient(); err != nil {
		return nil, err
	}
	a.handlers = map[string]func(context.Context, *agentproto.Task) (any, error){
		agentproto.TaskInventoryScan: a.handleInventory,
		agentproto.TaskIssue:         a.handleIssue,
		agentproto.TaskDeploy:        a.handleDeploy,
		agentproto.TaskVerify:        a.handleVerify,
		agentproto.TaskRollback:      a.handleRollback,
	}
	return a, nil
}

// Close releases resources.
func (a *Agent) Close() error { return a.state.Close() }

// ID returns the agent id.
func (a *Agent) ID() string { return a.id.AgentID }

func (a *Agent) loadClient() error {
	kp, err := tls.LoadX509KeyPair(a.path("agent.crt"), a.path("agent.key"))
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(a.path("ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("ca.pem has no certificate")
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	u, err := url.Parse(a.cfg.Server)
	if err != nil {
		return err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: u.Hostname(),
		Certificates: []tls.Certificate{kp}}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 45 * time.Second}
	a.mu.Lock()
	a.client, a.cert = &http.Client{Transport: tr, Timeout: 60 * time.Second}, leaf
	a.mu.Unlock()
	return nil
}

func (a *Agent) do(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.cfg.Server+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Heartbeat reports liveness and targets.
func (a *Agent) Heartbeat(ctx context.Context) error {
	host, _ := os.Hostname()
	hb := agentproto.Heartbeat{Version: version.Version, Hostname: host}
	for _, t := range a.cfg.Targets {
		hb.Targets = append(hb.Targets, agentproto.Target{Name: t.Name, Type: t.Type, AllowedSANs: t.AllowedSANs, ACME: t.Webroot != ""})
	}
	for _, t := range agentproto.AllTaskTypes {
		if a.cfg.taskAllowed(t) {
			hb.Tasks = append(hb.Tasks, t)
		}
	}
	hb.DNSSolvers = a.cfg.dnsSolverInfo()
	hb.NoCentralDNS, hb.NoCentralEAB = !a.cfg.centralDNSAllowed(), !a.cfg.centralEABAllowed()
	if !hb.NoCentralDNS || !hb.NoCentralEAB {
		a.mu.Lock()
		hb.SealKey = a.sealPub
		a.mu.Unlock()
	}
	hb.ACMEAccounts = a.accountSlots()
	for _, e := range a.cfg.ACMEEAB {
		hb.LocalEAB = append(hb.LocalEAB, e.DirectoryURL)
	}
	return a.do(ctx, http.MethodPost, agentproto.PathHeartbeat, hb, nil)
}

// RenewIdentityIfDue rotates the client certificate after half its lifetime.
func (a *Agent) RenewIdentityIfDue(ctx context.Context, now time.Time) error {
	a.mu.Lock()
	c := a.cert
	a.mu.Unlock()
	half := c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2)
	if now.Before(half) {
		return nil
	}
	keyPEM, csrPEM, err := newKeyCSR("")
	if err != nil {
		return err
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := a.do(ctx, http.MethodPost, agentproto.PathRenew, agentproto.RenewRequest{CSRPEM: string(csrPEM)}, &out); err != nil {
		return err
	}
	if err := writeAtomic(a.path("agent.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(a.path("agent.crt"), []byte(out.CertPEM), 0o644); err != nil {
		return err
	}
	if err := a.rotateSealKey(); err != nil {
		a.log.Error("sealing key rotation failed; keeping the old key", "error", err)
	}
	a.log.Info("agent identity certificate renewed")
	return a.loadClient()
}

// PollOnce long-polls for tasks and executes them; it also re-sends any
// results that were not acknowledged (e.g. after a crash or network loss).
func (a *Agent) PollOnce(ctx context.Context, wait time.Duration) (int, error) {
	if err := a.flushUnsent(ctx); err != nil {
		a.log.Warn("could not deliver stored results", "error", err)
	}
	var tl agentproto.TaskList
	if err := a.do(ctx, http.MethodGet, fmt.Sprintf("%s?wait=%d", agentproto.PathTasks, int(wait.Seconds())), nil, &tl); err != nil {
		return 0, err
	}
	for _, env := range tl.Tasks {
		a.Execute(ctx, env)
	}
	return len(tl.Tasks), a.flushUnsent(ctx)
}

// Execute verifies, admits, runs and records one task. A task with an
// invalid signature is never acted on and gets no result.
func (a *Agent) Execute(ctx context.Context, env agentproto.Envelope) {
	t, err := agentproto.Open(ed25519.PublicKey(a.id.TaskPublicKey), env, a.id.OrgID, a.id.AgentID, time.Now())
	if err != nil {
		if errors.Is(err, agentproto.ErrBadSignature) || errors.Is(err, agentproto.ErrWrongAgent) {
			a.log.Error("rejected task", "error", err)
			return
		}
		// Expired but authentic: report so the control plane stops waiting.
		var tt agentproto.Task
		if json.Unmarshal(env.Task, &tt) == nil && tt.ID != "" {
			_ = a.state.Record(&agentproto.Task{ID: tt.ID}, agentproto.Result{OK: false, Error: err.Error()})
		}
		return
	}
	if prev, _ := a.state.Result(t.ID); prev != nil {
		return // already executed; flushUnsent re-delivers the stored result
	}
	res := agentproto.Result{OK: true}
	h := a.handlers[t.Type]
	switch {
	case !a.cfg.taskAllowed(t.Type) || h == nil:
		res = agentproto.Result{Error: agentproto.ErrNotAllowed.Error() + ": " + t.Type}
	default:
		if err := a.state.Admit(t); err != nil {
			if errors.Is(err, ErrReplay) {
				// Admitted before but no result recorded: the agent stopped
				// while running it. Never run it twice; report the unknown
				// outcome so the control plane can roll back if needed.
				err = fmt.Errorf("interrupted: the agent stopped while running this task, outcome unknown (%w)", err)
			}
			res = agentproto.Result{Error: err.Error()}
			break
		}
		a.log.Info("executing task", "task", t.ID, "type", t.Type, "target", t.Target, "seq", t.Seq)
		out, err := h(ctx, t)
		if out != nil {
			res.Output, _ = json.Marshal(out)
		}
		if err != nil {
			res.OK, res.Error = false, err.Error()
			a.log.Warn("task failed", "task", t.ID, "type", t.Type, "error", err)
		}
	}
	if err := a.state.Record(t, res); err != nil {
		a.log.Error("record task result", "task", t.ID, "error", err)
	}
}

func (a *Agent) flushUnsent(ctx context.Context) error {
	ids, err := a.state.Unsent()
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := a.state.Result(id)
		if err != nil || r == nil {
			continue
		}
		path := strings.Replace(agentproto.PathResult, "{id}", url.PathEscape(id), 1)
		if err := a.do(ctx, http.MethodPost, path, r, nil); err != nil {
			if strings.Contains(err.Error(), ": 404 ") {
				_ = a.state.Acked(id) // the control plane no longer knows this task
				continue
			}
			return err
		}
		if err := a.state.Acked(id); err != nil {
			return err
		}
	}
	return nil
}

// Run loops until ctx is cancelled: heartbeat every 30s, identity rotation,
// long-poll for tasks, exponential backoff while the control plane is away.
func (a *Agent) Run(ctx context.Context) {
	backoff := time.Second
	lastHB := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastHB) > 30*time.Second {
			if err := a.Heartbeat(ctx); err != nil {
				a.log.Warn("heartbeat failed", "error", err)
			} else {
				lastHB = time.Now()
			}
			if err := a.RenewIdentityIfDue(ctx, time.Now()); err != nil {
				a.log.Warn("identity renewal failed", "error", err)
			}
			_ = a.state.PruneNonces(time.Now())
		}
		if _, err := a.PollOnce(ctx, 25*time.Second); err != nil {
			a.log.Warn("poll failed; will retry", "error", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
	}
}

// SetHandler replaces a task handler. Intended for tests that exercise the
// control-plane workflow without real ACME or web servers.
func (a *Agent) SetHandler(taskType string, h func(context.Context, *agentproto.Task) (any, error)) {
	a.handlers[taskType] = h
}

// Config returns the agent's configuration.
func (a *Agent) Config() *Config { return a.cfg }
