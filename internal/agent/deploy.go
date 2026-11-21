package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// switchLink atomically points link at dest (symlink + rename). An empty
// dest removes the link. The link must not be a regular directory: certloom-agent
// only manages a symlink it owns.
func switchLink(link, dest string) error {
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s exists and is not a symlink; certloom-agent manages it as a symlink (move the existing files away first)", link)
	}
	if dest == "" {
		err := os.Remove(link)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	// The web server (another user) must be able to traverse to the live link.
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil { //nolint:gosec // see above
		return err
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tmp := link + ".certloom-tmp-" + hex.EncodeToString(b)
	if err := os.Symlink(dest, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func readLink(link string) (string, error) {
	d, err := os.Readlink(link)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return d, err
}

// runCommand executes a locally configured command with a timeout and
// returns trimmed output for diagnostics.
func runCommand(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv comes from the local agent config only
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		o := out.String()
		if len(o) > 2000 {
			o = o[:2000] + "..."
		}
		return fmt.Errorf("%v: %w: %s", argv, err, bytes.TrimSpace([]byte(o)))
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// handleDeploy activates a run's certificate: write the chain next to the
// run's key, check they match, switch the live symlink atomically, run the
// target's config test and reload. On any failure after switching, it
// restores the previous link (and reloads) before reporting RolledBack.
func (a *Agent) handleDeploy(ctx context.Context, t *agentproto.Task) (any, error) {
	tgt, ok := a.cfg.target(t.Target)
	if !ok {
		return nil, fmt.Errorf("unknown target %q", t.Target)
	}
	var p agentproto.DeployPayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil, err
	}
	if tgt.Type == agentproto.TargetIIS {
		return a.deployIIS(ctx, tgt, p)
	}
	dir := a.runDir(tgt.Name, p.RunID)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return nil, fmt.Errorf("no private key for run %s on this host (was it issued by this agent?): %w", p.RunID, err)
	}
	pair, err := tls.X509KeyPair([]byte(p.ChainPEM), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate does not match the run's private key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	for _, san := range leaf.DNSNames {
		if !agentproto.SANAllowed(san, tgt.AllowedSANs, true) { // wildcards only come from a DNS-01 issue step
			return nil, fmt.Errorf("certificate SAN %q not allowed for target %s", san, tgt.Name)
		}
	}
	if err := writeAtomic(filepath.Join(dir, "fullchain.pem"), []byte(p.ChainPEM), 0o644); err != nil {
		return nil, err
	}
	prev, err := a.state.Previous(tgt.Name, p.RunID, func() (string, error) { return readLink(tgt.LiveLink) })
	if err != nil {
		return nil, err
	}
	out := agentproto.DeployOutput{Previous: filepath.Base(prev)}
	if prev == "" {
		out.Previous = ""
	}
	if err := switchLink(tgt.LiveLink, dir); err != nil {
		return out, err
	}
	// restore puts the previous link back. If the server was never reloaded
	// (config test failed), it is still running with the previous files, so
	// restoring the link is a complete rollback and no reload is needed (a
	// reload could fail for the same unrelated reason the test did). If the
	// reload step itself failed, reload once more after restoring and claim a
	// clean rollback only if that succeeds; otherwise escalate.
	restore := func(cause error, reloaded bool) (any, error) {
		if err := switchLink(tgt.LiveLink, prev); err != nil {
			return out, fmt.Errorf("%w; RESTORE FAILED: %w", cause, err)
		}
		if reloaded && prev != "" {
			if err := runCommand(ctx, tgt.ReloadCommand); err != nil {
				return out, fmt.Errorf("%w; restored previous certificate files but reload failed: %w", cause, err)
			}
		}
		out.RolledBack = true
		return out, cause
	}
	if err := runCommand(ctx, tgt.TestCommand); err != nil {
		return restore(fmt.Errorf("config test failed with new certificate: %w", err), false)
	}
	if err := runCommand(ctx, tgt.ReloadCommand); err != nil {
		return restore(fmt.Errorf("reload failed: %w", err), true)
	}
	return out, nil
}

// handleVerify handshakes with the local endpoint and compares fingerprints.
func (a *Agent) handleVerify(ctx context.Context, t *agentproto.Task) (any, error) {
	tgt, ok := a.cfg.target(t.Target)
	if !ok {
		return nil, fmt.Errorf("unknown target %q", t.Target)
	}
	var p agentproto.VerifyPayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil, err
	}
	if tgt.Type == agentproto.TargetIIS {
		return a.verifyIIS(ctx, tgt, p)
	}
	var served string
	var lastErr error
	// Reloads are asynchronous: give old workers a few seconds to drain.
	for range 10 {
		served, lastErr = servedFingerprint(ctx, tgt.VerifyAddress, p.SNI)
		if lastErr == nil && served == p.ExpectedSHA256 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return agentproto.VerifyOutput{ServedSHA256: served, Match: served == p.ExpectedSHA256}, nil
}

func servedFingerprint(ctx context.Context, addr, sni string) (string, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}} //nolint:gosec // fingerprint comparison, not trust
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate served")
	}
	s := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(s[:]), nil
}

// handleRollback restores the link recorded before the run's deploy.
func (a *Agent) handleRollback(ctx context.Context, t *agentproto.Task) (any, error) {
	tgt, ok := a.cfg.target(t.Target)
	if !ok {
		return nil, fmt.Errorf("unknown target %q", t.Target)
	}
	var p agentproto.RollbackPayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil, err
	}
	if tgt.Type == agentproto.TargetIIS {
		return a.rollbackIIS(ctx, tgt, p)
	}
	prev, ok := a.state.LookupPrevious(tgt.Name, p.RunID)
	if !ok {
		// Deploy never switched anything on this host: nothing to undo.
		return map[string]string{"note": "no deploy recorded for this run; nothing to roll back"}, nil
	}
	if prev == "" {
		return nil, errors.New("no previous certificate existed before this run; refusing to remove the live certificate")
	}
	if err := switchLink(tgt.LiveLink, prev); err != nil {
		return nil, err
	}
	if err := runCommand(ctx, tgt.TestCommand); err != nil {
		return nil, fmt.Errorf("config test failed after restoring previous certificate: %w", err)
	}
	if err := runCommand(ctx, tgt.ReloadCommand); err != nil {
		return nil, fmt.Errorf("reload failed after restoring previous certificate: %w", err)
	}
	return map[string]string{"restored": filepath.Base(prev)}, nil
}
