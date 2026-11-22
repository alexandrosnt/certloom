package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/plugin"
)

// runMaterial loads the run's private key and checks that the issued chain
// belongs to it and only names SANs the target allows.
func (a *Agent) runMaterial(tgt *TargetConfig, p agentproto.DeployPayload) ([]byte, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(filepath.Join(a.runDir(tgt.Name, p.RunID), "privkey.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("no private key for run %s on this host (was it issued by this agent?): %w", p.RunID, err)
	}
	pair, err := tls.X509KeyPair([]byte(p.ChainPEM), keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate does not match the run's private key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	for _, san := range leaf.DNSNames {
		if !agentproto.SANAllowed(san, tgt.AllowedSANs, true) { // wildcards only come from a DNS-01 issue step
			return nil, nil, fmt.Errorf("certificate SAN %q not allowed for target %s", san, tgt.Name)
		}
	}
	return keyPEM, leaf, nil
}

func (a *Agent) targetPlugin(tgt *TargetConfig) (*plugin.Plugin, error) {
	return a.cfg.pluginSource().open(tgt.Plugin, tgt.SHA256, plugin.KindDeployTarget, tgt.Env, tgt.TimeoutSeconds,
		&logWriter{log: a.log, solver: tgt.Name})
}

func (a *Agent) pluginRequest(tgt *TargetConfig, runID string) plugin.Request {
	return plugin.Request{Kind: plugin.KindDeployTarget, Config: tgt.PluginConfig, Target: tgt.Name, IdempotencyKey: runID}
}

// deployPlugin hands the new key and chain to the target's plugin. The files
// live in a private directory for the length of the call only. If the plugin
// fails, it is asked to roll back before the failure is reported.
func (a *Agent) deployPlugin(ctx context.Context, tgt *TargetConfig, p agentproto.DeployPayload) (any, error) {
	keyPEM, leaf, err := a.runMaterial(tgt, p)
	if err != nil {
		return nil, err
	}
	pl, err := a.targetPlugin(tgt)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(a.cfg.StateDir, "plugin-deploy-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := makeStateDir(dir); err != nil { // ACL on Windows; MkdirTemp is 0700 elsewhere
		return nil, err
	}
	leafPEM, chainPEM := splitChain(p.ChainPEM)
	files := &plugin.Files{
		Key:         filepath.Join(dir, "privkey.pem"),
		Certificate: filepath.Join(dir, "cert.pem"),
		Chain:       filepath.Join(dir, "chain.pem"),
		Fullchain:   filepath.Join(dir, "fullchain.pem"),
	}
	for path, data := range map[string][]byte{files.Key: keyPEM, files.Certificate: leafPEM, files.Chain: chainPEM, files.Fullchain: []byte(p.ChainPEM)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
	}
	req := a.pluginRequest(tgt, p.RunID)
	req.Files = files
	req.Names = leaf.DNSNames
	if _, err := pl.Call(ctx, plugin.ActionDeploy, req); err != nil {
		out := agentproto.DeployOutput{}
		if _, rerr := pl.Call(ctx, plugin.ActionRollback, a.pluginRequest(tgt, p.RunID)); rerr != nil {
			return out, fmt.Errorf("%w; ROLLBACK FAILED: %w", err, rerr)
		}
		out.RolledBack = true
		return out, err
	}
	return agentproto.DeployOutput{}, nil
}

// verifyPlugin asks the plugin what the target serves when the agent has no
// address of its own to handshake with.
func (a *Agent) verifyPlugin(ctx context.Context, tgt *TargetConfig, p agentproto.VerifyPayload) (any, error) {
	pl, err := a.targetPlugin(tgt)
	if err != nil {
		return nil, err
	}
	if p.RunID == "" {
		return nil, errors.New("verify of a plugin target needs a run id (control plane too old)")
	}
	var served string
	var lastErr error
	// Appliances may apply a change asynchronously, like web server reloads.
	for range 10 {
		served, lastErr = pluginServed(ctx, pl, a.pluginRequest(tgt, p.RunID))
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

func pluginServed(ctx context.Context, pl *plugin.Plugin, req plugin.Request) (string, error) {
	resp, err := pl.Call(ctx, plugin.ActionVerify, req)
	if err != nil {
		return "", err
	}
	b, _ := pem.Decode([]byte(resp.Certificate))
	if b == nil || b.Type != "CERTIFICATE" {
		return "", errors.New("plugin verify did not return a PEM certificate")
	}
	s := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(s[:]), nil
}

func (a *Agent) rollbackPlugin(ctx context.Context, tgt *TargetConfig, p agentproto.RollbackPayload) (any, error) {
	pl, err := a.targetPlugin(tgt)
	if err != nil {
		return nil, err
	}
	if _, err := pl.Call(ctx, plugin.ActionRollback, a.pluginRequest(tgt, p.RunID)); err != nil {
		return nil, err
	}
	return map[string]string{"restored": "by plugin"}, nil
}

// splitChain returns the leaf and the rest of a PEM chain.
func splitChain(chain string) ([]byte, []byte) {
	b, rest := pem.Decode([]byte(chain))
	if b == nil {
		return nil, nil
	}
	return pem.EncodeToMemory(b), rest
}
