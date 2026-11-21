package agent

import (
	"context"
	"crypto/sha1" //nolint:gosec // Windows thumbprints are SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/winapi"
)

// TestIISEndToEnd drives a real IIS site and HTTP.sys with machine CNG keys.
// It needs an elevated process on a host with IIS (the Windows CI job):
//
//	CERTLOOM_IIS_E2E=1 go test ./internal/agent/ -run TestIISEndToEnd
func TestIISEndToEnd(t *testing.T) {
	if os.Getenv("CERTLOOM_IIS_E2E") != "1" {
		t.Skip("set CERTLOOM_IIS_E2E=1 on an elevated Windows host with IIS")
	}
	ctx := context.Background()
	appcmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "appcmd.exe")
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	// Under inetpub the site inherits an ACL IIS can read.
	root := filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", "certloom-e2e")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	const site, host, binding = "certloom-e2e", "shop.e2e.test", "*:44300:shop.e2e.test"
	run(appcmd, "add", "site", "/name:"+site, "/bindings:https/"+binding+",http/*:48080:", "/physicalPath:"+root)
	t.Cleanup(func() {
		_ = exec.Command(appcmd, "delete", "site", site).Run()
		_ = exec.Command("netsh", "http", "delete", "sslcert", "hostnameport="+host+":44300").Run()
		_ = os.RemoveAll(root)
	})
	run(appcmd, "set", "site", "/site.name:"+site, "/bindings.[protocol='https',bindingInformation='"+binding+"'].sslFlags:1")

	st, err := OpenState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tgt := TargetConfig{Name: "e2e", Type: agentproto.TargetIIS, Site: site, Bindings: []string{binding}, AllowedSANs: []string{host}, Webroot: root}
	a := &Agent{cfg: &Config{StateDir: t.TempDir(), Targets: []TargetConfig{tgt}}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: st, win: newWinHost()}
	tp := &a.cfg.Targets[0]
	t.Cleanup(func() {
		own, _ := a.win.OwnCerts(iisFriendlyPrefix("e2e"))
		for _, c := range own {
			_ = a.win.RemoveCert(c.Store, c.Thumb)
		}
		for _, r := range []string{"run1", "run2"} {
			_ = a.win.DeleteKey(iisKeyName("e2e", r))
		}
	})

	issue := func(runID string) *x509.Certificate {
		t.Helper()
		key, err := a.runKey(tp, runID, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := key.(*winapi.Key); !ok {
			t.Fatalf("iis key is %T, want a CNG key", key)
		}
		return selfSigned(t, key, host)
	}
	deploy := func(runID string, leaf *x509.Certificate) agentproto.DeployOutput {
		t.Helper()
		res, err := a.deployIIS(ctx, tp, agentproto.DeployPayload{RunID: runID, ChainPEM: chainPEM(leaf)})
		if err != nil {
			t.Fatalf("deploy %s: %v", runID, err)
		}
		return res.(agentproto.DeployOutput)
	}
	served := func(leaf *x509.Certificate) bool {
		t.Helper()
		sum := sha256.Sum256(leaf.Raw)
		res, err := a.verifyIIS(ctx, tp, agentproto.VerifyPayload{ExpectedSHA256: hex.EncodeToString(sum[:])})
		if err != nil {
			t.Fatal(err)
		}
		return res.(agentproto.VerifyOutput).Match
	}

	leaf1 := issue("run1")
	deploy("run1", leaf1)
	if !served(leaf1) {
		t.Fatal("IIS does not serve the run1 certificate")
	}
	leaf2 := issue("run2")
	if out := deploy("run2", leaf2); out.Previous != "run1" {
		t.Fatalf("previous = %q", out.Previous)
	}
	if !served(leaf2) {
		t.Fatal("IIS does not serve the run2 certificate")
	}

	// Someone points the binding back at the old certificate by hand.
	sum2 := sha256.Sum256(leaf2.Raw)
	th1 := strings.ToUpper(hex.EncodeToString(sha1Thumb(leaf1)))
	run("netsh", "http", "update", "sslcert", "hostnameport="+host+":44300", "certhash="+th1,
		"certstorename=WebHosting", "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}")
	bindings, err := a.inventoryIIS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var obs []checks.ObservedBinding
	for _, b := range bindings {
		if b.Site == site {
			obs = append(obs, checks.ObservedBinding{Binding: b.Binding, InSite: true, CertHash: b.CertHash, CertSHA256: b.CertSHA256})
		}
	}
	if fs := checks.IISBindingDrift(hex.EncodeToString(sum2[:]), obs); len(fs) != 1 {
		t.Fatalf("manual rebinding not detected as drift: %+v", obs)
	}

	// Rollback of run2 restores what was bound before it: run1.
	run("netsh", "http", "update", "sslcert", "hostnameport="+host+":44300", "certhash="+strings.ToUpper(hex.EncodeToString(sha1Thumb(leaf2))),
		"certstorename=WebHosting", "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}")
	if _, err := a.rollbackIIS(ctx, tp, agentproto.RollbackPayload{RunID: "run2"}); err != nil {
		t.Fatal(err)
	}
	if !served(leaf1) {
		t.Fatal("rollback did not restore run1")
	}

	// HTTP-01: IIS serves the extensionless challenge file as text.
	if err := writeChallengeWebConfig(root); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(root, ".well-known", "acme-challenge", "tok-123")
	if err := os.WriteFile(tok, []byte("tok-123.thumb"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://127.0.0.1:48080/.well-known/acme-challenge/tok-123")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "tok-123.thumb" {
		t.Fatalf("challenge file: %d %q", resp.StatusCode, body)
	}
}

func sha1Thumb(c *x509.Certificate) []byte {
	s := sha1.Sum(c.Raw) //nolint:gosec // Windows thumbprints are SHA-1
	return s[:]
}
