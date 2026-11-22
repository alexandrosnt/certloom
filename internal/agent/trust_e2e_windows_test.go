package agent

import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// TestWindowsRootStore adds a root to LocalMachine\Root through trust.apply,
// checks that Windows chain building now trusts a leaf under it, and removes
// it again. It changes the machine's trust, so it only runs where the IIS
// end-to-end test runs (elevated CI runner).
func TestWindowsRootStore(t *testing.T) {
	if os.Getenv("CERTLOOM_IIS_E2E") != "1" {
		t.Skip("set CERTLOOM_IIS_E2E=1 on an elevated, disposable Windows host")
	}
	root := testpki.Issue(t, nil, testpki.Options{CommonName: "certloom e2e root", IsCA: true})
	leaf := testpki.Issue(t, root, testpki.Options{CommonName: "trust.e2e.test", DNSNames: []string{"trust.e2e.test"}})
	verify := func() error {
		_, err := leaf.Cert.Verify(x509.VerifyOptions{DNSName: "trust.e2e.test", CurrentTime: time.Now()})
		return err
	}
	if verify() == nil {
		t.Fatal("leaf verified before the root was installed")
	}
	a := trustAgent(TrustStoreConfig{Name: "win", Type: agentproto.TrustWindows})
	a.winTrust = newWinTrust()
	t.Cleanup(func() { _, _ = applyTrust(t, a, "win", 99) })

	out, err := applyTrust(t, a, "win", 1, root)
	if err != nil {
		t.Fatal(err)
	}
	owned := anchorSet(out.State, true)
	if len(owned) != 1 || owned[0] != hashes(root)[0] {
		t.Fatalf("owned after apply: %v", owned)
	}
	if err := verify(); err != nil {
		t.Fatalf("Windows does not trust the installed root: %v", err)
	}
	if _, err := applyTrust(t, a, "win", 2); err != nil {
		t.Fatal(err)
	}
	if st := a.trustState(&a.cfg.TrustStores[0]); len(anchorSet(st, true)) != 0 {
		t.Fatalf("root left behind: %v", anchorSet(st, true))
	}
}
