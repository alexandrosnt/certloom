package agent

import (
	"os"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// TestOSTrustStore runs inside a disposable Debian or RHEL-family container
// (test/acme/truststore_test.go) with the real update command, and checks
// that the anchor reaches the system bundle and leaves it again.
func TestOSTrustStore(t *testing.T) {
	typ := os.Getenv("CERTLOOM_OS_TRUST_E2E")
	bundle := map[string]string{agentproto.TrustDebian: "/etc/ssl/certs/ca-certificates.crt",
		agentproto.TrustRHEL: "/etc/pki/tls/certs/ca-bundle.crt"}[typ]
	if bundle == "" {
		t.Skip("runs in a container with CERTLOOM_OS_TRUST_E2E=debian or rhel")
	}
	root := testpki.Issue(t, nil, testpki.Options{CommonName: "certloom os trust root", IsCA: true})
	inSystem := func() bool {
		b, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		pem := strings.TrimSpace(string(root.PEM()))
		return strings.Contains(strings.ReplaceAll(string(b), "\r", ""), pem)
	}
	a := trustAgent(TrustStoreConfig{Name: "os", Type: typ})
	if _, err := applyTrust(t, a, "os", 1, root); err != nil {
		t.Fatal(err)
	}
	if !inSystem() {
		t.Fatalf("anchor not in %s after the update command", bundle)
	}
	st := a.trustState(&a.cfg.TrustStores[0])
	if st.Error != "" || len(anchorSet(st, true)) != 1 {
		t.Fatalf("state: %+v", st)
	}
	if _, err := applyTrust(t, a, "os", 2); err != nil {
		t.Fatal(err)
	}
	if inSystem() {
		t.Fatalf("anchor still in %s after removal", bundle)
	}
}
