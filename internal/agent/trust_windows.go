package agent

import (
	"crypto/sha1" //nolint:gosec // the Windows store indexes certificates by SHA-1 thumbprint
	"crypto/x509"

	"github.com/alexandrosnt/certloom/internal/winapi"
)

// machineRoot is LocalMachine\Root, the store Windows trusts for every user.
type machineRoot struct{ store string }

func newWinTrust() winTrustHost { return machineRoot{store: "Root"} }

func (m machineRoot) List() ([]winTrustCert, error) {
	all, err := winapi.ListCerts(m.store, winapi.ScopeMachine)
	if err != nil {
		return nil, err
	}
	out := make([]winTrustCert, 0, len(all))
	for _, c := range all {
		out = append(out, winTrustCert{DER: c.DER, FriendlyName: c.FriendlyName})
	}
	return out, nil
}

func (m machineRoot) Add(c *x509.Certificate, friendlyName string) error {
	return winapi.AddTrusted(m.store, winapi.ScopeMachine, c, friendlyName)
}

func (m machineRoot) Remove(der []byte) error {
	thumb := sha1.Sum(der) //nolint:gosec // thumbprint lookup, not a security decision
	return winapi.RemoveCert(m.store, winapi.ScopeMachine, thumb[:])
}
