package agent

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/winapi"
	"golang.org/x/sys/windows"
)

type windowsHost struct {
	scope  winapi.Scope
	appcmd string
}

func newWinHost() winHost {
	return &windowsHost{scope: winapi.ScopeMachine,
		appcmd: filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "appcmd.exe")}
}

func (w *windowsHost) Key(name string, create bool) (crypto.Signer, error) {
	k, err := winapi.OpenKey(name, w.scope)
	if errors.Is(err, winapi.ErrKeyNotFound) && create {
		return winapi.CreateKey(name, w.scope)
	}
	return k, err
}

func (w *windowsHost) DeleteKey(name string) error { return winapi.DeleteKey(name, w.scope) }

func (w *windowsHost) AddCert(chain []*x509.Certificate, keyName, friendlyName string) ([]byte, string, error) {
	store := winapi.LeafStore(w.scope)
	thumb, err := winapi.AddCert(store, w.scope, chain, keyName, friendlyName)
	return thumb, store, err
}

func (w *windowsHost) OwnCerts(prefix string) ([]storedCert, error) {
	list, err := winapi.OwnCerts(winapi.LeafStore(w.scope), w.scope, prefix)
	out := make([]storedCert, 0, len(list))
	for _, c := range list {
		out = append(out, storedCert(c))
	}
	return out, err
}

func (w *windowsHost) RemoveCert(store string, thumb []byte) error {
	return winapi.RemoveCert(store, w.scope, thumb)
}

func (w *windowsHost) Cert(store string, thumb []byte) ([]byte, error) {
	return winapi.Cert(store, w.scope, thumb)
}

// Sites reads the IIS configuration through appcmd. No IIS means no sites.
func (w *windowsHost) Sites(ctx context.Context) ([]iisSite, error) {
	if _, err := os.Stat(w.appcmd); err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, w.appcmd, "list", "site", "/config", "/xml").Output() //nolint:gosec // fixed system path
	if err != nil {
		return nil, fmt.Errorf("appcmd list site: %w", err)
	}
	return appcmdSites(out)
}

func toWin(k sslKey) winapi.SSLBinding {
	return winapi.SSLBinding{IP: k.IP, Port: k.Port, Host: k.Host}
}

func (w *windowsHost) SSLCert(k sslKey) (sslEntry, bool, error) {
	c, ok, err := winapi.GetSSLCert(toWin(k))
	return sslEntry{Hash: c.Hash, Store: c.Store}, ok, err
}

func (w *windowsHost) SetSSLCert(k sslKey, e sslEntry) error {
	return winapi.SetSSLCert(toWin(k), winapi.SSLCert{Hash: e.Hash, Store: e.Store})
}

// makeStateDir creates the state directory readable only by SYSTEM and
// Administrators (and the owner, for tests and manual runs); the default ACL
// under ProgramData lets every user read.
func makeStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
