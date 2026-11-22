package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"software.sslmate.com/src/go-pkcs12"
)

// Trust store limits: a trust store is a few hundred roots at most.
const (
	maxTrustAnchors   = 500
	maxTrustFileBytes = 4 << 20
)

// TrustStoreConfig declares a trust store the control plane may manage or
// observe (ADR-0030).
type TrustStoreConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // pem, pkcs12, debian, rhel, windows
	// Mode is manage (default) or observe; an observed store is never written.
	Mode string `json:"mode,omitempty"`
	// Path is the file for pem and pkcs12, and the directory certloom owns
	// for debian and rhel (defaults below).
	Path string `json:"path,omitempty"`
	// PasswordFile holds the PKCS#12 password; without it "changeit" is used,
	// the Java default.
	PasswordFile string `json:"password_file,omitempty"`
	// ReloadCommand runs after a pem or pkcs12 store changed.
	ReloadCommand []string `json:"reload_command,omitempty"`
	// UpdateCommand replaces update-ca-certificates / update-ca-trust.
	UpdateCommand []string `json:"update_command,omitempty"`
}

const (
	debianDefaultDir = "/usr/local/share/ca-certificates/certloom"
	rhelDefaultDir   = "/etc/pki/ca-trust/source/anchors"
	rhelSystemDir    = "/usr/share/pki/ca-trust-source/anchors"
	rhelPrefix       = "certloom-"
	windowsPrefix    = "certloom:"
)

func (s *TrustStoreConfig) mode() string {
	if s.Mode == "" {
		return agentproto.TrustManage
	}
	return s.Mode
}

func (s *TrustStoreConfig) dir() string {
	switch {
	case s.Path != "":
		return s.Path
	case s.Type == agentproto.TrustDebian:
		return debianDefaultDir
	case s.Type == agentproto.TrustRHEL:
		return rhelDefaultDir
	}
	return ""
}

func (s *TrustStoreConfig) command() []string {
	switch {
	case len(s.UpdateCommand) > 0:
		return s.UpdateCommand
	case s.Type == agentproto.TrustDebian:
		return []string{"update-ca-certificates"}
	case s.Type == agentproto.TrustRHEL:
		return []string{"update-ca-trust", "extract"}
	}
	return s.ReloadCommand
}

func (c *Config) validateTrustStores() []string {
	var p []string
	seen := map[string]bool{}
	for _, s := range c.TrustStores {
		switch {
		case s.Name == "" || strings.ContainsAny(s.Name, `/\. `):
			p = append(p, fmt.Sprintf("trust store name %q must be non-empty without / \\ . or spaces", s.Name))
		case seen[s.Name]:
			p = append(p, "duplicate trust store "+s.Name)
		case !slices.Contains(agentproto.TrustStoreTypes, s.Type):
			p = append(p, fmt.Sprintf("trust store %s: type must be one of %s", s.Name, strings.Join(agentproto.TrustStoreTypes, ", ")))
		case s.Mode != "" && s.Mode != agentproto.TrustManage && s.Mode != agentproto.TrustObserve:
			p = append(p, fmt.Sprintf("trust store %s: mode must be manage or observe", s.Name))
		case (s.Type == agentproto.TrustPEM || s.Type == agentproto.TrustPKCS12) && !filepath.IsAbs(s.Path):
			p = append(p, fmt.Sprintf("trust store %s: path must be an absolute file path", s.Name))
		case s.Path != "" && !filepath.IsAbs(s.Path):
			p = append(p, fmt.Sprintf("trust store %s: path must be absolute", s.Name))
		case s.Type == agentproto.TrustWindows && s.Path != "":
			p = append(p, fmt.Sprintf("trust store %s: windows stores have no path (LocalMachine\\Root)", s.Name))
		case s.PasswordFile != "" && s.Type != agentproto.TrustPKCS12:
			p = append(p, fmt.Sprintf("trust store %s: password_file is for pkcs12 stores", s.Name))
		}
		seen[s.Name] = true
	}
	return p
}

func (c *Config) trustStore(name string) (*TrustStoreConfig, bool) {
	for i := range c.TrustStores {
		if c.TrustStores[i].Name == name {
			return &c.TrustStores[i], true
		}
	}
	return nil, false
}

func (c *Config) trustStoreInfos() []agentproto.TrustStoreInfo {
	var out []agentproto.TrustStoreInfo
	for _, s := range c.TrustStores {
		out = append(out, agentproto.TrustStoreInfo{Name: s.Name, Type: s.Type, Mode: s.mode()})
	}
	return out
}

// trustBackend reads and writes one kind of store. write makes certloom's
// own entries equal certs and returns a function that restores them.
type trustBackend interface {
	read() ([]agentproto.TrustAnchor, error)
	write(certs []*x509.Certificate) (restore func() error, err error)
}

func (a *Agent) trustBackend(s *TrustStoreConfig) (trustBackend, error) {
	switch s.Type {
	case agentproto.TrustPEM:
		return &pemTrust{path: s.Path}, nil
	case agentproto.TrustPKCS12:
		pw := "changeit"
		if s.PasswordFile != "" {
			b, err := os.ReadFile(s.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("read password_file: %w", err)
			}
			pw = strings.TrimRight(string(b), "\r\n")
		}
		return &pkcs12Trust{path: s.Path, password: pw}, nil
	case agentproto.TrustDebian:
		dir := s.dir()
		return &dirTrust{own: dir, observe: []string{filepath.Dir(dir)}, name: func(c *x509.Certificate) string { return fingerprint(c) + ".crt" }}, nil
	case agentproto.TrustRHEL:
		dir := s.dir()
		obs := []string{dir}
		if dir == rhelDefaultDir {
			obs = append(obs, rhelSystemDir)
		}
		return &dirTrust{own: dir, observe: obs, prefix: rhelPrefix, name: func(c *x509.Certificate) string { return rhelPrefix + fingerprint(c) + ".pem" }}, nil
	case agentproto.TrustWindows:
		if a.winTrust == nil {
			return nil, errors.New("windows trust stores exist only on Windows")
		}
		return &windowsTrust{h: a.winTrust}, nil
	}
	return nil, fmt.Errorf("unknown trust store type %q", s.Type)
}

func fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

func anchorOf(c *x509.Certificate, owned bool) agentproto.TrustAnchor {
	return agentproto.TrustAnchor{SHA256: fingerprint(c), PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})), Owned: owned}
}

// handleTrustApply writes a bundle version to a managed store, runs its
// update or reload command and reports what the store holds afterwards.
// A failed command restores the previous content.
func (a *Agent) handleTrustApply(ctx context.Context, t *agentproto.Task) (any, error) {
	var p agentproto.TrustApplyPayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return nil, err
	}
	s, ok := a.cfg.trustStore(p.Store)
	if !ok {
		return nil, fmt.Errorf("unknown trust store %q", p.Store)
	}
	if s.mode() != agentproto.TrustManage {
		return nil, fmt.Errorf("trust store %s is observe-only on this host", s.Name)
	}
	if len(p.Anchors) > maxTrustAnchors {
		return nil, fmt.Errorf("bundle has %d anchors, more than %d", len(p.Anchors), maxTrustAnchors)
	}
	certs := make([]*x509.Certificate, 0, len(p.Anchors))
	for _, s := range p.Anchors {
		blk, rest := pem.Decode([]byte(s))
		if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) > 0 {
			return nil, errors.New("each anchor must be one PEM certificate")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		if !c.IsCA {
			return nil, fmt.Errorf("anchor %s is not a CA certificate", c.Subject)
		}
		certs = append(certs, c)
	}
	b, err := a.trustBackend(s)
	if err != nil {
		return nil, err
	}
	restore, err := b.write(certs)
	if err != nil {
		return nil, err
	}
	if cmd := s.command(); len(cmd) > 0 {
		if err := runCommand(ctx, cmd); err != nil {
			if rerr := restore(); rerr != nil {
				return nil, fmt.Errorf("%w; restoring the previous content failed: %v", err, rerr) //nolint:errorlint // only the first error is wrapped
			}
			_ = runCommand(ctx, cmd)
			return nil, fmt.Errorf("store restored: %w", err)
		}
	}
	return agentproto.TrustApplyOutput{Version: p.Version, Digest: p.Digest, State: a.trustState(s)}, nil
}

func (a *Agent) trustState(s *TrustStoreConfig) agentproto.TrustStoreState {
	st := agentproto.TrustStoreState{Name: s.Name, Type: s.Type, Mode: s.mode(), Anchors: []agentproto.TrustAnchor{}}
	b, err := a.trustBackend(s)
	if err == nil {
		var anchors []agentproto.TrustAnchor
		if anchors, err = b.read(); err == nil {
			st.Anchors = anchors
		}
	}
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

func (a *Agent) inventoryTrust() []agentproto.TrustStoreState {
	var out []agentproto.TrustStoreState
	for i := range a.cfg.TrustStores {
		out = append(out, a.trustState(&a.cfg.TrustStores[i]))
	}
	return out
}

// parsePEMCerts returns the certificates in b, skipping other blocks.
func parsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

func readSmall(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxTrustFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxTrustFileBytes)
	}
	return os.ReadFile(path)
}

// restoreFile puts back the previous content of path, or removes it if it
// did not exist.
func restoreFile(path string, old []byte, existed bool) func() error {
	return func() error {
		if !existed {
			return os.Remove(path)
		}
		return writeAtomic(path, old, 0o644)
	}
}

func snapshotFile(path string) ([]byte, bool, error) {
	old, err := readSmall(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return old, err == nil, err
}

// pemTrust is a PEM bundle file certloom owns entirely.
type pemTrust struct{ path string }

func (p *pemTrust) read() ([]agentproto.TrustAnchor, error) {
	b, err := readSmall(p.path)
	if err != nil {
		return nil, err
	}
	certs, err := parsePEMCerts(b)
	if err != nil {
		return nil, err
	}
	out := make([]agentproto.TrustAnchor, 0, len(certs))
	for _, c := range certs {
		out = append(out, anchorOf(c, true))
	}
	return out, nil
}

func (p *pemTrust) write(certs []*x509.Certificate) (func() error, error) {
	old, existed, err := snapshotFile(p.path)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, c := range certs {
		fmt.Fprintf(&b, "# %s\n", c.Subject)
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	if err := writeAtomic(p.path, b.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return restoreFile(p.path, old, existed), nil
}

// pkcs12Trust is a Java-compatible trust-only PKCS#12 file.
type pkcs12Trust struct{ path, password string }

func (p *pkcs12Trust) read() ([]agentproto.TrustAnchor, error) {
	b, err := readSmall(p.path)
	if err != nil {
		return nil, err
	}
	certs, err := pkcs12.DecodeTrustStore(b, p.password)
	if err != nil {
		return nil, err
	}
	out := make([]agentproto.TrustAnchor, 0, len(certs))
	for _, c := range certs {
		out = append(out, anchorOf(c, true))
	}
	return out, nil
}

func (p *pkcs12Trust) write(certs []*x509.Certificate) (func() error, error) {
	old, existed, err := snapshotFile(p.path)
	if err != nil {
		return nil, err
	}
	// Modern2023 (PBES2/AES, HMAC-SHA-256) is read by Java 8u301 and later.
	b, err := pkcs12.Modern2023.WithRand(rand.Reader).EncodeTrustStore(certs, p.password)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(p.path, b, 0o644); err != nil {
		return nil, err
	}
	return restoreFile(p.path, old, existed), nil
}

// dirTrust is an OS anchors directory: certloom owns one directory (or the
// files with a prefix in it) and reports the other local anchors as well.
type dirTrust struct {
	own     string
	prefix  string // owned files in a shared directory (rhel)
	observe []string
	name    func(*x509.Certificate) string
}

func (d *dirTrust) owned(path string) bool {
	if d.prefix != "" {
		return filepath.Dir(path) == d.own && strings.HasPrefix(filepath.Base(path), d.prefix)
	}
	rel, err := filepath.Rel(d.own, path)
	return err == nil && !strings.HasPrefix(rel, "..")
}

func (d *dirTrust) read() ([]agentproto.TrustAnchor, error) {
	var out []agentproto.TrustAnchor
	seen := map[string]bool{}
	for _, root := range d.observe {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if e.IsDir() || len(out) >= maxTrustAnchors {
				return nil
			}
			b, err := readSmall(path)
			if err != nil {
				return nil //nolint:nilerr // unreadable files are skipped, not fatal
			}
			certs, err := parsePEMCerts(b)
			if err != nil || len(certs) == 0 {
				if c, derr := x509.ParseCertificate(b); derr == nil {
					certs = []*x509.Certificate{c}
				}
			}
			for _, c := range certs {
				a := anchorOf(c, d.owned(path))
				if !seen[a.SHA256] {
					seen[a.SHA256] = true
					out = append(out, a)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *dirTrust) ownedFiles() (map[string][]byte, error) {
	out := map[string][]byte{}
	entries, err := os.ReadDir(d.own)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		p := filepath.Join(d.own, e.Name())
		if e.IsDir() || !d.owned(p) {
			continue
		}
		b, err := readSmall(p)
		if err != nil {
			return nil, err
		}
		out[p] = b
	}
	return out, nil
}

func (d *dirTrust) write(certs []*x509.Certificate) (func() error, error) {
	if err := os.MkdirAll(d.own, 0o755); err != nil { //nolint:gosec // anchors are public; OS anchor directories are world-readable by convention
		return nil, err
	}
	before, err := d.ownedFiles()
	if err != nil {
		return nil, err
	}
	restore := func() error {
		now, err := d.ownedFiles()
		if err != nil {
			return err
		}
		for p := range now {
			if _, ok := before[p]; !ok {
				if err := os.Remove(p); err != nil {
					return err
				}
			}
		}
		for p, b := range before {
			if err := writeAtomic(p, b, 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	want := map[string][]byte{}
	for _, c := range certs {
		want[filepath.Join(d.own, d.name(c))] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	for p, b := range want {
		if bytes.Equal(before[p], b) {
			continue
		}
		if err := writeAtomic(p, b, 0o644); err != nil {
			_ = restore()
			return nil, err
		}
	}
	for p := range before {
		if _, ok := want[p]; !ok {
			if err := os.Remove(p); err != nil {
				_ = restore()
				return nil, err
			}
		}
	}
	return restore, nil
}

// winTrustHost is the Windows root store, behind an interface for tests.
type winTrustHost interface {
	// List returns every certificate in LocalMachine\Root with its friendly name.
	List() ([]winTrustCert, error)
	Add(c *x509.Certificate, friendlyName string) error
	Remove(der []byte) error
}

type winTrustCert struct {
	DER          []byte
	FriendlyName string
}

type windowsTrust struct{ h winTrustHost }

func (w *windowsTrust) read() ([]agentproto.TrustAnchor, error) {
	all, err := w.h.List()
	if err != nil {
		return nil, err
	}
	out := make([]agentproto.TrustAnchor, 0, len(all))
	for _, e := range all {
		c, err := x509.ParseCertificate(e.DER)
		if err != nil {
			continue
		}
		out = append(out, anchorOf(c, strings.HasPrefix(e.FriendlyName, windowsPrefix)))
	}
	return out, nil
}

func (w *windowsTrust) write(certs []*x509.Certificate) (func() error, error) {
	all, err := w.h.List()
	if err != nil {
		return nil, err
	}
	owned := map[string]winTrustCert{}
	present := map[string]bool{}
	for _, e := range all {
		h := sha256.Sum256(e.DER)
		k := hex.EncodeToString(h[:])
		present[k] = true
		if strings.HasPrefix(e.FriendlyName, windowsPrefix) {
			owned[k] = e
		}
	}
	want := map[string]*x509.Certificate{}
	for _, c := range certs {
		want[fingerprint(c)] = c
	}
	var added []*x509.Certificate
	var removed []winTrustCert
	restore := func() error {
		for _, c := range added {
			if err := w.h.Remove(c.Raw); err != nil {
				return err
			}
		}
		for _, e := range removed {
			c, err := x509.ParseCertificate(e.DER)
			if err != nil {
				return err
			}
			if err := w.h.Add(c, e.FriendlyName); err != nil {
				return err
			}
		}
		return nil
	}
	for k, c := range want {
		if _, ok := owned[k]; ok {
			continue
		}
		// A root the administrator added is left alone; certloom labels only
		// what it adds itself, so it never removes theirs later.
		if present[k] {
			continue
		}
		if err := w.h.Add(c, windowsPrefix+c.Subject.CommonName); err != nil {
			_ = restore()
			return nil, err
		}
		added = append(added, c)
	}
	for k, e := range owned {
		if _, ok := want[k]; ok {
			continue
		}
		if err := w.h.Remove(e.DER); err != nil {
			_ = restore()
			return nil, err
		}
		removed = append(removed, e)
	}
	return restore, nil
}
