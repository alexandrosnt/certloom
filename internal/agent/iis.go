package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// IIS site binding flags (applicationHost.config sslFlags).
const (
	sslFlagSNI = 1
	sslFlagCCS = 2
)

// winHost is what iis targets need from Windows: CNG keys, the system
// certificate stores, HTTP.sys and the IIS configuration. The real one is in
// iis_windows.go; tests use a fake.
type winHost interface {
	// Key opens the named machine key. With create set, a missing key is
	// created non-exportable.
	Key(name string, create bool) (crypto.Signer, error)
	DeleteKey(name string) error
	// AddCert stores the leaf, linked to keyName and labelled friendlyName,
	// and its intermediates. It returns the leaf's SHA-1 thumbprint and store.
	AddCert(chain []*x509.Certificate, keyName, friendlyName string) (thumb []byte, store string, err error)
	// OwnCerts lists certificates whose friendly name starts with prefix.
	OwnCerts(prefix string) ([]storedCert, error)
	RemoveCert(store string, thumb []byte) error
	// Cert returns a stored certificate (DER), or nil if it is not there.
	Cert(store string, thumb []byte) ([]byte, error)
	Sites(ctx context.Context) ([]iisSite, error)
	// SSLCert reads the HTTP.sys entry for k; ok is false when there is none.
	SSLCert(k sslKey) (e sslEntry, ok bool, err error)
	// SetSSLCert points the entry for k at e's certificate, keeping every other
	// setting of an existing entry.
	SetSSLCert(k sslKey, e sslEntry) error
}

type storedCert struct {
	Store, FriendlyName string
	Thumb               []byte
}

type iisSite struct {
	Name         string
	PhysicalPath string
	Bindings     []iisBinding
}

type iisBinding struct {
	Protocol string
	Info     string // ip:port:host
	SSLFlags int
}

// sslKey addresses an HTTP.sys certificate entry: host:port with SNI,
// otherwise ip:port.
type sslKey struct {
	IP   string
	Port int
	Host string
}

func (k sslKey) String() string {
	if k.Host != "" {
		return net.JoinHostPort(k.Host, strconv.Itoa(k.Port))
	}
	return net.JoinHostPort(k.IP, strconv.Itoa(k.Port))
}

type sslEntry struct {
	Hash  []byte // SHA-1 thumbprint
	Store string
}

// parseBinding splits "ip:port:host". ip is "*", an IPv4 address or a
// bracketed IPv6 address; host may be empty.
func parseBinding(s string) (ip string, port int, host string, err error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, "", fmt.Errorf("binding %q: want ip:port:host", s)
	}
	host = strings.ToLower(s[i+1:])
	rest := s[:i]
	j := strings.LastIndex(rest, ":")
	if j < 0 {
		return "", 0, "", fmt.Errorf("binding %q: want ip:port:host", s)
	}
	ip = strings.Trim(rest[:j], "[]")
	port, err = strconv.Atoi(rest[j+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("binding %q: bad port", s)
	}
	if ip != "*" && net.ParseIP(ip) == nil {
		return "", 0, "", fmt.Errorf("binding %q: bad ip %q", s, ip)
	}
	return ip, port, host, nil
}

// bindingSSLKey returns the HTTP.sys entry IIS uses for a site binding.
func bindingSSLKey(b iisBinding) (sslKey, error) {
	ip, port, host, err := parseBinding(b.Info)
	if err != nil {
		return sslKey{}, err
	}
	if b.SSLFlags&sslFlagCCS != 0 {
		return sslKey{}, fmt.Errorf("binding %s uses the Central Certificate Store, which certloom does not manage", b.Info)
	}
	if b.SSLFlags&sslFlagSNI != 0 {
		if host == "" {
			return sslKey{}, fmt.Errorf("binding %s has SNI set but no host name", b.Info)
		}
		return sslKey{Host: host, Port: port}, nil
	}
	if ip == "*" {
		ip = "0.0.0.0"
	}
	return sslKey{IP: ip, Port: port}, nil
}

func (t TargetConfig) validateIIS() []string {
	var p []string
	switch {
	case t.Site == "":
		p = append(p, fmt.Sprintf("target %s: site is required for iis", t.Name))
	case len(t.Bindings) == 0:
		p = append(p, fmt.Sprintf("target %s: bindings must list the https bindings to manage (ip:port:host)", t.Name))
	case len(t.AllowedSANs) == 0:
		p = append(p, fmt.Sprintf("target %s: allowed_sans must list the names this host may obtain certificates for", t.Name))
	case t.LiveLink != "" || len(t.TestCommand) > 0 || len(t.ReloadCommand) > 0:
		p = append(p, fmt.Sprintf("target %s: live_link, test_command and reload_command do not apply to iis", t.Name))
	}
	for _, b := range t.Bindings {
		if _, _, _, err := parseBinding(b); err != nil {
			p = append(p, fmt.Sprintf("target %s: %v", t.Name, err))
		}
	}
	return p
}

// iisKeyName names the CNG key of one run.
func iisKeyName(target, run string) string { return "certloom-" + target + "-" + run }

func iisFriendlyPrefix(target string) string { return "certloom:" + target + ":" }

// appcmdSites parses `appcmd list site /config /xml`.
func appcmdSites(b []byte) ([]iisSite, error) {
	var doc struct {
		Sites []struct {
			Site struct {
				Name     string `xml:"name,attr"`
				Bindings []struct {
					Protocol string `xml:"protocol,attr"`
					Info     string `xml:"bindingInformation,attr"`
					SSLFlags string `xml:"sslFlags,attr"`
				} `xml:"bindings>binding"`
				Apps []struct {
					Path string `xml:"path,attr"`
					VDir []struct {
						Path         string `xml:"path,attr"`
						PhysicalPath string `xml:"physicalPath,attr"`
					} `xml:"virtualDirectory"`
				} `xml:"application"`
			} `xml:"site"`
		} `xml:"SITE"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("appcmd output: %w", err)
	}
	var out []iisSite
	for _, s := range doc.Sites {
		site := iisSite{Name: s.Site.Name}
		for _, a := range s.Site.Apps {
			for _, v := range a.VDir {
				if a.Path == "/" && v.Path == "/" {
					site.PhysicalPath = os.ExpandEnv(strings.ReplaceAll(v.PhysicalPath, "%SystemDrive%", os.Getenv("SystemDrive")))
				}
			}
		}
		for _, b := range s.Site.Bindings {
			f, _ := strconv.Atoi(b.SSLFlags)
			site.Bindings = append(site.Bindings, iisBinding{Protocol: strings.ToLower(b.Protocol), Info: b.Info, SSLFlags: f})
		}
		out = append(out, site)
	}
	return out, nil
}

// challengeWebConfig lets IIS serve the extensionless HTTP-01 files as text
// and keeps other handlers and rewrite rules out of that directory.
const challengeWebConfig = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <clear />
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <clear />
      <add name="StaticFile" path="*" verb="*" modules="StaticFileModule" resourceType="Either" requireAccess="Read" />
    </handlers>
  </system.webServer>
</configuration>
`

func writeChallengeWebConfig(webroot string) error {
	dir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // served by the web server
		return err
	}
	return writeAtomic(filepath.Join(dir, "web.config"), []byte(challengeWebConfig), 0o644) //nolint:gosec // served by the web server
}

// iisPrevious is what a deploy replaced, per configured binding.
type iisPrevious map[string]sslEntry

func (a *Agent) iisTargetBindings(ctx context.Context, tgt *TargetConfig) (map[string]sslKey, error) {
	if a.win == nil {
		return nil, errors.New("iis targets need Windows")
	}
	sites, err := a.win.Sites(ctx)
	if err != nil {
		return nil, err
	}
	var site *iisSite
	for i := range sites {
		if strings.EqualFold(sites[i].Name, tgt.Site) {
			site = &sites[i]
		}
	}
	if site == nil {
		return nil, fmt.Errorf("IIS has no site named %q", tgt.Site)
	}
	keys := map[string]sslKey{}
	for _, want := range tgt.Bindings {
		var found *iisBinding
		for i := range site.Bindings {
			if site.Bindings[i].Protocol == "https" && strings.EqualFold(site.Bindings[i].Info, want) {
				found = &site.Bindings[i]
			}
		}
		if found == nil {
			return nil, fmt.Errorf("site %q has no https binding %s (create it in IIS first)", tgt.Site, want)
		}
		k, err := bindingSSLKey(*found)
		if err != nil {
			return nil, err
		}
		keys[want] = k
	}
	return keys, nil
}

// deployIIS points the target's bindings at the run's certificate. On a
// failure after the first change it restores the previous certificates.
func (a *Agent) deployIIS(ctx context.Context, tgt *TargetConfig, p agentproto.DeployPayload) (any, error) {
	chain, err := parseChain(p.ChainPEM)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	for _, san := range leaf.DNSNames {
		if !agentproto.SANAllowed(san, tgt.AllowedSANs, true) {
			return nil, fmt.Errorf("certificate SAN %q not allowed for target %s", san, tgt.Name)
		}
	}
	keyName := iisKeyName(tgt.Name, p.RunID)
	key, err := a.win.Key(keyName, false)
	if err != nil {
		return nil, fmt.Errorf("no private key for run %s on this host (was it issued by this agent?): %w", p.RunID, err)
	}
	if !publicKeysEqual(key.Public(), leaf.PublicKey) {
		return nil, errors.New("certificate does not match the run's private key")
	}
	keys, err := a.iisTargetBindings(ctx, tgt)
	if err != nil {
		return nil, err
	}
	prevJSON, err := a.state.Previous(tgt.Name, p.RunID, func() (string, error) {
		prev := iisPrevious{}
		for b, k := range keys {
			e, ok, err := a.win.SSLCert(k)
			if err != nil {
				return "", err
			}
			if ok {
				prev[b] = e
			}
		}
		out, err := json.Marshal(prev)
		return string(out), err
	})
	if err != nil {
		return nil, err
	}
	var prev iisPrevious
	if err := json.Unmarshal([]byte(prevJSON), &prev); err != nil {
		return nil, err
	}
	thumb, store, err := a.win.AddCert(chain, keyName, iisFriendlyPrefix(tgt.Name)+p.RunID)
	if err != nil {
		return nil, fmt.Errorf("certificate store: %w", err)
	}
	out := agentproto.DeployOutput{Previous: a.iisRunOf(tgt, prev)}
	want := sslEntry{Hash: thumb, Store: store}
	var changed []string
	restore := func(cause error) (any, error) {
		for _, b := range changed {
			if e, ok := prev[b]; ok {
				// A failed change usually leaves the entry as it was.
				if cur, ok, err := a.win.SSLCert(keys[b]); err == nil && ok && bytes.Equal(cur.Hash, e.Hash) {
					continue
				}
				if err := a.win.SetSSLCert(keys[b], e); err != nil {
					return out, fmt.Errorf("%w; RESTORE FAILED for %s: %w", cause, b, err)
				}
			}
		}
		out.RolledBack = true
		return out, cause
	}
	for _, b := range tgt.Bindings {
		changed = append(changed, b)
		if err := a.win.SetSSLCert(keys[b], want); err != nil {
			return restore(fmt.Errorf("binding %s: %w", b, err))
		}
		got, ok, err := a.win.SSLCert(keys[b])
		if err != nil || !ok || !bytes.Equal(got.Hash, want.Hash) {
			return restore(fmt.Errorf("binding %s: HTTP.sys does not hold the new certificate after the change (err %w)", b, err))
		}
	}
	a.pruneIISCerts(tgt, want, prev)
	return out, nil
}

// iisRunOf names the run whose certificate prev held, if certloom created it.
func (a *Agent) iisRunOf(tgt *TargetConfig, prev iisPrevious) string {
	own, err := a.win.OwnCerts(iisFriendlyPrefix(tgt.Name))
	if err != nil {
		return ""
	}
	for _, e := range prev {
		for _, c := range own {
			if bytes.Equal(c.Thumb, e.Hash) {
				return strings.TrimPrefix(c.FriendlyName, iisFriendlyPrefix(tgt.Name))
			}
		}
	}
	return ""
}

// pruneIISCerts removes older certloom certificates and keys of the target,
// keeping the current one and those the deploy replaced (for rollback).
// Certificates certloom did not create are never touched.
func (a *Agent) pruneIISCerts(tgt *TargetConfig, current sslEntry, prev iisPrevious) {
	own, err := a.win.OwnCerts(iisFriendlyPrefix(tgt.Name))
	if err != nil {
		a.log.Warn("listing old certificates failed", "target", tgt.Name, "error", err)
		return
	}
	keep := func(thumb []byte) bool {
		if bytes.Equal(thumb, current.Hash) {
			return true
		}
		for _, e := range prev {
			if bytes.Equal(thumb, e.Hash) {
				return true
			}
		}
		return false
	}
	for _, c := range own {
		if keep(c.Thumb) {
			continue
		}
		run := strings.TrimPrefix(c.FriendlyName, iisFriendlyPrefix(tgt.Name))
		if err := a.win.RemoveCert(c.Store, c.Thumb); err != nil {
			a.log.Warn("removing old certificate failed", "target", tgt.Name, "run", run, "error", err)
			continue
		}
		if err := a.win.DeleteKey(iisKeyName(tgt.Name, run)); err != nil {
			a.log.Warn("removing old key failed", "target", tgt.Name, "run", run, "error", err)
		}
	}
}

func (a *Agent) rollbackIIS(ctx context.Context, tgt *TargetConfig, p agentproto.RollbackPayload) (any, error) {
	prevJSON, ok := a.state.LookupPrevious(tgt.Name, p.RunID)
	if !ok {
		return map[string]string{"note": "no deploy recorded for this run; nothing to roll back"}, nil
	}
	var prev iisPrevious
	if err := json.Unmarshal([]byte(prevJSON), &prev); err != nil {
		return nil, err
	}
	if len(prev) == 0 {
		return nil, errors.New("no previous certificate was bound before this run; refusing to remove the live certificate")
	}
	keys, err := a.iisTargetBindings(ctx, tgt)
	if err != nil {
		return nil, err
	}
	restored := map[string]string{}
	for b, e := range prev {
		k, ok := keys[b]
		if !ok {
			continue
		}
		if err := a.win.SetSSLCert(k, e); err != nil {
			return nil, fmt.Errorf("restoring %s: %w", b, err)
		}
		restored[b] = strings.ToUpper(hex.EncodeToString(e.Hash))
	}
	return map[string]any{"restored": restored}, nil
}

// verifyIIS handshakes with every configured binding. Wildcard IPs are
// reached over loopback; the binding's host (or the run's SNI) is sent.
func (a *Agent) verifyIIS(ctx context.Context, tgt *TargetConfig, p agentproto.VerifyPayload) (any, error) {
	out := agentproto.VerifyOutput{Match: true}
	for _, b := range tgt.Bindings {
		ip, port, host, err := parseBinding(b)
		if err != nil {
			return nil, err
		}
		if ip == "*" {
			ip = "127.0.0.1"
		}
		sni := host
		if sni == "" {
			sni = p.SNI
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		var served string
		var lastErr error
		for range 5 {
			served, lastErr = servedFingerprint(ctx, addr, sni)
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
			return nil, fmt.Errorf("binding %s: %w", b, lastErr)
		}
		if out.ServedSHA256 == "" || served != p.ExpectedSHA256 {
			out.ServedSHA256 = served
		}
		if served != p.ExpectedSHA256 {
			out.Match = false
		}
	}
	return out, nil
}

// inventoryIIS reports every https binding with the certificate HTTP.sys
// serves for it, so the control plane can detect binding drift.
func (a *Agent) inventoryIIS(ctx context.Context) ([]agentproto.IISBinding, error) {
	sites, err := a.win.Sites(ctx)
	if err != nil {
		return nil, err
	}
	var out []agentproto.IISBinding
	for _, s := range sites {
		for _, b := range s.Bindings {
			if b.Protocol != "https" {
				continue
			}
			rec := agentproto.IISBinding{Site: s.Name, Binding: b.Info, SSLFlags: b.SSLFlags}
			k, err := bindingSSLKey(b)
			if err == nil {
				if e, ok, err := a.win.SSLCert(k); err == nil && ok {
					rec.CertHash, rec.CertStore = strings.ToUpper(hex.EncodeToString(e.Hash)), e.Store
					if der, err := a.win.Cert(e.Store, e.Hash); err == nil && der != nil {
						h := sha256.Sum256(der)
						rec.CertSHA256 = hex.EncodeToString(h[:])
						rec.ChainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
					}
				}
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

func parseChain(chainPEM string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	b := []byte(chainPEM)
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
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
	if len(out) == 0 {
		return nil, errors.New("no certificate in chain")
	}
	return out, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// readWinACME reads win-acme renewal files (never writes them). Only names,
// plugins and history are reported; stored credentials are not.
func readWinACME(dir string) []agentproto.WinACMERenewal {
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*.renewal.json"))
	var out []agentproto.WinACMERenewal
	for _, f := range files {
		if r, ok := readWinACMEFile(f); ok {
			out = append(out, r)
		}
	}
	return out
}

func readWinACMEFile(path string) (agentproto.WinACMERenewal, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 1<<20 {
		return agentproto.WinACMERenewal{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return agentproto.WinACMERenewal{}, false
	}
	type plugin struct {
		Type   string `json:"$type"`
		Plugin string `json:"Plugin"`
	}
	var doc struct {
		ID            string `json:"Id"`
		FriendlyName  string `json:"FriendlyName"`
		LastFriendly  string `json:"LastFriendlyName"`
		TargetOptions struct {
			plugin
			Host             string   `json:"Host"`
			CommonName       string   `json:"CommonName"`
			AlternativeNames []string `json:"AlternativeNames"`
		} `json:"TargetPluginOptions"`
		Store        []plugin `json:"StorePluginOptions"`
		Installation []plugin `json:"InstallationPluginOptions"`
		History      []struct {
			Date    string `json:"Date"`
			Success bool   `json:"Success"`
		} `json:"History"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &doc); err != nil || doc.ID == "" {
		return agentproto.WinACMERenewal{}, false
	}
	name := func(p plugin) string {
		if p.Type != "" {
			t, _, _ := strings.Cut(p.Type, ",")
			return t[strings.LastIndex(t, ".")+1:]
		}
		return p.Plugin
	}
	r := agentproto.WinACMERenewal{ID: doc.ID, FriendlyName: doc.FriendlyName, Target: name(doc.TargetOptions.plugin), Path: path}
	if r.FriendlyName == "" {
		r.FriendlyName = doc.LastFriendly
	}
	for _, h := range append([]string{doc.TargetOptions.Host, doc.TargetOptions.CommonName}, doc.TargetOptions.AlternativeNames...) {
		if h != "" && !containsFold(r.Hosts, h) {
			r.Hosts = append(r.Hosts, strings.ToLower(h))
		}
	}
	for _, p := range doc.Store {
		r.Store = append(r.Store, name(p))
	}
	for _, p := range doc.Installation {
		r.Installation = append(r.Installation, name(p))
	}
	if n := len(doc.History); n > 0 {
		r.LastRenewal, r.LastRenewalOK = doc.History[n-1].Date, doc.History[n-1].Success
	}
	return r, true
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
