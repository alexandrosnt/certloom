package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Windows thumbprints are SHA-1
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// fakeWin stands in for CNG, the certificate store, HTTP.sys and appcmd.
type fakeWin struct {
	keys    map[string]*ecdsa.PrivateKey
	certs   map[string]storedCert // hex thumb -> cert
	ders    map[string][]byte
	entries map[string]sslEntry // sslKey.String() -> entry
	sites   []iisSite
	failSet map[string]error
}

func newFakeWin(sites ...iisSite) *fakeWin {
	return &fakeWin{keys: map[string]*ecdsa.PrivateKey{}, certs: map[string]storedCert{}, ders: map[string][]byte{},
		entries: map[string]sslEntry{}, sites: sites, failSet: map[string]error{}}
}

func (f *fakeWin) Key(name string, create bool) (crypto.Signer, error) {
	if k, ok := f.keys[name]; ok {
		return k, nil
	}
	if !create {
		return nil, errors.New("key not found")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.keys[name] = k
	return k, nil
}

func (f *fakeWin) DeleteKey(name string) error { delete(f.keys, name); return nil }

func (f *fakeWin) AddCert(chain []*x509.Certificate, _ /*keyName*/, friendly string) ([]byte, string, error) {
	t := sha1.Sum(chain[0].Raw) //nolint:gosec // thumbprint
	f.certs[hex.EncodeToString(t[:])] = storedCert{Store: "WebHosting", FriendlyName: friendly, Thumb: t[:]}
	f.ders[hex.EncodeToString(t[:])] = chain[0].Raw
	return t[:], "WebHosting", nil
}

func (f *fakeWin) OwnCerts(prefix string) ([]storedCert, error) {
	var out []storedCert
	for _, c := range f.certs {
		if strings.HasPrefix(c.FriendlyName, prefix) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeWin) RemoveCert(_ string, thumb []byte) error {
	delete(f.certs, hex.EncodeToString(thumb))
	return nil
}

func (f *fakeWin) Cert(_ string, thumb []byte) ([]byte, error) {
	return f.ders[hex.EncodeToString(thumb)], nil
}

func (f *fakeWin) Sites(context.Context) ([]iisSite, error) { return f.sites, nil }

func (f *fakeWin) SSLCert(k sslKey) (sslEntry, bool, error) {
	e, ok := f.entries[k.String()]
	return e, ok, nil
}

func (f *fakeWin) SetSSLCert(k sslKey, e sslEntry) error {
	if err := f.failSet[k.String()]; err != nil {
		return err
	}
	f.entries[k.String()] = e
	return nil
}

func (f *fakeWin) addForeign(t *testing.T, friendly string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := selfSigned(t, k, "old.example.test")
	th, _, _ := f.AddCert([]*x509.Certificate{c}, "", friendly)
	return th
}

func selfSigned(t *testing.T, k crypto.Signer, names ...string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func chainPEM(cs ...*x509.Certificate) string {
	var b bytes.Buffer
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

func iisAgent(t *testing.T, win *fakeWin) (*Agent, *TargetConfig) {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tgt := TargetConfig{Name: "shop", Type: agentproto.TargetIIS, Site: "Shop", Bindings: []string{"*:443:shop.example.test", "10.0.0.5:8443:"},
		AllowedSANs: []string{"shop.example.test"}}
	a := &Agent{cfg: &Config{StateDir: dir, Targets: []TargetConfig{tgt}}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: st, win: win}
	return a, &a.cfg.Targets[0]
}

func shopSite() iisSite {
	return iisSite{Name: "Shop", Bindings: []iisBinding{
		{Protocol: "http", Info: "*:80:shop.example.test"},
		{Protocol: "https", Info: "*:443:shop.example.test", SSLFlags: sslFlagSNI},
		{Protocol: "https", Info: "10.0.0.5:8443:"},
	}}
}

func TestParseBindingAndSSLKey(t *testing.T) {
	cases := []struct {
		b    iisBinding
		want string
		err  bool
	}{
		{iisBinding{Info: "*:443:www.example.test", SSLFlags: 1}, "www.example.test:443", false},
		{iisBinding{Info: "*:443:"}, "0.0.0.0:443", false},
		{iisBinding{Info: "10.1.2.3:8443:www.example.test"}, "10.1.2.3:8443", false},
		{iisBinding{Info: "[::1]:443:"}, "[::1]:443", false},
		{iisBinding{Info: "*:443:www.example.test", SSLFlags: 3}, "", true}, // CCS
		{iisBinding{Info: "*:443:", SSLFlags: 1}, "", true},                 // SNI without host
		{iisBinding{Info: "*:99999:"}, "", true},
		{iisBinding{Info: "nonsense"}, "", true},
	}
	for _, c := range cases {
		k, err := bindingSSLKey(c.b)
		if (err != nil) != c.err || (err == nil && k.String() != c.want) {
			t.Errorf("%+v: got %v %v, want %q err=%v", c.b, k, err, c.want, c.err)
		}
	}
}

func TestAppcmdSites(t *testing.T) {
	out := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<appcmd>
    <SITE SITE.NAME="Default Web Site" SITE.ID="1" STATE="Started">
        <site name="Default Web Site" id="1">
            <bindings>
                <binding protocol="http" bindingInformation="*:80:" />
                <binding protocol="https" bindingInformation="*:443:www.example.test" sslFlags="1" />
            </bindings>
            <application path="/">
                <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot" />
            </application>
        </site>
    </SITE>
</appcmd>`)
	sites, err := appcmdSites(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Name != "Default Web Site" || len(sites[0].Bindings) != 2 || sites[0].PhysicalPath != `C:\inetpub\wwwroot` {
		t.Fatalf("%+v", sites)
	}
	if b := sites[0].Bindings[1]; b.Protocol != "https" || b.SSLFlags != 1 || b.Info != "*:443:www.example.test" {
		t.Fatalf("%+v", b)
	}
}

func TestDeployIISSwitchesBindingsAndPrunes(t *testing.T) {
	win := newFakeWin(shopSite())
	a, tgt := iisAgent(t, win)
	ctx := context.Background()
	// Live state: run0 (older certloom cert), run1 bound now, and a foreign cert.
	old0 := win.addForeign(t, iisFriendlyPrefix("shop")+"run0")
	win.keys[iisKeyName("shop", "run0")], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	old1 := win.addForeign(t, iisFriendlyPrefix("shop")+"run1")
	foreign := win.addForeign(t, "Imported by hand")
	win.entries["shop.example.test:443"] = sslEntry{Hash: old1, Store: "WebHosting"}
	win.entries["10.0.0.5:8443"] = sslEntry{Hash: old1, Store: "WebHosting"}

	key, _ := win.Key(iisKeyName("shop", "run2"), true)
	leaf := selfSigned(t, key, "shop.example.test")
	res, err := a.deployIIS(ctx, tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: chainPEM(leaf)})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(agentproto.DeployOutput)
	if out.Previous != "run1" || out.RolledBack {
		t.Fatalf("output %+v", out)
	}
	newThumb := sha1.Sum(leaf.Raw) //nolint:gosec // thumbprint
	for k, e := range win.entries {
		if !bytes.Equal(e.Hash, newThumb[:]) {
			t.Fatalf("%s still points at %x", k, e.Hash)
		}
	}
	if _, ok := win.certs[hex.EncodeToString(old0)]; ok {
		t.Fatal("run0 certificate should be pruned")
	}
	if _, ok := win.keys[iisKeyName("shop", "run0")]; ok {
		t.Fatal("run0 key should be deleted")
	}
	for _, keep := range [][]byte{old1, foreign} {
		if _, ok := win.certs[hex.EncodeToString(keep)]; !ok {
			t.Fatalf("certificate %x must be kept", keep)
		}
	}

	// Rollback restores run1 on both bindings.
	if _, err := a.rollbackIIS(ctx, tgt, agentproto.RollbackPayload{RunID: "run2"}); err != nil {
		t.Fatal(err)
	}
	for k, e := range win.entries {
		if !bytes.Equal(e.Hash, old1) {
			t.Fatalf("%s not restored", k)
		}
	}
}

func TestDeployIISRestoresOnFailure(t *testing.T) {
	win := newFakeWin(shopSite())
	a, tgt := iisAgent(t, win)
	old := win.addForeign(t, iisFriendlyPrefix("shop")+"run1")
	win.entries["shop.example.test:443"] = sslEntry{Hash: old, Store: "WebHosting"}
	win.entries["10.0.0.5:8443"] = sslEntry{Hash: old, Store: "WebHosting"}
	win.failSet["10.0.0.5:8443"] = errors.New("access denied")
	key, _ := win.Key(iisKeyName("shop", "run2"), true)
	res, err := a.deployIIS(context.Background(), tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: chainPEM(selfSigned(t, key, "shop.example.test"))})
	if err == nil || !res.(agentproto.DeployOutput).RolledBack {
		t.Fatalf("want rolled back failure, got %v %+v", err, res)
	}
	if !bytes.Equal(win.entries["shop.example.test:443"].Hash, old) {
		t.Fatal("first binding not restored")
	}
}

func TestDeployIISRefusals(t *testing.T) {
	ctx := context.Background()
	// Binding missing from the site, CCS binding, wrong key, SAN not allowed.
	site := shopSite()
	site.Bindings = site.Bindings[:2]
	win := newFakeWin(site)
	a, tgt := iisAgent(t, win)
	key, _ := win.Key(iisKeyName("shop", "run2"), true)
	ok := chainPEM(selfSigned(t, key, "shop.example.test"))
	if _, err := a.deployIIS(ctx, tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: ok}); err == nil || !strings.Contains(err.Error(), "no https binding") {
		t.Fatalf("missing binding: %v", err)
	}
	ccs := shopSite()
	ccs.Bindings[1].SSLFlags = sslFlagSNI | sslFlagCCS
	win.sites = []iisSite{ccs}
	if _, err := a.deployIIS(ctx, tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: ok}); err == nil || !strings.Contains(err.Error(), "Central Certificate Store") {
		t.Fatalf("CCS: %v", err)
	}
	win.sites = []iisSite{shopSite()}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := a.deployIIS(ctx, tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: chainPEM(selfSigned(t, other, "shop.example.test"))}); err == nil {
		t.Fatal("certificate for another key accepted")
	}
	if _, err := a.deployIIS(ctx, tgt, agentproto.DeployPayload{RunID: "run2", ChainPEM: chainPEM(selfSigned(t, key, "evil.example.test"))}); err == nil {
		t.Fatal("SAN outside allowed_sans accepted")
	}
	if len(win.entries) != 0 {
		t.Fatal("a refused deploy changed HTTP.sys")
	}
}

func TestVerifyIIS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := selfSigned(t, key, "shop.example.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	a, _ := iisAgent(t, newFakeWin())
	tgt := &TargetConfig{Name: "shop", Type: agentproto.TargetIIS, Bindings: []string{ln.Addr().String() + ":shop.example.test"}}
	sum := sha256.Sum256(leaf.Raw)
	res, err := a.verifyIIS(context.Background(), tgt, agentproto.VerifyPayload{ExpectedSHA256: hex.EncodeToString(sum[:])})
	if err != nil || !res.(agentproto.VerifyOutput).Match {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

func TestInventoryIISReportsBindings(t *testing.T) {
	win := newFakeWin(shopSite())
	a, _ := iisAgent(t, win)
	th := win.addForeign(t, "x")
	win.entries["shop.example.test:443"] = sslEntry{Hash: th, Store: "WebHosting"}
	got, err := a.inventoryIIS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the 2 https bindings, got %+v", got)
	}
	if got[0].CertHash != strings.ToUpper(hex.EncodeToString(th)) || got[0].CertSHA256 == "" || got[0].ChainPEM == "" {
		t.Fatalf("bound entry: %+v", got[0])
	}
	if got[1].CertHash != "" {
		t.Fatalf("binding without HTTP.sys entry must have no hash: %+v", got[1])
	}
}

func TestIISConfigValidation(t *testing.T) {
	base := func() *Config {
		return &Config{Server: "https://cp.example.test", StateDir: filepath.Join(t.TempDir(), "s"), Targets: []TargetConfig{{
			Name: "shop", Type: "iis", Site: "Shop", Bindings: []string{"*:443:shop.example.test"}, AllowedSANs: []string{"shop.example.test"}}}}
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"no site":      func(c *Config) { c.Targets[0].Site = "" },
		"no bindings":  func(c *Config) { c.Targets[0].Bindings = nil },
		"bad binding":  func(c *Config) { c.Targets[0].Bindings = []string{"*:443"} },
		"nginx fields": func(c *Config) { c.Targets[0].ReloadCommand = []string{"x"} },
		"kube targets": func(c *Config) { c.Kubernetes = &KubeConfig{Cluster: "c"} },
	} {
		c := base()
		mut(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWinACMEDiscovery(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "acme-v02.api.letsencrypt.org")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := `{
  "Id": "abc123",
  "LastFriendlyName": "[IIS] Shop, (any host)",
  "TargetPluginOptions": {"$type": "PKISharp.WACS.Plugins.TargetPlugins.IISOptions, wacs.lib", "Host": "Shop.example.test",
    "AlternativeNames": ["shop.example.test", "www.shop.example.test"]},
  "StorePluginOptions": [{"$type": "PKISharp.WACS.Plugins.StorePlugins.CertificateStoreOptions, wacs.lib", "Plugin": "b5f6", "PfxPassword": {"Value": "secret"}}],
  "InstallationPluginOptions": [{"Plugin": "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2"}],
  "History": [{"Date": "2026-10-01T10:00:00Z", "Success": true}, {"Date": "2026-11-01T10:00:00Z", "Success": false}]
}`
	if err := os.WriteFile(filepath.Join(sub, "abc123.renewal.json"), []byte("\xef\xbb\xbf"+doc), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sub, "broken.renewal.json"), []byte("{"), 0o600)
	got := readWinACME(dir)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	r := got[0]
	want := agentproto.WinACMERenewal{ID: "abc123", FriendlyName: "[IIS] Shop, (any host)", Hosts: []string{"shop.example.test", "www.shop.example.test"},
		Target: "IISOptions", Store: []string{"CertificateStoreOptions"}, Installation: []string{"ea6a5be3-f8de-4d27-a6bd-750b619b2ee2"},
		LastRenewal: "2026-11-01T10:00:00Z", LastRenewalOK: false, Path: r.Path}
	if fmt.Sprint(r) != fmt.Sprint(want) {
		t.Fatalf("got  %+v\nwant %+v", r, want)
	}
	if strings.Contains(fmt.Sprint(r), "secret") {
		t.Fatal("stored credentials must not be reported")
	}
}
