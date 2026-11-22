package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func trustAgent(stores ...TrustStoreConfig) *Agent {
	return &Agent{cfg: &Config{TrustStores: stores}}
}

func applyTrust(t *testing.T, a *Agent, store string, version int, roots ...*testpki.Cert) (agentproto.TrustApplyOutput, error) {
	t.Helper()
	p := agentproto.TrustApplyPayload{Store: store, Bundle: "corp", Version: version, Digest: "d"}
	for _, r := range roots {
		p.Anchors = append(p.Anchors, string(r.PEM()))
	}
	raw, _ := json.Marshal(p)
	out, err := a.handleTrustApply(context.Background(), &agentproto.Task{Type: agentproto.TaskTrustApply, Payload: raw})
	if err != nil {
		return agentproto.TrustApplyOutput{}, err
	}
	return out.(agentproto.TrustApplyOutput), nil
}

func anchorSet(st agentproto.TrustStoreState, ownedOnly bool) []string {
	var out []string
	for _, a := range st.Anchors {
		if !ownedOnly || a.Owned {
			out = append(out, a.SHA256)
		}
	}
	slices.Sort(out)
	return out
}

func hashes(cs ...*testpki.Cert) []string {
	var out []string
	for _, c := range cs {
		h := sha256.Sum256(c.DER)
		out = append(out, hex.EncodeToString(h[:]))
	}
	slices.Sort(out)
	return out
}

func roots(t *testing.T, n int) []*testpki.Cert {
	var out []*testpki.Cert
	for i := range n {
		out = append(out, testpki.Issue(t, nil, testpki.Options{CommonName: "Root " + string(rune('A'+i)), IsCA: true}))
	}
	return out
}

func TestTrustPEMAndPKCS12(t *testing.T) {
	dir := t.TempDir()
	r := roots(t, 2)
	a := trustAgent(
		TrustStoreConfig{Name: "bundle", Type: agentproto.TrustPEM, Path: filepath.Join(dir, "ca.pem")},
		TrustStoreConfig{Name: "java", Type: agentproto.TrustPKCS12, Path: filepath.Join(dir, "trust.p12")},
	)
	for _, store := range []string{"bundle", "java"} {
		out, err := applyTrust(t, a, store, 1, r[0], r[1])
		if err != nil {
			t.Fatalf("%s: %v", store, err)
		}
		if got := anchorSet(out.State, true); !slices.Equal(got, hashes(r[0], r[1])) || out.Version != 1 {
			t.Fatalf("%s after v1: %v", store, out)
		}
		out, err = applyTrust(t, a, store, 2, r[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := anchorSet(out.State, true); !slices.Equal(got, hashes(r[1])) {
			t.Fatalf("%s after v2: %v", store, got)
		}
	}
	inv := a.inventoryTrust()
	if len(inv) != 2 || inv[0].Error != "" || inv[1].Error != "" || len(inv[1].Anchors) != 1 {
		t.Fatalf("inventory: %+v", inv)
	}

	// A wrong password shows up as a read error, not as an empty store.
	pw := filepath.Join(dir, "pw")
	_ = os.WriteFile(pw, []byte("other\n"), 0o600)
	a.cfg.TrustStores[1].PasswordFile = pw
	if st := a.trustState(&a.cfg.TrustStores[1]); st.Error == "" {
		t.Error("expected a decode error with the wrong password")
	}
}

func TestTrustCommandFailureRestores(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/false")
	}
	dir := t.TempDir()
	r := roots(t, 2)
	path := filepath.Join(dir, "ca.pem")
	a := trustAgent(TrustStoreConfig{Name: "bundle", Type: agentproto.TrustPEM, Path: path})
	if _, err := applyTrust(t, a, "bundle", 1, r[0]); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	a.cfg.TrustStores[0].ReloadCommand = []string{"false"}
	if _, err := applyTrust(t, a, "bundle", 2, r[1]); err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err = %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("store was not restored")
	}
}

func TestTrustDebianKeepsForeignAnchors(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "certloom")
	r := roots(t, 3)
	// An anchor the administrator installed by hand.
	if err := os.WriteFile(filepath.Join(base, "corp-old.crt"), r[2].PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	a := trustAgent(TrustStoreConfig{Name: "os", Type: agentproto.TrustDebian, Path: own, UpdateCommand: []string{"go", "version"}})
	out, err := applyTrust(t, a, "os", 1, r[0], r[1])
	if err != nil {
		t.Fatal(err)
	}
	if got := anchorSet(out.State, true); !slices.Equal(got, hashes(r[0], r[1])) {
		t.Fatalf("owned = %v", got)
	}
	if got := anchorSet(out.State, false); !slices.Equal(got, hashes(r[0], r[1], r[2])) {
		t.Fatalf("all = %v", got)
	}
	if _, err := applyTrust(t, a, "os", 2, r[1]); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(own, "*.crt"))
	if len(files) != 1 {
		t.Fatalf("owned files: %v", files)
	}
	if _, err := os.Stat(filepath.Join(base, "corp-old.crt")); err != nil {
		t.Fatal("the administrator's anchor must stay")
	}
}

func TestTrustRHELOwnsPrefixedFiles(t *testing.T) {
	dir := t.TempDir()
	r := roots(t, 2)
	_ = os.WriteFile(filepath.Join(dir, "vendor.pem"), r[1].PEM(), 0o644)
	a := trustAgent(TrustStoreConfig{Name: "os", Type: agentproto.TrustRHEL, Path: dir, UpdateCommand: []string{"go", "version"}})
	out, err := applyTrust(t, a, "os", 1, r[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := anchorSet(out.State, true); !slices.Equal(got, hashes(r[0])) {
		t.Fatalf("owned = %v", got)
	}
	if _, err := applyTrust(t, a, "os", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vendor.pem")); err != nil {
		t.Fatal("foreign anchor removed")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, rhelPrefix+"*")); len(files) != 0 {
		t.Fatalf("owned files left: %v", files)
	}
}

type fakeRoot struct{ certs []winTrustCert }

func (f *fakeRoot) List() ([]winTrustCert, error) { return slices.Clone(f.certs), nil }
func (f *fakeRoot) Add(c *x509.Certificate, name string) error {
	f.certs = append(f.certs, winTrustCert{DER: c.Raw, FriendlyName: name})
	return nil
}
func (f *fakeRoot) Remove(der []byte) error {
	f.certs = slices.DeleteFunc(f.certs, func(e winTrustCert) bool { return bytes.Equal(e.DER, der) })
	return nil
}

func TestTrustWindowsLabelsOwnEntries(t *testing.T) {
	r := roots(t, 3)
	host := &fakeRoot{certs: []winTrustCert{{DER: r[2].DER, FriendlyName: "Microsoft Root"}, {DER: r[1].DER, FriendlyName: "Corp (by hand)"}}}
	a := trustAgent(TrustStoreConfig{Name: "win", Type: agentproto.TrustWindows})
	a.winTrust = host
	out, err := applyTrust(t, a, "win", 1, r[0], r[1])
	if err != nil {
		t.Fatal(err)
	}
	// r[1] was already there by hand: present, but not certloom's.
	if got := anchorSet(out.State, true); !slices.Equal(got, hashes(r[0])) {
		t.Fatalf("owned = %v", got)
	}
	if _, err := applyTrust(t, a, "win", 2); err != nil {
		t.Fatal(err)
	}
	if len(host.certs) != 2 {
		t.Fatalf("removing the bundle must leave the other roots: %+v", host.certs)
	}
	a.winTrust = nil
	if st := a.trustState(&a.cfg.TrustStores[0]); st.Error == "" {
		t.Error("windows store without a host must report an error")
	}
}

func TestTrustApplyRefusals(t *testing.T) {
	dir := t.TempDir()
	r := roots(t, 1)
	leaf := testpki.Issue(t, r[0], testpki.Options{CommonName: "leaf"})
	a := trustAgent(
		TrustStoreConfig{Name: "watch", Type: agentproto.TrustPEM, Path: filepath.Join(dir, "a.pem"), Mode: agentproto.TrustObserve},
		TrustStoreConfig{Name: "bundle", Type: agentproto.TrustPEM, Path: filepath.Join(dir, "b.pem")},
	)
	if _, err := applyTrust(t, a, "watch", 1, r[0]); err == nil {
		t.Error("observe-only store was written")
	}
	if _, err := applyTrust(t, a, "nope", 1, r[0]); err == nil {
		t.Error("unknown store accepted")
	}
	if _, err := applyTrust(t, a, "bundle", 1, leaf); err == nil {
		t.Error("non-CA anchor accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "a.pem")); err == nil {
		t.Error("observe-only file created")
	}
}

func TestTrustStoreConfigValidation(t *testing.T) {
	bad := [][]TrustStoreConfig{
		{{Name: "x", Type: "jks", Path: "/a"}},
		{{Name: "x", Type: agentproto.TrustPEM}},
		{{Name: "x", Type: agentproto.TrustPEM, Path: "/a", Mode: "sync"}},
		{{Name: "x", Type: agentproto.TrustWindows, Path: "/a"}},
		{{Name: "x", Type: agentproto.TrustPEM, Path: "/a", PasswordFile: "/p"}},
		{{Name: "x", Type: agentproto.TrustDebian}, {Name: "x", Type: agentproto.TrustRHEL}},
		{{Name: "a/b", Type: agentproto.TrustDebian}},
	}
	for i, ts := range bad {
		if p := (&Config{TrustStores: ts}).validateTrustStores(); len(p) == 0 {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := &Config{TrustStores: []TrustStoreConfig{{Name: "os", Type: agentproto.TrustDebian}, {Name: "java", Type: agentproto.TrustPKCS12,
		Path: filepath.Join(t.TempDir(), "trust.p12"), PasswordFile: "/etc/java/pw"}, {Name: "win", Type: agentproto.TrustWindows, Mode: agentproto.TrustObserve}}}
	if p := ok.validateTrustStores(); len(p) != 0 {
		t.Errorf("valid config refused: %v", p)
	}
	if got := ok.trustStoreInfos(); len(got) != 3 || got[0].Mode != agentproto.TrustManage || got[2].Mode != agentproto.TrustObserve {
		t.Errorf("infos = %+v", got)
	}
}
