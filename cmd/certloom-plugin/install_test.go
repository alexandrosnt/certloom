package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/alexandrosnt/certloom/internal/pluginstore"
)

const (
	ciIssuer   = "https://token.actions.githubusercontent.com"
	ciIdentity = "https://github.com/example/certloom-plugin-f5/.github/workflows/release.yml@refs/tags/v1.2.0"
)

// pluginDir writes a minimal plugin source directory.
func pluginDir(t *testing.T, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		pluginstore.ManifestFile: manifest,
		"bin/corp-f5":            "#!/bin/sh\necho '{\"ok\":true}'\n",
		"README.md":              "F5 BIG-IP deploy target\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const manifest = "name: corp-f5\nversion: 1.2.0\nprotocol: 1\nkinds: [deploy_target]\nexecutable: bin/corp-f5\npermissions: [\"BIG-IP user with the Certificate Manager role\"]\n"

func packed(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := pack(pluginDir(t, manifest), &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// keySigned signs archive with a fresh key, the way cosign sign-blob --key
// does, and returns the bundle JSON and the trust config for the key.
func keySigned(t *testing.T, archive []byte) ([]byte, *pluginstore.Config) {
	t.Helper()
	kp, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := sign.Bundle(&sign.PlainData{Data: archive}, kp, sign.BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bj, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := kp.GetPublicKeyPem()
	keyFile := filepath.Join(t.TempDir(), "corp.pub")
	if err := os.WriteFile(keyFile, []byte(pemKey), 0o644); err != nil {
		t.Fatal(err)
	}
	return bj, &pluginstore.Config{Trust: []pluginstore.Publisher{{Name: "corp", PublicKey: keyFile}}}
}

func loadBundle(t *testing.T, bj []byte) *bundle.Bundle {
	t.Helper()
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bj); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestPackIsDeterministic(t *testing.T) {
	dir := pluginDir(t, manifest)
	var a, b bytes.Buffer
	m, err := pack(dir, &a)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_ = os.Chtimes(filepath.Join(dir, "README.md"), time.Now(), time.Now())
	if _, err := pack(dir, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("packing twice gave different archives")
	}
	if got := packageName(m, "linux", "amd64"); got != "certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz" {
		t.Fatal(got)
	}
	if _, err := pack(pluginDir(t, strings.Replace(manifest, "bin/corp-f5", "bin/missing", 1)), &b); err == nil {
		t.Fatal("packed without the executable")
	}
}

func TestKeyBasedInstall(t *testing.T) {
	archive := packed(t)
	bj, trust := keySigned(t, archive)
	plugins := filepath.Join(t.TempDir(), "plugins")
	v, err := verifyArchive(&trustPolicy{cfg: trust}, archive, loadBundle(t, bj))
	if err != nil {
		t.Fatal(err)
	}
	if v.signer.Trust != "corp" || !strings.HasPrefix(v.signer.Identity, "key sha256:") {
		t.Fatalf("signer %+v", v.signer)
	}
	r, err := install(v, plugins, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recs, err := pluginstore.Load(plugins)
	if err != nil || len(recs) != 1 || recs[0].ExecutableSHA256 != r.ExecutableSHA256 || recs[0].Trust != "corp" {
		t.Fatalf("records %+v %v", recs, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(r.Executable)
		if fi.Mode().Perm() != 0o755 {
			t.Fatalf("executable mode %v", fi.Mode())
		}
	}
	if _, err := install(v, plugins, time.Now()); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("reinstall: %v", err)
	}
	if err := remove(plugins, "corp-f5@1.2.0"); err != nil {
		t.Fatal(err)
	}
	if recs, _ := pluginstore.Load(plugins); len(recs) != 0 {
		t.Fatalf("after remove: %+v", recs)
	}
	for _, bad := range []string{"corp-f5", "corp-f5@../x", "corp-f5@.tmp"} {
		if err := remove(plugins, bad); err == nil {
			t.Errorf("remove %q accepted", bad)
		}
	}
}

func TestRefusesUntrustedOrTampered(t *testing.T) {
	archive := packed(t)
	bj, trust := keySigned(t, archive)
	_, otherTrust := keySigned(t, archive)

	tampered := bytes.Clone(archive)
	tampered[len(tampered)-5] ^= 0xff
	if _, err := verifyArchive(&trustPolicy{cfg: trust}, tampered, loadBundle(t, bj)); err == nil {
		t.Error("tampered archive accepted")
	}
	if _, err := verifyArchive(&trustPolicy{cfg: otherTrust}, archive, loadBundle(t, bj)); err == nil || !strings.Contains(err.Error(), "not signed by a trusted publisher") {
		t.Errorf("other key: %v", err)
	}
	if _, err := verifyArchive(&trustPolicy{cfg: &pluginstore.Config{}}, archive, loadBundle(t, bj)); err == nil || !strings.Contains(err.Error(), "no plugins.trust") {
		t.Errorf("empty trust: %v", err)
	}
}

// noSCT is keylessVerifierOptions without the SCT check: the virtual Sigstore
// issues certificates without SCTs, unlike the real Fulcio.
var noSCT = []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}

func TestKeylessVerification(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	archive := packed(t)
	entity, err := vs.Sign(ciIdentity, ciIssuer, archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive)
	for name, c := range map[string]struct {
		keyless pluginstore.Keyless
		ok      bool
	}{
		"exact identity": {pluginstore.Keyless{Issuer: ciIssuer, Identity: ciIdentity}, true},
		"repo regexp":    {pluginstore.Keyless{Issuer: ciIssuer, IdentityRegexp: `^https://github\.com/example/certloom-plugin-[a-z0-9-]+/\.github/workflows/release\.yml@refs/tags/v`}, true},
		"other repo":     {pluginstore.Keyless{Issuer: ciIssuer, IdentityRegexp: `^https://github\.com/someone-else/`}, false},
		"other issuer":   {pluginstore.Keyless{Issuer: "https://accounts.google.com", Identity: ciIdentity}, false},
	} {
		k := c.keyless
		p := &trustPolicy{cfg: &pluginstore.Config{Trust: []pluginstore.Publisher{{Name: "example", Keyless: &k}}}, keyless: vs, keylessChecks: noSCT}
		s, err := p.verify(entity, sum[:])
		if c.ok && (err != nil || s.Identity != ciIdentity || s.Trust != "example") {
			t.Errorf("%s: %+v %v", name, s, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The signature covers the archive, not just any bytes.
	other := sha256.Sum256([]byte("something else"))
	p := &trustPolicy{cfg: &pluginstore.Config{Trust: []pluginstore.Publisher{{Name: "example",
		Keyless: &pluginstore.Keyless{Issuer: ciIssuer, Identity: ciIdentity}}}}, keyless: vs, keylessChecks: noSCT}
	if _, err := p.verify(entity, other[:]); err == nil {
		t.Fatal("signature accepted for another artifact")
	}
}

// rawArchive builds a gzip tar from hand-written headers, to produce what
// pack never would.
func rawArchive(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		body := ""
		if h.Typeflag == tar.TypeReg {
			body = "x"
			if h.Name == pluginstore.ManifestFile {
				body = manifest
			}
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestReadPackageRefusesUnsafeContent(t *testing.T) {
	m := tar.Header{Name: pluginstore.ManifestFile, Typeflag: tar.TypeReg, Mode: 0o644}
	exe := tar.Header{Name: "bin/corp-f5", Typeflag: tar.TypeReg, Mode: 0o755}
	if _, _, err := readPackage(rawArchive(t, m, exe)); err != nil {
		t.Fatalf("valid package: %v", err)
	}
	for name, hs := range map[string][]tar.Header{
		"traversal":      {m, exe, {Name: "../../etc/cron.d/x", Typeflag: tar.TypeReg}},
		"absolute":       {m, exe, {Name: "/etc/passwd", Typeflag: tar.TypeReg}},
		"symlink":        {m, exe, {Name: "bin/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}},
		"hardlink":       {m, exe, {Name: "bin/hard", Typeflag: tar.TypeLink, Linkname: "bin/corp-f5"}},
		"duplicate":      {m, exe, exe},
		"no manifest":    {exe},
		"no executable":  {m},
		"dot segments":   {m, exe, {Name: "bin/./x", Typeflag: tar.TypeReg}},
		"backslash path": {m, exe, {Name: `bin\x`, Typeflag: tar.TypeReg}},
	} {
		if _, _, err := readPackage(rawArchive(t, hs...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := readPackage([]byte("not gzip")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCommandLine(t *testing.T) {
	ctx := context.Background()
	src := pluginDir(t, manifest)
	out := t.TempDir()
	if err := run(ctx, "pack", []string{src, "--out", out, "--os", "linux", "--arch", "amd64"}); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(out, "certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz")
	archive, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	bj, trust := keySigned(t, archive)
	if err := os.WriteFile(pkg+".sigstore.json", bj, 0o644); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	cfg := map[string]any{"server": "https://cp.example", "state_dir": state, "targets": []any{},
		"plugins": map[string]any{"trust": []any{map[string]any{"name": "corp", "public_key": trust.Trust[0].PublicKey}}}}
	cb, _ := json.Marshal(cfg) // JSON is YAML
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(cfgPath, cb, 0o644)

	if err := run(ctx, "verify", []string{pkg, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, "install", []string{pkg, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := pluginstore.Load(filepath.Join(state, "plugins")); len(recs) != 1 {
		t.Fatalf("installed: %+v", recs)
	}
	if err := run(ctx, "list", []string{"--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, "remove", []string{"corp-f5@1.2.0", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(pkg + ".sigstore.json")
	if err := run(ctx, "install", []string{pkg, "--config", cfgPath}); err == nil || !strings.Contains(err.Error(), "unsigned packages are not installed") {
		t.Fatalf("unsigned install: %v", err)
	}
	if err := run(ctx, "install", []string{"http://example.com/p.tar.gz", "--config", cfgPath}); err == nil {
		t.Fatal("plain http accepted")
	}
}
