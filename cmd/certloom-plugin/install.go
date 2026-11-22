package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"sigs.k8s.io/yaml"

	"github.com/alexandrosnt/certloom/internal/pluginstore"
)

// agentConfig is the part of the agent config the installer needs. Other
// keys are ignored; certloom-agent check-config validates the whole file.
type agentConfig struct {
	StateDir string              `json:"state_dir"`
	Plugins  *pluginstore.Config `json:"plugins"`
}

func loadAgentConfig(path string) (*agentConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c agentConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return nil, fmt.Errorf("%s: state_dir must be an absolute path", path)
	}
	if c.Plugins == nil {
		c.Plugins = &pluginstore.Config{}
	}
	if p := c.Plugins.Validate(); len(p) > 0 {
		return nil, fmt.Errorf("%s: %s", path, strings.Join(p, "; "))
	}
	return &c, nil
}

func (c *agentConfig) pluginsDir() string { return c.Plugins.PluginsDir(c.StateDir) }

// fetch reads a local file or an https URL, up to maxArchiveBytes.
func fetch(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") {
		return nil, fmt.Errorf("%s: only https URLs are allowed", src)
	}
	if !strings.HasPrefix(src, "https://") {
		f, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readLimited(f, src)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// The URL is the operator's own command-line argument.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil) //nolint:gosec // see above
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // operator-supplied URL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", src, resp.Status)
	}
	return readLimited(resp.Body, src)
}

func readLimited(r io.Reader, name string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxArchiveBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxArchiveBytes)
	}
	return b, nil
}

// bundleSource is the signature bundle next to a package unless given.
func bundleSource(pkg, bundleFlag string) string {
	if bundleFlag != "" {
		return bundleFlag
	}
	return pkg + ".sigstore.json"
}

// verified is a package whose signature and contents passed every check.
type verified struct {
	manifest *pluginstore.Manifest
	entries  []entry
	digest   string
	signer   signer
}

// verifyPackage checks the signature over the archive first and only then
// looks inside it.
func verifyPackage(ctx context.Context, policy *trustPolicy, pkgSrc, bundleSrc string) (*verified, error) {
	archive, err := fetch(ctx, pkgSrc)
	if err != nil {
		return nil, err
	}
	bb, err := fetch(ctx, bundleSrc)
	if err != nil {
		return nil, fmt.Errorf("signature bundle: %w (unsigned packages are not installed)", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bb); err != nil {
		return nil, fmt.Errorf("signature bundle %s: %w", bundleSrc, err)
	}
	return verifyArchive(policy, archive, &b)
}

func verifyArchive(policy *trustPolicy, archive []byte, entity verify.SignedEntity) (*verified, error) {
	sum := sha256.Sum256(archive)
	s, err := policy.verify(entity, sum[:])
	if err != nil {
		return nil, err
	}
	m, entries, err := readPackage(archive)
	if err != nil {
		return nil, err
	}
	return &verified{manifest: m, entries: entries, digest: hex.EncodeToString(sum[:]), signer: s}, nil
}

// install unpacks a verified package into the plugins directory. The
// version directory appears complete or not at all, and install.json is
// written last, so the agent never sees a half-installed plugin.
func install(v *verified, pluginsDir string, now time.Time) (*pluginstore.Record, error) {
	m := v.manifest
	final := pluginstore.VersionDir(pluginsDir, m.Name, m.Version)
	if _, err := os.Stat(final); err == nil {
		return nil, fmt.Errorf("%s %s is already installed (remove it first)", m.Name, m.Version)
	}
	parent := filepath.Dir(final)
	if err := os.MkdirAll(parent, 0o755); err != nil { //nolint:gosec // readable by the agent user, see extract
		return nil, err
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tmp := filepath.Join(parent, ".tmp-"+m.Version+"-"+hex.EncodeToString(b))
	if err := extract(v.entries, m, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	exe := filepath.Join(final, filepath.FromSlash(m.Executable))
	exeSum, err := fileSHA256(exe)
	if err != nil {
		return nil, err
	}
	r := &pluginstore.Record{Name: m.Name, Version: m.Version, Kinds: m.Kinds, Executable: exe, ExecutableSHA256: exeSum,
		ArchiveSHA256: v.digest, Trust: v.signer.Trust, Signer: v.signer.Identity, InstalledAt: now.UTC()}
	rb, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	recPath := filepath.Join(final, pluginstore.RecordFile)
	if err := os.WriteFile(recPath+".tmp", rb, 0o644); err != nil { //nolint:gosec // the agent user reads the record
		return nil, err
	}
	return r, os.Rename(recPath+".tmp", recPath)
}

// remove deletes one installed version, record first so the agent stops
// using it before its files disappear.
func remove(pluginsDir, ref string) error {
	name, version, ok := strings.Cut(ref, "@")
	if !ok || !pluginstore.ValidName(name) || version == "" || strings.ContainsAny(version, `/\`) || strings.HasPrefix(version, ".") {
		return fmt.Errorf("give the plugin as name@version, e.g. corp-f5@1.2.0")
	}
	dir := pluginstore.VersionDir(pluginsDir, name, version)
	if err := os.Remove(filepath.Join(dir, pluginstore.RecordFile)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s is not installed", ref)
		}
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	_ = os.Remove(filepath.Dir(dir)) // only succeeds when no versions are left
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
