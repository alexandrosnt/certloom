// Package pluginstore is the on-disk side of agent plugins (ADR-0027): the
// trust policy in the agent config, the plugin.yaml manifest inside a
// package, and the install records certloom-plugin writes and certloom-agent
// reads. It holds no verification code; certloom-plugin checks signatures
// before it writes a record, and the agent trusts records only for trust
// entries still present in its config.
package pluginstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/plugin"
	"sigs.k8s.io/yaml"
)

// Config is the plugins block of the agent config.
type Config struct {
	// Dir holds installed plugins; default <state_dir>/plugins.
	Dir   string      `json:"dir,omitempty"`
	Trust []Publisher `json:"trust,omitempty"`
	// TrustedRoot is a Sigstore trusted root JSON file. Empty means the
	// public-good Sigstore instance.
	TrustedRoot string `json:"trusted_root,omitempty"`
	// RequireSigned refuses plugins pinned by path and sha256 in the config.
	RequireSigned bool `json:"require_signed,omitempty"`
}

// Publisher is one trusted signer of plugin packages. Exactly one of
// Keyless and PublicKey is set.
type Publisher struct {
	Name      string   `json:"name"`
	Keyless   *Keyless `json:"keyless,omitempty"`
	PublicKey string   `json:"public_key,omitempty"` // PEM file
}

// Keyless matches the certificate Sigstore's Fulcio issued for a CI
// identity. One of Identity and IdentityRegexp is set.
type Keyless struct {
	Issuer         string `json:"issuer"`
	Identity       string `json:"identity,omitempty"`
	IdentityRegexp string `json:"identity_regexp,omitempty"`
}

// PluginsDir returns where plugins are installed.
func (c *Config) PluginsDir(stateDir string) string {
	if c != nil && c.Dir != "" {
		return c.Dir
	}
	return filepath.Join(stateDir, "plugins")
}

// Publisher returns the trust entry with the given name.
func (c *Config) Publisher(name string) (*Publisher, bool) {
	if c == nil {
		return nil, false
	}
	for i := range c.Trust {
		if c.Trust[i].Name == name {
			return &c.Trust[i], true
		}
	}
	return nil, false
}

// Validate returns the problems in c, one per string.
func (c *Config) Validate() []string {
	var p []string
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		p = append(p, "plugins.dir must be absolute")
	}
	if c.TrustedRoot != "" && !filepath.IsAbs(c.TrustedRoot) {
		p = append(p, "plugins.trusted_root must be absolute")
	}
	seen := map[string]bool{}
	for _, t := range c.Trust {
		prefix := "plugins.trust " + t.Name + ": "
		switch {
		case !ValidName(t.Name):
			p = append(p, fmt.Sprintf("plugins.trust: name %q must be lower case letters, digits and dashes", t.Name))
		case seen[t.Name]:
			p = append(p, "plugins.trust: duplicate name "+t.Name)
		case (t.Keyless == nil) == (t.PublicKey == ""):
			p = append(p, prefix+"set exactly one of keyless and public_key")
		case t.PublicKey != "" && !filepath.IsAbs(t.PublicKey):
			p = append(p, prefix+"public_key must be an absolute path")
		case t.Keyless != nil:
			p = append(p, t.Keyless.validate(prefix)...)
		}
		seen[t.Name] = true
	}
	return p
}

func (k *Keyless) validate(prefix string) []string {
	switch {
	case !strings.HasPrefix(k.Issuer, "https://"):
		return []string{prefix + "keyless.issuer must be an https URL"}
	case (k.Identity == "") == (k.IdentityRegexp == ""):
		return []string{prefix + "set exactly one of keyless.identity and keyless.identity_regexp"}
	case k.IdentityRegexp != "":
		if !strings.HasPrefix(k.IdentityRegexp, "^") {
			// Unanchored, https://github.com/org/repo/ would also match
			// https://evil.example/https://github.com/org/repo/.
			return []string{prefix + "keyless.identity_regexp must start with ^"}
		}
		if _, err := regexp.Compile(k.IdentityRegexp); err != nil {
			return []string{prefix + "keyless.identity_regexp: " + err.Error()}
		}
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidName reports whether s can name a plugin or a trust entry.
func ValidName(s string) bool { return nameRE.MatchString(s) }

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// ManifestFile is the name of the manifest at the root of a package.
const ManifestFile = "plugin.yaml"

// Manifest is plugin.yaml.
type Manifest struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Protocol int      `json:"protocol"`
	Kinds    []string `json:"kinds"`
	// Executable is the path of the plugin inside the package, with forward
	// slashes.
	Executable  string `json:"executable"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	// Permissions says in plain words what the plugin needs on the host and
	// in the systems it talks to.
	Permissions []string `json:"permissions,omitempty"`
}

// ParseManifest reads and checks plugin.yaml.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.UnmarshalStrict(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	var p []string
	if !ValidName(m.Name) {
		p = append(p, fmt.Sprintf("name %q must be lower case letters, digits and dashes", m.Name))
	}
	if !versionRE.MatchString(m.Version) {
		p = append(p, fmt.Sprintf("version %q must be semantic (1.2.3)", m.Version))
	}
	if m.Protocol != plugin.Protocol {
		p = append(p, fmt.Sprintf("protocol %d is not supported (want %d)", m.Protocol, plugin.Protocol))
	}
	if len(m.Kinds) == 0 {
		p = append(p, "kinds is required")
	}
	for _, k := range m.Kinds {
		if !slices.Contains(Kinds, k) {
			p = append(p, "unknown kind "+k)
		}
	}
	if !fs.ValidPath(m.Executable) || m.Executable == "." || strings.Contains(m.Executable, `\`) {
		p = append(p, fmt.Sprintf("executable %q must be a relative path inside the package", m.Executable))
	}
	if len(p) > 0 {
		return nil, fmt.Errorf("%s: %s", ManifestFile, strings.Join(p, "; "))
	}
	return &m, nil
}

// Kinds are the plugin kinds an agent runs.
var Kinds = []string{plugin.KindDNSSolver, plugin.KindDeployTarget, plugin.KindDiscovery}

// RecordFile is the install record inside a plugin's version directory.
const RecordFile = "install.json"

// Record is written by certloom-plugin after a package verified.
type Record struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Kinds   []string `json:"kinds"`
	// Executable is the absolute path of the installed plugin.
	Executable       string `json:"executable"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArchiveSHA256    string `json:"archive_sha256"`
	// Trust names the trust entry that matched; Signer is the certificate
	// identity (keyless) or the key fingerprint.
	Trust       string    `json:"trust"`
	Signer      string    `json:"signer"`
	InstalledAt time.Time `json:"installed_at"`
}

// VersionDir is where one version of a plugin is unpacked.
func VersionDir(pluginsDir, name, version string) string {
	return filepath.Join(pluginsDir, name, version)
}

// Load returns every install record under dir, sorted by name and then by
// version, newest first. A missing dir means no plugins.
func Load(dir string) ([]Record, error) {
	names, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, n := range names {
		if !n.IsDir() || !ValidName(n.Name()) {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(dir, n.Name()))
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			b, err := os.ReadFile(filepath.Join(dir, n.Name(), v.Name(), RecordFile))
			if errors.Is(err, fs.ErrNotExist) {
				continue // an install in progress or removed by hand
			}
			if err != nil {
				return nil, err
			}
			var r Record
			if err := json.Unmarshal(b, &r); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", n.Name(), v.Name(), err)
			}
			if r.Name != n.Name() || r.Version != v.Name() {
				return nil, fmt.Errorf("%s/%s: record names %s %s", n.Name(), v.Name(), r.Name, r.Version)
			}
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Record) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return -CompareVersions(a.Version, b.Version)
	})
	return out, nil
}

// Find returns the record for ref, which is a name or name@version. Without
// a version the newest installed one is used.
func Find(records []Record, ref string) (*Record, error) {
	name, version, _ := strings.Cut(ref, "@")
	for i := range records {
		r := &records[i]
		if r.Name == name && (version == "" || r.Version == version) {
			return r, nil // records are sorted newest first
		}
	}
	if version != "" {
		return nil, fmt.Errorf("plugin %s version %s is not installed", name, version)
	}
	return nil, fmt.Errorf("plugin %s is not installed", name)
}

// CompareVersions orders semantic versions; a pre-release sorts before its
// release. Malformed versions compare as strings.
func CompareVersions(a, b string) int {
	ac, apre, _ := strings.Cut(a, "-")
	bc, bpre, _ := strings.Cut(b, "-")
	as, bs := strings.Split(ac, "."), strings.Split(bc, ".")
	if len(as) != 3 || len(bs) != 3 {
		return strings.Compare(a, b)
	}
	for i := range 3 {
		var x, y int
		if _, err := fmt.Sscan(as[i], &x); err != nil {
			return strings.Compare(a, b)
		}
		if _, err := fmt.Sscan(bs[i], &y); err != nil {
			return strings.Compare(a, b)
		}
		if x != y {
			return x - y
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}
