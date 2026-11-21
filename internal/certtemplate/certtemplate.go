// Package certtemplate parses certificate template documents (ADR-0020): a
// named recipe of issuer, challenge, key algorithms and allowed names that
// deployments reference.
package certtemplate

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// APIVersion and Kind identify the document type.
const (
	APIVersion = "certloom/v1"
	Kind       = "CertificateTemplate"
)

// Document is a template file.
type Document struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	} `json:"metadata"`
	Spec Spec `json:"spec"`
}

// Spec is what a template fixes and allows.
type Spec struct {
	// Issuer is the issuer name.
	Issuer string `json:"issuer"`
	// Challenge is "http-01" (default) or "dns-01".
	Challenge string `json:"challenge,omitempty"`
	// KeyAlgorithms are allowed; the first is the default.
	KeyAlgorithms []string `json:"keyAlgorithms,omitempty"`
	SANs          struct {
		// Allowed are glob patterns; see NameAllowed.
		Allowed   []string `json:"allowed"`
		MaxNames  int      `json:"maxNames,omitempty"`
		Wildcards bool     `json:"wildcards,omitempty"`
	} `json:"sans"`
	// MaintenanceWindow is the default window for new deployments.
	MaintenanceWindow string `json:"maintenanceWindow,omitempty"`
}

// KnownKeyAlgorithms are the keys agents can generate.
var KnownKeyAlgorithms = []string{"ecdsa-p256"}

// DefaultMaxNames applies when sans.maxNames is not set.
const DefaultMaxNames = 100

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Parse decodes YAML or JSON strictly, fills defaults and validates.
func Parse(src []byte) (*Document, error) {
	if len(src) > 64<<10 {
		return nil, errors.New("template document larger than 64 KiB")
	}
	j, err := yaml.YAMLToJSON(src)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(j)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if d.Spec.Challenge == "" {
		d.Spec.Challenge = "http-01"
	}
	if len(d.Spec.KeyAlgorithms) == 0 {
		d.Spec.KeyAlgorithms = []string{KnownKeyAlgorithms[0]}
	}
	if d.Spec.SANs.MaxNames == 0 {
		d.Spec.SANs.MaxNames = DefaultMaxNames
	}
	for i, p := range d.Spec.SANs.Allowed {
		d.Spec.SANs.Allowed[i] = normName(p)
	}
	return &d, d.Validate()
}

// ValidationError lists every problem in a document.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid template: " + strings.Join(e.Problems, "; ")
}

// Validate checks the document. The issuer's existence is checked by the
// caller, which has the database.
func (d *Document) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	if d.APIVersion != APIVersion {
		add("apiVersion must be %q", APIVersion)
	}
	if d.Kind != Kind {
		add("kind must be %q", Kind)
	}
	if !nameRE.MatchString(d.Metadata.Name) {
		add("metadata.name must be lower-case letters, digits and dashes (max 63)")
	}
	s := d.Spec
	if strings.TrimSpace(s.Issuer) == "" {
		add("spec.issuer is required")
	}
	if s.Challenge != "http-01" && s.Challenge != "dns-01" {
		add("spec.challenge must be http-01 or dns-01")
	}
	for _, k := range s.KeyAlgorithms {
		if !slices.Contains(KnownKeyAlgorithms, k) {
			add("spec.keyAlgorithms: unsupported %q (supported: %s)", k, strings.Join(KnownKeyAlgorithms, ", "))
		}
	}
	if len(s.SANs.Allowed) == 0 {
		add("spec.sans.allowed needs at least one pattern")
	}
	for _, pat := range s.SANs.Allowed {
		if err := checkPattern(pat); err != nil {
			add("spec.sans.allowed %q: %v", pat, err)
		}
	}
	if s.SANs.MaxNames < 1 || s.SANs.MaxNames > DefaultMaxNames {
		add("spec.sans.maxNames must be between 1 and %d", DefaultMaxNames)
	}
	if s.SANs.Wildcards && s.Challenge != "dns-01" {
		add("spec.sans.wildcards needs challenge dns-01")
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// checkPattern accepts DNS names whose labels may contain one "*" each, with
// at least two labels so a pattern can never match a whole TLD.
func checkPattern(p string) error {
	labels := strings.Split(p, ".")
	if len(labels) < 2 {
		return errors.New("needs at least two labels")
	}
	for i, l := range labels {
		if strings.Count(l, "*") > 1 {
			return errors.New("at most one * per label")
		}
		if l == "*" && i == len(labels)-1 {
			return errors.New("the last label cannot be *")
		}
		plain := strings.Replace(l, "*", "x", 1)
		if !nameRE.MatchString(plain) {
			return fmt.Errorf("label %q is not a DNS label", l)
		}
	}
	if strings.Contains(labels[len(labels)-1], "*") {
		return errors.New("the top-level label cannot contain *")
	}
	return nil
}

// NameAllowed reports whether a requested name matches one of the patterns.
// "*" in a pattern matches one or more characters within a single label. A
// requested wildcard ("*.example.com") needs wildcards and must itself match
// a pattern, its "*" label standing for any one label.
func NameAllowed(name string, patterns []string, wildcards bool) bool {
	name = normName(name)
	if strings.HasPrefix(name, "*.") && !wildcards {
		return false
	}
	nl := strings.Split(name, ".")
	for _, p := range patterns {
		if matchLabels(nl, strings.Split(normName(p), ".")) {
			return true
		}
	}
	return false
}

func matchLabels(name, pat []string) bool {
	if len(name) != len(pat) {
		return false
	}
	for i := range name {
		if name[i] == "*" {
			// A wildcard name is only as wide as a pattern label that is a bare "*".
			if pat[i] != "*" {
				return false
			}
			continue
		}
		if !matchLabel(name[i], pat[i]) {
			return false
		}
	}
	return true
}

func matchLabel(l, p string) bool {
	pre, post, star := strings.Cut(p, "*")
	if !star {
		return l == p
	}
	return len(l) > len(pre)+len(post) && strings.HasPrefix(l, pre) && strings.HasSuffix(l, post)
}

// CheckNames returns the problems a list of names has under the template.
func (d *Document) CheckNames(sans []string) []string {
	var p []string
	if len(sans) > d.Spec.SANs.MaxNames {
		p = append(p, fmt.Sprintf("%d names, template allows %d", len(sans), d.Spec.SANs.MaxNames))
	}
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") && !d.Spec.SANs.Wildcards {
			p = append(p, fmt.Sprintf("wildcard %q not allowed by the template", s))
			continue
		}
		if !NameAllowed(s, d.Spec.SANs.Allowed, d.Spec.SANs.Wildcards) {
			p = append(p, fmt.Sprintf("name %q not allowed by the template", s))
		}
	}
	return p
}
