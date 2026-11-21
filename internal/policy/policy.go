// Package policy defines the versioned, schema-validated monitoring policy
// (`certloom policy validate|plan|apply`).
//
// Security-sensitive settings may only be made stricter than the defaults:
// a policy cannot lower the minimum key size, for example. Flexibility must
// not silently weaken safety controls.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/checks"
	"sigs.k8s.io/yaml"
)

// APIVersion and Kind identify the document type.
const (
	APIVersion = "certloom/v1"
	Kind       = "MonitoringPolicy"
)

// Duration accepts "30d", "12h", "90m" in YAML/JSON.
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30d\" or \"12h\"")
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(FormatDuration(time.Duration(d)))
}

// ParseDuration parses Go durations plus a "d" (day) suffix.
func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		v, err := strconv.Atoi(n)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(v) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return v, nil
}

// FormatDuration renders whole days as "Nd".
func FormatDuration(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// Document is a policy file.
type Document struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Description string `json:"description,omitempty"`
	} `json:"metadata,omitempty"`
	Spec Spec `json:"spec"`
}

// Spec holds the tunables. Zero values mean "use the default".
type Spec struct {
	Expiry struct {
		Warning  Duration `json:"warning,omitempty"`
		Critical Duration `json:"critical,omitempty"`
	} `json:"expiry,omitempty"`
	Keys struct {
		MinRSABits   int `json:"minRSABits,omitempty"`
		MinECDSABits int `json:"minECDSABits,omitempty"`
	} `json:"keys,omitempty"`
	Probing struct {
		FailuresBeforeAlert int `json:"failuresBeforeAlert,omitempty"`
	} `json:"probing,omitempty"`
	Retention struct {
		Observations Duration `json:"observations,omitempty"`
	} `json:"retention,omitempty"`
	Escalation struct {
		// After: re-notify unacknowledged warning/critical alerts after this long.
		After Duration `json:"after,omitempty"`
		// Channels: channel names to escalate to; empty = all enabled channels.
		Channels []string `json:"channels,omitempty"`
	} `json:"escalation,omitempty"`
	Approvals struct {
		// Deployments is "optional" (default) or "required". When required,
		// a new or changed deployment spec renews only after someone other
		// than the requester approves it.
		Deployments string `json:"deployments,omitempty"`
		// ExpireAfter: an undecided request expires after this long.
		ExpireAfter Duration `json:"expireAfter,omitempty"`
		// Channels: channel names for approval requests, decisions and
		// renewals blocked on approval; empty = all enabled channels.
		Channels []string `json:"channels,omitempty"`
	} `json:"approvals,omitempty"`
}

// Defaults.
const (
	ApprovalOptional            = "optional"
	ApprovalRequired            = "required"
	DefaultObservationRetention = 30 * 24 * time.Hour
)

// Default returns the built-in policy.
func Default() *Document {
	d := &Document{APIVersion: APIVersion, Kind: Kind}
	d.Metadata.Description = "built-in defaults"
	d.Spec.Expiry.Warning = Duration(30 * 24 * time.Hour)
	d.Spec.Expiry.Critical = Duration(7 * 24 * time.Hour)
	d.Spec.Keys.MinRSABits = 2048
	d.Spec.Keys.MinECDSABits = 256
	d.Spec.Probing.FailuresBeforeAlert = 3
	d.Spec.Retention.Observations = Duration(DefaultObservationRetention)
	d.Spec.Approvals.Deployments = ApprovalOptional
	d.Spec.Approvals.ExpireAfter = Duration(7 * 24 * time.Hour)
	return d
}

// Parse decodes YAML or JSON strictly (unknown fields are errors), fills
// defaults and validates.
func Parse(src []byte) (*Document, error) {
	if len(src) > 64<<10 {
		return nil, errors.New("policy document larger than 64 KiB")
	}
	j, err := yaml.YAMLToJSON(src)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	d.fill()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

func (d *Document) fill() {
	def := Default()
	s := &d.Spec
	if s.Expiry.Warning == 0 {
		s.Expiry.Warning = def.Spec.Expiry.Warning
	}
	if s.Expiry.Critical == 0 {
		s.Expiry.Critical = def.Spec.Expiry.Critical
	}
	if s.Keys.MinRSABits == 0 {
		s.Keys.MinRSABits = def.Spec.Keys.MinRSABits
	}
	if s.Keys.MinECDSABits == 0 {
		s.Keys.MinECDSABits = def.Spec.Keys.MinECDSABits
	}
	if s.Probing.FailuresBeforeAlert == 0 {
		s.Probing.FailuresBeforeAlert = def.Spec.Probing.FailuresBeforeAlert
	}
	if s.Retention.Observations == 0 {
		s.Retention.Observations = def.Spec.Retention.Observations
	}
	if s.Approvals.Deployments == "" {
		s.Approvals.Deployments = def.Spec.Approvals.Deployments
	}
	if s.Approvals.ExpireAfter == 0 {
		s.Approvals.ExpireAfter = def.Spec.Approvals.ExpireAfter
	}
}

// ValidationError lists every problem found.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return "invalid policy: " + strings.Join(e.Problems, "; ") }

// Validate checks semantic rules.
func (d *Document) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	if d.APIVersion != APIVersion {
		add("apiVersion must be %q", APIVersion)
	}
	if d.Kind != Kind {
		add("kind must be %q", Kind)
	}
	s := d.Spec
	w, c := time.Duration(s.Expiry.Warning), time.Duration(s.Expiry.Critical)
	if c <= 0 || w <= c {
		add("expiry.warning (%s) must be greater than expiry.critical (%s) and both positive", FormatDuration(w), FormatDuration(c))
	}
	if w > 365*24*time.Hour {
		add("expiry.warning must be at most 365d")
	}
	if s.Keys.MinRSABits < 2048 {
		add("keys.minRSABits may not be lowered below 2048")
	}
	if s.Keys.MinRSABits > 16384 {
		add("keys.minRSABits must be at most 16384")
	}
	if s.Keys.MinECDSABits < 256 {
		add("keys.minECDSABits may not be lowered below 256")
	}
	if s.Keys.MinECDSABits > 521 {
		add("keys.minECDSABits must be at most 521")
	}
	if f := s.Probing.FailuresBeforeAlert; f < 1 || f > 20 {
		add("probing.failuresBeforeAlert must be between 1 and 20")
	}
	if r := time.Duration(s.Retention.Observations); r < 24*time.Hour || r > 3650*24*time.Hour {
		add("retention.observations must be between 1d and 3650d")
	}
	if a := time.Duration(s.Escalation.After); a != 0 && a < 15*time.Minute {
		add("escalation.after must be at least 15m (or omitted to disable escalation)")
	}
	if a := s.Approvals.Deployments; a != ApprovalOptional && a != ApprovalRequired {
		add("approvals.deployments must be %q or %q", ApprovalOptional, ApprovalRequired)
	}
	if e := time.Duration(s.Approvals.ExpireAfter); e < time.Hour || e > 30*24*time.Hour {
		add("approvals.expireAfter must be between 1h and 30d")
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Checks converts to the checks package's thresholds.
func (d *Document) Checks() checks.Policy {
	return checks.Policy{
		ExpiryWarning:        time.Duration(d.Spec.Expiry.Warning),
		ExpiryCritical:       time.Duration(d.Spec.Expiry.Critical),
		MinRSABits:           d.Spec.Keys.MinRSABits,
		MinECDSABits:         d.Spec.Keys.MinECDSABits,
		ProbeFailuresToAlert: d.Spec.Probing.FailuresBeforeAlert,
	}
}

// YAML renders the document (for `certloom policy get`).
func (d *Document) YAML() ([]byte, error) {
	j, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return yaml.JSONToYAML(j)
}
