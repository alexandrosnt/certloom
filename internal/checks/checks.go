// Package checks turns certificates and endpoint observations into findings.
// All functions are pure: same inputs, same findings (docs/domain-model.md).
package checks

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/probe"
)

// Severity of a finding.
type Severity string

// Severities, ordered.
const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank orders severities for comparison.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Check identifiers (stable; used as keys in storage and alert routing).
const (
	CheckExpiry             = "expiry"
	CheckNotYetValid        = "not_yet_valid"
	CheckHostnameMismatch   = "hostname_mismatch"
	CheckChainIncomplete    = "chain_incomplete"
	CheckUntrusted          = "untrusted"
	CheckWeakKey            = "weak_key"
	CheckWeakSignature      = "weak_signature"
	CheckFingerprintChanged = "fingerprint_changed"
	CheckLineageMismatch    = "lineage_mismatch"
	CheckProbeFailed        = "probe_failed"
	// Issuer checks (ADR-0019).
	CheckEABPool        = "eab_pool"
	CheckEABKeyExpiring = "eab_key_expiring"
)

// KnownCheck reports whether id is one of the check identifiers above.
func KnownCheck(id string) bool { return checkVersions[id] > 0 }

// Finding is one check result.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	// Remediation is a short, actionable hint for the owner.
	Remediation string `json:"remediation,omitempty"`
	// Fingerprint identifies the condition behind the finding (which
	// certificate, which failure), so an exception accepted for one condition
	// does not cover a different one under the same check.
	Fingerprint string `json:"fingerprint"`
}

func mk(check string, sev Severity, msg, remediation string) Finding {
	return Finding{Check: check, Severity: sev, Message: msg, Remediation: remediation}
}

// checkVersions holds each check's definition version. Bump a version when
// a check starts to mean something different: fingerprints change with it,
// so existing exceptions stop covering the new meaning.
var checkVersions = map[string]int{
	CheckExpiry: 1, CheckNotYetValid: 1, CheckHostnameMismatch: 1, CheckChainIncomplete: 1, CheckUntrusted: 1, CheckWeakKey: 1,
	CheckWeakSignature: 1, CheckFingerprintChanged: 1, CheckLineageMismatch: 1, CheckProbeFailed: 1,
	CheckEABPool: 1, CheckEABKeyExpiring: 1,
	CheckCAExpiring: 1, CheckChainOutlived: 1, CheckChainCertExpiring: 1,
}

// Version returns a check's definition version (0 for unknown checks).
func Version(check string) int { return checkVersions[check] }

// fingerprint hashes the check, its version and the facts that define the
// condition.
func fingerprint(check string, facts ...string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s/%d", check, Version(check))
	for _, f := range facts {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Policy holds tunable thresholds. Zero values select defaults.
type Policy struct {
	ExpiryWarning        time.Duration // default 30d, capped at lifetime/3
	ExpiryCritical       time.Duration // default 7d, capped at lifetime/10
	MinRSABits           int           // default 2048
	MinECDSABits         int           // default 256
	ProbeFailuresToAlert int           // default 3
	CAExpiryWarning      time.Duration // default 180d
	CAExpiryCritical     time.Duration // default 30d
}

func (p Policy) withDefaults() Policy {
	if p.ExpiryWarning == 0 {
		p.ExpiryWarning = 30 * 24 * time.Hour
	}
	if p.ExpiryCritical == 0 {
		p.ExpiryCritical = 7 * 24 * time.Hour
	}
	if p.MinRSABits == 0 {
		p.MinRSABits = 2048
	}
	if p.MinECDSABits == 0 {
		p.MinECDSABits = 256
	}
	if p.ProbeFailuresToAlert == 0 {
		p.ProbeFailuresToAlert = 3
	}
	if p.CAExpiryWarning == 0 {
		p.CAExpiryWarning = 180 * 24 * time.Hour
	}
	if p.CAExpiryCritical == 0 {
		p.CAExpiryCritical = 30 * 24 * time.Hour
	}
	return p
}

// ExpiryThresholds returns the warning and critical lead times for a
// certificate, scaled down for short-lived certificates so that a 6-day
// certificate is not permanently "expiring".
func (p Policy) ExpiryThresholds(lifetime time.Duration) (warn, crit time.Duration) {
	p = p.withDefaults()
	warn, crit = p.ExpiryWarning, p.ExpiryCritical
	if lifetime > 0 {
		warn = min(warn, lifetime/3)
		crit = min(crit, lifetime/10)
	}
	return warn, crit
}

// Certificate evaluates properties intrinsic to one certificate.
func Certificate(c *certparse.Certificate, now time.Time, pol Policy) []Finding {
	pol = pol.withDefaults()
	var out []Finding
	remaining := c.NotAfter.Sub(now)
	warn, crit := pol.ExpiryThresholds(c.Lifetime())
	switch {
	case remaining <= 0:
		out = append(out, mk(CheckExpiry, Critical,
			fmt.Sprintf("expired %s ago (%s)", human(-remaining), c.NotAfter.Format(time.RFC3339)),
			"Replace the certificate now; clients are rejecting it."))
	case remaining <= crit:
		out = append(out, mk(CheckExpiry, Critical,
			fmt.Sprintf("expires in %s (%s)", human(remaining), c.NotAfter.Format(time.RFC3339)),
			"Renew immediately and verify the new certificate is served."))
	case remaining <= warn:
		out = append(out, mk(CheckExpiry, Warning,
			fmt.Sprintf("expires in %s (%s)", human(remaining), c.NotAfter.Format(time.RFC3339)),
			"Confirm renewal is scheduled or renew now."))
	}
	if now.Before(c.NotBefore) {
		out = append(out, mk(CheckNotYetValid, Critical,
			fmt.Sprintf("not valid until %s", c.NotBefore.Format(time.RFC3339)),
			"Check the issuing system's clock and the served certificate."))
	}
	switch c.KeyAlgorithm {
	case "RSA":
		if c.KeyBits < pol.MinRSABits {
			out = append(out, mk(CheckWeakKey, Critical,
				fmt.Sprintf("RSA key is %d bits (policy minimum %d)", c.KeyBits, pol.MinRSABits),
				"Reissue with a stronger key (RSA-2048+ or ECDSA P-256)."))
		}
	case "ECDSA":
		if c.KeyBits < pol.MinECDSABits {
			out = append(out, mk(CheckWeakKey, Critical,
				fmt.Sprintf("ECDSA key is %d bits (policy minimum %d)", c.KeyBits, pol.MinECDSABits),
				"Reissue with ECDSA P-256 or stronger."))
		}
	}
	// Signature on a self-signed trust anchor is not security-relevant.
	if !c.SelfSigned {
		sig := strings.ToUpper(c.SignatureAlgorithm)
		if strings.Contains(sig, "SHA1") || strings.Contains(sig, "MD5") || strings.Contains(sig, "MD2") {
			out = append(out, mk(CheckWeakSignature, Critical,
				"signed with "+c.SignatureAlgorithm,
				"Reissue; SHA-1/MD5 signatures are rejected by modern clients."))
		}
	}
	// These conditions are fixed by the certificate itself.
	for i := range out {
		out[i].Fingerprint = fingerprint(out[i].Check, c.SHA256)
	}
	return out
}

// EndpointInput is everything needed to evaluate one endpoint observation.
type EndpointInput struct {
	Observation *probe.Observation
	// ExpectedName is the hostname clients use (SNI or host). Empty skips the check.
	ExpectedName string
	// PreviousLeaf is the leaf SHA-256 from the last successful observation.
	PreviousLeaf string
	// ExpectedLeaf is the lineage's current certificate, if the endpoint is
	// bound to a lineage. Empty skips the lineage check.
	ExpectedLeaf string
	// Roots are the trust anchors; nil means the system pool.
	Roots              *x509.CertPool
	KnownIntermediates []*x509.Certificate
	// ConsecutiveFailures including this observation, if it failed.
	ConsecutiveFailures int
	Now                 time.Time
	Policy              Policy
}

// Endpoint evaluates an observation: reachability, trust, hostname, chain
// completeness, fingerprint change, lineage match, plus the leaf's own checks.
func Endpoint(in EndpointInput) []Finding {
	pol := in.Policy.withDefaults()
	o := in.Observation
	if o.ErrorClass != "" {
		if in.ConsecutiveFailures >= pol.ProbeFailuresToAlert {
			f := mk(CheckProbeFailed, Warning,
				fmt.Sprintf("probe failed %d times in a row: %s (%s)", in.ConsecutiveFailures, o.ErrorClass, o.Error),
				"Check that the endpoint is up and reachable from the prober, and that the scope allows it.")
			// A different kind of failure is a different condition.
			f.Fingerprint = fingerprint(CheckProbeFailed, o.ErrorClass)
			return []Finding{f}
		}
		return nil
	}
	leaf := o.Leaf()
	var out []Finding
	presented := make([]*x509.Certificate, 0, len(o.Chain))
	for _, c := range o.Chain {
		presented = append(presented, c.X509)
	}
	vr := certparse.Verify(leaf.X509, presented, certparse.VerifyOptions{
		Roots: in.Roots, At: in.Now, DNSName: in.ExpectedName, KnownIntermediates: in.KnownIntermediates,
	})
	switch {
	case vr.Trusted && !vr.ChainComplete:
		out = append(out, mk(CheckChainIncomplete, Warning,
			"server does not send all intermediate certificates",
			"Configure the full chain (leaf + intermediates) on the server; some clients will fail otherwise."))
	case !vr.Trusted && vr.ErrorClass == "unknown_authority":
		out = append(out, mk(CheckUntrusted, Critical,
			"no trusted path to a configured trust anchor: "+vr.Error,
			"Serve a certificate from a trusted CA, include missing intermediates, or add the private root to the trust store if intended."))
	}
	if vr.HostnameChecked && !vr.HostnameOK {
		out = append(out, mk(CheckHostnameMismatch, Critical,
			fmt.Sprintf("certificate does not cover %q (SANs: %s)", in.ExpectedName, strings.Join(leaf.DNSNames, ", ")),
			"Serve a certificate whose SANs include this hostname, or fix the SNI/vhost mapping."))
	}
	if in.PreviousLeaf != "" && in.PreviousLeaf != leaf.SHA256 {
		sev := Warning
		msg := fmt.Sprintf("served certificate changed from %s to %s", short(in.PreviousLeaf), short(leaf.SHA256))
		if in.ExpectedLeaf != "" && in.ExpectedLeaf == leaf.SHA256 {
			sev, msg = Info, msg+" (expected replacement)"
		}
		out = append(out, mk(CheckFingerprintChanged, sev, msg,
			"Confirm the change was intended."))
	}
	if in.ExpectedLeaf != "" && in.ExpectedLeaf != leaf.SHA256 {
		out = append(out, mk(CheckLineageMismatch, Critical,
			fmt.Sprintf("endpoint serves %s but its lineage expects %s", short(leaf.SHA256), short(in.ExpectedLeaf)),
			"Deploy the lineage's current certificate to this endpoint, or update the lineage binding."))
	}
	for i := range out {
		f := &out[i]
		switch f.Check {
		case CheckUntrusted:
			f.Fingerprint = fingerprint(f.Check, leaf.SHA256, vr.ErrorClass)
		case CheckHostnameMismatch:
			f.Fingerprint = fingerprint(f.Check, leaf.SHA256, strings.ToLower(in.ExpectedName))
		case CheckFingerprintChanged:
			f.Fingerprint = fingerprint(f.Check, in.PreviousLeaf, leaf.SHA256)
		case CheckLineageMismatch:
			f.Fingerprint = fingerprint(f.Check, leaf.SHA256, in.ExpectedLeaf)
		default:
			f.Fingerprint = fingerprint(f.Check, leaf.SHA256)
		}
	}
	out = append(out, servedChain(o.Chain, in.Now)...)
	out = append(out, Certificate(leaf, in.Now, pol)...)
	return out
}

func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

func human(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

// New builds a finding for checks evaluated outside this package; facts
// define the condition, as for the built-in checks.
func New(check string, sev Severity, msg, remediation string, facts ...string) Finding {
	f := mk(check, sev, msg, remediation)
	f.Fingerprint = fingerprint(check, facts...)
	return f
}
