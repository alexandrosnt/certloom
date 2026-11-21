package checks

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// Observation checks: IIS binding drift (ADR-0022) and Kubernetes
// conditions (ADR-0023).
const (
	CheckIISBindingDrift    = "iis_binding_drift"
	CheckK8sCertNotReady    = "k8s_certificate_not_ready"
	CheckK8sRenewalOverdue  = "k8s_renewal_overdue"
	CheckK8sIssuerNotReady  = "k8s_issuer_not_ready"
	CheckK8sRequestFailed   = "k8s_request_failed"
	CheckK8sBundleNotSynced = "k8s_bundle_not_synced"
)

func init() {
	for _, c := range []string{CheckIISBindingDrift, CheckK8sCertNotReady, CheckK8sRenewalOverdue, CheckK8sIssuerNotReady,
		CheckK8sRequestFailed, CheckK8sBundleNotSynced} {
		checkVersions[c] = 1
	}
}

// ObservedBinding is a managed IIS binding as the agent last saw it.
type ObservedBinding struct {
	Binding string
	// InSite is false when the site no longer has the https binding.
	InSite     bool
	CertHash   string // HTTP.sys thumbprint, empty without an entry
	CertSHA256 string // empty when the certificate is not in the store
}

// IISBindingDrift reports managed bindings that do not serve the
// deployment's current certificate (current is its SHA-256).
func IISBindingDrift(current string, bindings []ObservedBinding) []Finding {
	var problems []string
	sev := Warning
	for _, b := range bindings {
		switch {
		case !b.InSite:
			problems = append(problems, b.Binding+": binding removed from the site")
		case b.CertHash == "":
			problems = append(problems, b.Binding+": HTTP.sys has no certificate for it")
			sev = Critical
		case b.CertSHA256 == "":
			problems = append(problems, b.Binding+": bound certificate "+b.CertHash+" is not in the certificate store")
			sev = Critical
		case current != "" && b.CertSHA256 != current:
			problems = append(problems, b.Binding+": serves "+b.CertSHA256[:16]+"..., not the deployment's current certificate")
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	f := mk(CheckIISBindingDrift, sev, "IIS binding drift: "+strings.Join(problems, "; "),
		"Find out who changed the binding (IIS Manager, another ACME client), then run a renewal or roll back so certloom and IIS agree.")
	f.Fingerprint = fingerprint(CheckIISBindingDrift, problems...)
	return []Finding{f}
}

func condition(conds []agentproto.KubeCondition, typ string) *agentproto.KubeCondition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}

// KubeCertificate checks a cert-manager Certificate. notReadyFor is how long
// Ready may be False before it is reported (default 1h).
func KubeCertificate(c agentproto.KubeCert, now time.Time, notReadyFor time.Duration) []Finding {
	if notReadyFor == 0 {
		notReadyFor = time.Hour
	}
	id := c.Namespace + "/" + c.Name
	var out []Finding
	if r := condition(c.Conditions, "Ready"); r != nil && r.Status == "False" {
		since, err := time.Parse(time.RFC3339, r.LastTransitionTime)
		if err != nil || now.Sub(since) >= notReadyFor {
			f := mk(CheckK8sCertNotReady, Warning, fmt.Sprintf("Certificate %s is not Ready: %s %s", id, r.Reason, r.Message),
				"kubectl describe certificate -n "+c.Namespace+" "+c.Name)
			f.Fingerprint = fingerprint(CheckK8sCertNotReady, id, r.Reason)
			out = append(out, f)
		}
	}
	if rt, err := time.Parse(time.RFC3339, c.RenewalTime); err == nil && now.Sub(rt) > time.Hour {
		f := mk(CheckK8sRenewalOverdue, Warning, fmt.Sprintf("Certificate %s was due for renewal at %s", id, c.RenewalTime),
			"Check cert-manager's logs and the latest CertificateRequest for this Certificate.")
		f.Fingerprint = fingerprint(CheckK8sRenewalOverdue, id, c.RenewalTime)
		out = append(out, f)
	}
	if c.RequestFailed != "" {
		f := mk(CheckK8sRequestFailed, Warning, fmt.Sprintf("CertificateRequest %s/%s for %s will not be issued: %s", c.Namespace, c.RequestName, id, c.RequestFailed),
			"kubectl describe certificaterequest -n "+c.Namespace+" "+c.RequestName)
		f.Fingerprint = fingerprint(CheckK8sRequestFailed, id, c.RequestName)
		out = append(out, f)
	}
	return out
}

// KubeIssuer checks an Issuer or ClusterIssuer that certificates use.
func KubeIssuer(is agentproto.KubeIssuer, users int) []Finding {
	r := condition(is.Conditions, "Ready")
	if r != nil && r.Status == "True" {
		return nil
	}
	reason := "no Ready condition"
	if r != nil {
		reason = strings.TrimSpace(r.Reason + " " + r.Message)
	}
	name := is.Name
	if is.Namespace != "" {
		name = is.Namespace + "/" + is.Name
	}
	f := mk(CheckK8sIssuerNotReady, Warning, fmt.Sprintf("Issuer %s (used by %d certificates) is not Ready: %s", name, users, reason),
		"Renewals through this issuer fail until it is Ready; check its credentials and ACME account.")
	f.Fingerprint = fingerprint(CheckK8sIssuerNotReady, name)
	return []Finding{f}
}

// KubeBundle checks a trust-manager Bundle.
func KubeBundle(b agentproto.KubeBundle) []Finding {
	if r := condition(b.Conditions, "Synced"); r != nil && r.Status == "True" {
		return nil
	}
	f := mk(CheckK8sBundleNotSynced, Warning, fmt.Sprintf("Bundle %s is not Synced; consumers may hold an outdated trust store", b.Name),
		"kubectl describe bundle "+b.Name)
	f.Fingerprint = fingerprint(CheckK8sBundleNotSynced, b.Name)
	return []Finding{f}
}
