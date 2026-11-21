package checks

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// Cloud observation checks (ADR-0024). They are the same for every
// provider; the agent normalises renewal state.
const (
	CheckCloudRenewalFailing    = "cloud_renewal_failing"
	CheckCloudRenewalManual     = "cloud_renewal_manual"
	CheckCloudVersionNotAdopted = "cloud_version_not_adopted"
)

func init() {
	for _, c := range []string{CheckCloudRenewalFailing, CheckCloudRenewalManual, CheckCloudVersionNotAdopted} {
		checkVersions[c] = 1
	}
}

const (
	// cloudPendingFor is how long issuance may stay pending (DNS or HTTP
	// validation outstanding) before it is reported.
	cloudPendingFor = 72 * time.Hour
	// cloudAdoptGrace is how long consumers get to pick up a new version.
	cloudAdoptGrace = 24 * time.Hour
)

var cloudLabels = map[string]string{
	agentproto.CloudAWSACM:           "ACM certificate",
	agentproto.CloudAWSPCA:           "AWS Private CA",
	agentproto.CloudAzureKeyVault:    "Key Vault certificate",
	agentproto.CloudGCPCertManager:   "Certificate Manager certificate",
	agentproto.CloudGCPCAS:           "CA Service authority",
	agentproto.CloudCloudflareEdge:   "Cloudflare certificate pack",
	agentproto.CloudCloudflareOrigin: "Cloudflare Origin CA certificate",
}

// CloudLabel names an observed object for messages.
func CloudLabel(o agentproto.CloudObject) string {
	kind := cloudLabels[o.Provider]
	if kind == "" {
		kind = o.Provider
	}
	return kind + " " + o.ID
}

// CloudObject checks renewal of a certificate held by a cloud service.
// Expiry itself is checked on the certificate when the service returned it.
func CloudObject(o agentproto.CloudObject, now time.Time, pol Policy) []Finding {
	pol = pol.withDefaults()
	label := CloudLabel(o)
	notAfter, hasExpiry := parseTime(o.NotAfter)
	left := notAfter.Sub(now)
	var out []Finding
	switch {
	case o.Renewal == agentproto.RenewalFailed:
		sev := Warning
		if hasExpiry && left < pol.ExpiryWarning {
			sev = Critical
		}
		out = append(out, New(CheckCloudRenewalFailing, sev,
			fmt.Sprintf("%s: issuance or renewal failed%s", label, reasonSuffix(o.RenewalReason)),
			"Fix the cause in the provider's console (validation records, CAA, quota), then retry the request there.",
			o.ID, "failed", o.RenewalReason))
	case o.Renewal == agentproto.RenewalPending:
		since, ok := parseTime(o.RenewalSince)
		if ok && now.Sub(since) >= cloudPendingFor {
			out = append(out, New(CheckCloudRenewalFailing, Warning,
				fmt.Sprintf("%s: validation pending since %s%s", label, since.Format(time.DateOnly), reasonSuffix(o.RenewalReason)),
				"Check that the DNS or HTTP validation records the provider asks for are in place.",
				o.ID, "pending", o.RenewalSince))
		}
	case o.Managed && !o.CA && hasExpiry && left < pol.ExpiryCritical && left > 0:
		// The service should have renewed long before this.
		out = append(out, New(CheckCloudRenewalFailing, Critical,
			fmt.Sprintf("%s expires in %s and the service has not renewed it", label, human(left)),
			"Check renewal eligibility in the provider (in use, validation records still valid) or replace the certificate.",
			o.ID, "overdue", o.NotAfter))
	}
	if !o.Managed && !o.CA && hasExpiry && left < pol.ExpiryWarning && left > 0 {
		sev := Warning
		if left < pol.ExpiryCritical {
			sev = Critical
		}
		where := ""
		if len(o.InUseBy) > 0 {
			where = " (in use by " + strings.Join(firstN(o.InUseBy, 3), ", ") + ")"
		}
		out = append(out, New(CheckCloudRenewalManual, sev,
			fmt.Sprintf("%s expires in %s and is not renewed by the service%s", label, human(left), where),
			"Issue a replacement and import or upload it, or move the certificate to provider-managed renewal.",
			o.ID, o.NotAfter))
	}
	return out
}

// CloudVersionNotAdopted reports endpoints that still serve the previous
// version of a versioned certificate (Key Vault) after the grace period.
func CloudVersionNotAdopted(o agentproto.CloudObject, now time.Time, stale []string) []Finding {
	if len(stale) == 0 || len(o.Versions) == 0 {
		return nil
	}
	newest, _ := parseTime(o.Versions[0].Created)
	if now.Sub(newest) < cloudAdoptGrace {
		return nil
	}
	stale = slices.Sorted(slices.Values(stale))
	return []Finding{New(CheckCloudVersionNotAdopted, Warning,
		fmt.Sprintf("%s has a new version since %s, but %s still serve the previous one", CloudLabel(o), newest.Format(time.DateOnly),
			strings.Join(firstN(stale, 5), ", ")),
		"Restart or reconfigure the consumers so they load the current version.",
		append([]string{o.ID, o.Versions[0].ID}, stale...)...)}
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return ": " + r
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(slices.Clone(s[:n]), fmt.Sprintf("%d more", len(s)-n))
}
