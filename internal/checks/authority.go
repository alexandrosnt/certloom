package checks

import (
	"fmt"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
)

// CA inventory checks (ADR-0029).
const (
	CheckCAExpiring        = "ca_expiring"
	CheckChainOutlived     = "chain_outlived"
	CheckChainCertExpiring = "chain_cert_expiring"
)

// Served-chain and outlived-chain thresholds are fixed: by then the chain is
// broken for some clients whatever the policy says.
const (
	chainCritical       = 30 * 24 * time.Hour
	servedChainWarning  = 30 * 24 * time.Hour
	servedChainCritical = 7 * 24 * time.Hour
)

// AuthorityInput describes one CA authority in use.
type AuthorityInput struct {
	Key     string
	Subject string
	Root    bool
	// Expiry is the end of the longest valid path through the authority.
	Expiry time.Time
	// PubliclyTrusted authorities are rotated by their CA; expiry is then
	// informational and chain_outlived carries the actionable risk.
	PubliclyTrusted bool
	Now             time.Time
	Policy          Policy
}

// Authority evaluates an authority's expiry.
func Authority(in AuthorityInput) []Finding {
	pol := in.Policy.withDefaults()
	remaining := in.Expiry.Sub(in.Now)
	kind := "intermediate CA"
	if in.Root {
		kind = "root CA"
	}
	var f Finding
	switch {
	case remaining <= 0:
		f = mk(CheckCAExpiring, Critical, fmt.Sprintf("%s %s expired %s ago (%s)", kind, in.Subject, human(-remaining), in.Expiry.Format(time.RFC3339)),
			"Move every certificate under this CA to a valid hierarchy now: `certloom ca impact` lists them.")
	case remaining <= pol.CAExpiryCritical:
		f = mk(CheckCAExpiring, Critical, fmt.Sprintf("%s %s expires in %s (%s)", kind, in.Subject, human(remaining), in.Expiry.Format(time.RFC3339)),
			"Roll the CA over and renew what depends on it: `certloom ca impact`, then `certloom ca renew-affected`.")
	case remaining <= pol.CAExpiryWarning:
		f = mk(CheckCAExpiring, Warning, fmt.Sprintf("%s %s expires in %s (%s)", kind, in.Subject, human(remaining), in.Expiry.Format(time.RFC3339)),
			"Plan the rollover: `certloom ca plan` shows what depends on this CA and by when.")
	default:
		return nil
	}
	if in.PubliclyTrusted {
		f.Severity = Info
		f.Remediation = "A public CA rotates its own hierarchy; watch chain_outlived findings for certificates that outlive it."
	}
	f.Fingerprint = fingerprint(CheckCAExpiring, in.Key, in.Expiry.UTC().Format(time.RFC3339))
	return []Finding{f}
}

// ChainOutlived reports a certificate that stays valid after every path
// above it has expired. chainExpiry is the issuing authority's expiry.
func ChainOutlived(c *certparse.Certificate, chainExpiry, now time.Time) []Finding {
	if c.IsCA || !c.NotAfter.After(chainExpiry) || !c.NotAfter.After(now) {
		return nil
	}
	left := chainExpiry.Sub(now)
	var f Finding
	switch {
	case left <= 0:
		f = mk(CheckChainOutlived, Critical, fmt.Sprintf("the CA chain above this certificate expired %s ago (%s)", human(-left), chainExpiry.Format(time.RFC3339)),
			"Renew from a valid hierarchy now; clients cannot build a path.")
	case left <= chainCritical:
		f = mk(CheckChainOutlived, Critical, fmt.Sprintf("the CA chain expires in %s (%s), before this certificate (%s)",
			human(left), chainExpiry.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
			"Renew before the chain expires, from the CA's successor hierarchy.")
	default:
		f = mk(CheckChainOutlived, Warning, fmt.Sprintf("the CA chain expires %s (%s), before this certificate (%s)",
			chainExpiry.Format("2006-01-02"), chainExpiry.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
			"Renew before the chain expires; `certloom ca renew-affected` renews every certificate under the CA.")
	}
	f.Fingerprint = fingerprint(CheckChainOutlived, c.SHA256, chainExpiry.UTC().Format(time.RFC3339))
	return []Finding{f}
}

// servedChain reports the CA certificate in a served chain that expires
// first, if it expires before the leaf and soon.
func servedChain(chain []*certparse.Certificate, now time.Time) []Finding {
	if len(chain) < 2 {
		return nil
	}
	leaf := chain[0]
	var soonest *certparse.Certificate
	for _, c := range chain[1:] {
		if !c.IsCA || !c.NotAfter.Before(leaf.NotAfter) {
			continue
		}
		if soonest == nil || c.NotAfter.Before(soonest.NotAfter) {
			soonest = c
		}
	}
	if soonest == nil {
		return nil
	}
	left := soonest.NotAfter.Sub(now)
	var f Finding
	switch {
	case left <= 0:
		f = mk(CheckChainCertExpiring, Critical, fmt.Sprintf("served chain contains %s, expired %s ago", soonest.Subject, human(-left)),
			"Serve the CA's current intermediate; download the chain again from the CA or renew.")
	case left <= servedChainCritical:
		f = mk(CheckChainCertExpiring, Critical, fmt.Sprintf("served chain contains %s, expiring in %s", soonest.Subject, human(left)),
			"Serve the CA's current intermediate; download the chain again from the CA or renew.")
	case left <= servedChainWarning:
		f = mk(CheckChainCertExpiring, Warning, fmt.Sprintf("served chain contains %s, expiring in %s", soonest.Subject, human(left)),
			"Serve the CA's current intermediate before it expires.")
	default:
		return nil
	}
	f.Fingerprint = fingerprint(CheckChainCertExpiring, leaf.SHA256, soonest.SHA256)
	return []Finding{f}
}
