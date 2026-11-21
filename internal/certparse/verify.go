package certparse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

// VerifyOptions configure chain verification.
type VerifyOptions struct {
	// Roots are the trust anchors. nil means the host system pool.
	Roots *x509.CertPool
	// At is the verification time; zero means now.
	At time.Time
	// DNSName, if set, is checked against the leaf SANs (also accepts IP literals).
	DNSName string
	// KnownIntermediates are intermediates the inventory already holds. If the
	// presented chain fails but succeeds with these, the result is Trusted with
	// ChainComplete=false (the server omitted an intermediate).
	KnownIntermediates []*x509.Certificate
}

// VerifyResult describes the outcome of verifying a presented chain.
// It never fetches anything over the network (no AIA chasing; threat model T2).
type VerifyResult struct {
	Trusted bool `json:"trusted"`
	// Chain is the best verified chain as SHA-256 fingerprints, leaf first.
	Chain []string `json:"chain,omitempty"`
	// ChainComplete is true if the presented certificates alone (plus roots)
	// build a path; false means a needed intermediate was not presented.
	ChainComplete bool `json:"chain_complete"`
	// HostnameChecked/HostnameOK describe the SAN check when DNSName was given.
	HostnameChecked bool   `json:"hostname_checked"`
	HostnameOK      bool   `json:"hostname_ok"`
	Expired         bool   `json:"expired"`
	NotYetValid     bool   `json:"not_yet_valid"`
	Error           string `json:"error,omitempty"`
	// ErrorClass is a stable classifier: unknown_authority, expired,
	// not_yet_valid, hostname, invalid, or "".
	ErrorClass string `json:"error_class,omitempty"`
}

// Verify verifies leaf against roots using the presented intermediates.
func Verify(leaf *x509.Certificate, presented []*x509.Certificate, o VerifyOptions) VerifyResult {
	at := o.At
	if at.IsZero() {
		at = time.Now()
	}
	res := VerifyResult{
		Expired:     at.After(leaf.NotAfter),
		NotYetValid: at.Before(leaf.NotBefore),
	}
	inter := x509.NewCertPool()
	for _, c := range presented {
		if !c.Equal(leaf) {
			inter.AddCert(c)
		}
	}
	vo := x509.VerifyOptions{
		Roots:         o.Roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chains, err := leaf.Verify(vo)
	complete := err == nil
	if err != nil && len(o.KnownIntermediates) > 0 {
		for _, c := range o.KnownIntermediates {
			inter.AddCert(c)
		}
		if ch2, err2 := leaf.Verify(vo); err2 == nil {
			chains, err = ch2, nil
		}
	}
	if err != nil {
		res.Error, res.ErrorClass = err.Error(), classify(err)
		if res.ErrorClass == "expired" && res.NotYetValid {
			res.ErrorClass = "not_yet_valid"
		}
	} else {
		res.Trusted, res.ChainComplete = true, complete
		best := chains[0]
		for _, ch := range chains[1:] {
			if len(ch) < len(best) {
				best = ch
			}
		}
		for _, c := range best {
			res.Chain = append(res.Chain, Fingerprint(c))
		}
	}
	if o.DNSName != "" {
		res.HostnameChecked = true
		res.HostnameOK = leaf.VerifyHostname(o.DNSName) == nil
		if res.Trusted && !res.HostnameOK && res.ErrorClass == "" {
			res.ErrorClass = "hostname"
		}
	}
	return res
}

func classify(err error) string {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &ua):
		return "unknown_authority"
	case errors.As(err, &hn):
		return "hostname"
	case errors.As(err, &ci):
		if ci.Reason == x509.Expired { // stdlib uses Expired for both expired and not-yet-valid
			return "expired"
		}
		return "invalid"
	}
	return "invalid"
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate's DER.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
