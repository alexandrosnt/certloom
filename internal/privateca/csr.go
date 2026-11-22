package privateca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCN  = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// CheckCSR makes sure an agent's CSR asks for exactly the approved names
// and key before it is sent to a CA: a valid self-signature, the expected
// key algorithm, DNS names equal to sans, a subject of at most a common name
// that is one of them, and no extension besides the SAN extension.
func CheckCSR(csrPEM string, sans []string, keyAlgorithm string) (*x509.CertificateRequest, error) {
	blk, rest := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("not a single PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	switch keyAlgorithm {
	case "", "ecdsa-p256":
		k, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return nil, errors.New("key is not ECDSA P-256")
		}
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", keyAlgorithm)
	}
	got := normNames(csr.DNSNames)
	want := normNames(sans)
	if !slices.Equal(got, want) {
		return nil, fmt.Errorf("CSR names %v do not match the deployment's %v", got, want)
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return nil, errors.New("CSR has IP, email or URI names")
	}
	for _, n := range csr.Subject.Names {
		if !n.Type.Equal(oidCN) {
			return nil, errors.New("CSR subject has attributes besides the common name")
		}
	}
	if cn := csr.Subject.CommonName; cn != "" && !slices.Contains(want, strings.ToLower(cn)) {
		return nil, errors.New("CSR common name is not one of its names")
	}
	for _, e := range csr.Extensions {
		if !e.Id.Equal(oidSAN) {
			return nil, fmt.Errorf("CSR has extension %s", e.Id)
		}
	}
	return csr, nil
}

func normNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
