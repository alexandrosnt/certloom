// Package certparse parses X.509 material from PEM, DER and PKCS#12 into
// normalized metadata. It never returns or retains private keys.
package certparse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/secret"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Input limits.
const (
	MaxInputBytes = 1 << 20  // 1 MiB per import
	MaxCertBytes  = 64 << 10 // 64 KiB per certificate
	MaxCerts      = 50       // certificates per input
	MaxSANs       = 1000
)

// Errors returned by the parser.
var (
	ErrTooLarge        = errors.New("input exceeds size limit")
	ErrNoCertificates  = errors.New("no certificates found in input")
	ErrPasswordNeeded  = errors.New("PKCS#12 input requires a password")
	ErrUnknownEncoding = errors.New("input is not PEM, DER or PKCS#12")
)

// Certificate is the normalized, immutable view of one X.509 certificate.
type Certificate struct {
	SHA256             string    `json:"sha256"` // lowercase hex of SHA-256(DER); identity
	Serial             string    `json:"serial"` // lowercase hex, no leading zeros
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	CommonName         string    `json:"common_name,omitempty"`
	SubjectKeyID       string    `json:"ski,omitempty"`
	AuthorityKeyID     string    `json:"aki,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	EmailAddresses     []string  `json:"email_addresses,omitempty"`
	URIs               []string  `json:"uris,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"` // RSA, ECDSA, Ed25519, unknown
	KeyBits            int       `json:"key_bits,omitempty"`
	Curve              string    `json:"curve,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsCA               bool      `json:"is_ca"`
	MaxPathLen         *int      `json:"max_path_len,omitempty"`
	SelfSigned         bool      `json:"self_signed"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	CRLDistribution    []string  `json:"crl_distribution_points,omitempty"`
	IssuingCertURLs    []string  `json:"issuing_certificate_urls,omitempty"`
	Warnings           []string  `json:"warnings,omitempty"`
	DER                []byte    `json:"-"`

	X509 *x509.Certificate `json:"-"`
}

// Lifetime returns NotAfter - NotBefore.
func (c *Certificate) Lifetime() time.Duration { return c.NotAfter.Sub(c.NotBefore) }

// Result is the outcome of parsing one input.
type Result struct {
	Format       string         `json:"format"` // pem, der, pkcs12
	Certificates []*Certificate `json:"certificates"`
	// PrivateKeySeen is true if the input contained a private key. The key is
	// never returned or stored; for PKCS#12 it is only compared to the leaf.
	PrivateKeySeen bool `json:"private_key_seen"`
	// KeyMatchesLeaf is set for PKCS#12 inputs: whether the bundled key
	// corresponds to the first certificate's public key.
	KeyMatchesLeaf *bool    `json:"key_matches_leaf,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// Parse detects the encoding of data and parses all certificates in it.
// password is used only for PKCS#12 and may be empty.
func Parse(data []byte, password secret.Value) (res *Result, err error) {
	if len(data) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	defer func() {
		if r := recover(); r != nil { // don't let a parser bug take the server down
			res, err = nil, fmt.Errorf("certificate parser panic: %v", r)
		}
	}()
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		return parsePEM(trimmed)
	case len(trimmed) == 0:
		return nil, ErrNoCertificates
	}
	if c, derr := x509.ParseCertificate(data); derr == nil {
		pc, err := fromX509(c)
		if err != nil {
			return nil, err
		}
		return &Result{Format: "der", Certificates: []*Certificate{pc}}, nil
	}
	return parsePKCS12(data, password)
}

func parsePEM(data []byte) (*Result, error) {
	res := &Result{Format: "pem"}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			if len(res.Certificates) >= MaxCerts {
				return nil, fmt.Errorf("%w: more than %d certificates", ErrTooLarge, MaxCerts)
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificate %d: %w", len(res.Certificates)+1, err)
			}
			pc, err := fromX509(c)
			if err != nil {
				return nil, err
			}
			res.Certificates = append(res.Certificates, pc)
		case strings.Contains(block.Type, "PRIVATE KEY"):
			res.PrivateKeySeen = true
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf("ignored PEM block of type %q", block.Type))
		}
	}
	if res.PrivateKeySeen {
		res.Warnings = append(res.Warnings, "input contained a private key; it was ignored and not stored")
	}
	if len(res.Certificates) == 0 {
		return nil, ErrNoCertificates
	}
	return res, nil
}

func parsePKCS12(data []byte, password secret.Value) (*Result, error) {
	key, leaf, cas, err := pkcs12.DecodeChain(data, password.RevealString())
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			if password.IsEmpty() {
				return nil, ErrPasswordNeeded
			}
			return nil, errors.New("PKCS#12: incorrect password")
		}
		return nil, ErrUnknownEncoding
	}
	res := &Result{Format: "pkcs12", PrivateKeySeen: key != nil}
	all := append([]*x509.Certificate{leaf}, cas...)
	if len(all) > MaxCerts {
		return nil, fmt.Errorf("%w: more than %d certificates", ErrTooLarge, MaxCerts)
	}
	for _, c := range all {
		pc, err := fromX509(c)
		if err != nil {
			return nil, err
		}
		res.Certificates = append(res.Certificates, pc)
	}
	if key != nil {
		m := KeyMatches(leaf, key)
		res.KeyMatchesLeaf = &m
		res.Warnings = append(res.Warnings, "PKCS#12 private key was checked against the certificate and discarded")
	}
	return res, nil
}

// KeyMatches reports whether priv's public key equals cert's public key.
func KeyMatches(cert *x509.Certificate, priv any) bool {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k.PublicKey.Equal(cert.PublicKey)
	case *ecdsa.PrivateKey:
		return k.PublicKey.Equal(cert.PublicKey)
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey).Equal(cert.PublicKey)
	}
	return false
}

// FromX509 converts an already-parsed certificate.
func FromX509(c *x509.Certificate) (*Certificate, error) { return fromX509(c) }

func fromX509(c *x509.Certificate) (*Certificate, error) {
	if len(c.Raw) > MaxCertBytes {
		return nil, fmt.Errorf("%w: certificate is %d bytes", ErrTooLarge, len(c.Raw))
	}
	sum := sha256.Sum256(c.Raw)
	out := &Certificate{
		SHA256:             hex.EncodeToString(sum[:]),
		Serial:             strings.ToLower(c.SerialNumber.Text(16)),
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		CommonName:         c.Subject.CommonName,
		SubjectKeyID:       hex.EncodeToString(c.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(c.AuthorityKeyId),
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
		OCSPServers:        c.OCSPServer,
		CRLDistribution:    c.CRLDistributionPoints,
		IssuingCertURLs:    c.IssuingCertificateURL,
		DER:                c.Raw,
		X509:               c,
	}
	for _, ip := range c.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		out.URIs = append(out.URIs, u.String())
	}
	if n := len(c.DNSNames) + len(c.IPAddresses) + len(c.URIs) + len(c.EmailAddresses); n > MaxSANs {
		return nil, fmt.Errorf("%w: %d SANs", ErrTooLarge, n)
	}
	if c.BasicConstraintsValid && c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		pl := c.MaxPathLen
		out.MaxPathLen = &pl
	}
	out.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil

	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.KeyAlgorithm, out.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		out.KeyAlgorithm, out.KeyBits, out.Curve = "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name
	case ed25519.PublicKey:
		out.KeyAlgorithm, out.KeyBits = "Ed25519", 256
	default:
		out.KeyAlgorithm = "unknown"
		out.Warnings = append(out.Warnings, fmt.Sprintf("unsupported public key algorithm %v", c.PublicKeyAlgorithm))
	}
	out.KeyUsage = keyUsageNames(c.KeyUsage)
	for _, eku := range c.ExtKeyUsage {
		out.ExtKeyUsage = append(out.ExtKeyUsage, extKeyUsageName(eku))
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out.ExtKeyUsage = append(out.ExtKeyUsage, oid.String())
	}
	for _, ext := range c.UnhandledCriticalExtensions {
		out.Warnings = append(out.Warnings, "unhandled critical extension "+ext.String())
	}
	if !c.NotAfter.After(c.NotBefore) {
		out.Warnings = append(out.Warnings, "NotAfter is not after NotBefore")
	}
	return out, nil
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsageNames(ku x509.KeyUsage) []string {
	var out []string
	for _, b := range keyUsageBits {
		if ku&b.bit != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

func extKeyUsageName(e x509.ExtKeyUsage) string {
	switch e {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	}
	return fmt.Sprintf("eku(%d)", e)
}
