// Package testpki generates throwaway X.509 hierarchies for tests.
// Nothing generated here is persisted; keys live only in memory.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SKI derivation only, per RFC 5280 section 4.2.1.2 method 1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// Cert is a generated certificate plus its private key.
type Cert struct {
	Cert *x509.Certificate
	DER  []byte
	Key  crypto.Signer
}

// PEM returns the certificate in PEM form.
func (c *Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
}

// KeyPEM returns the private key as PKCS#8 PEM.
func (c *Cert) KeyPEM(t testing.TB) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Options control leaf/CA generation.
type Options struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	NotBefore  time.Time
	NotAfter   time.Time
	IsCA       bool
	RSABits    int // 0 => ECDSA P-256
	Serial     *big.Int
	SHA1Sig    bool // sign with SHA1-RSA (for weak-signature tests); requires RSA issuer
}

func newKey(t testing.TB, rsaBits int) crypto.Signer {
	t.Helper()
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ski(t testing.TB, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.Sum(der) //nolint:gosec
	return h[:]
}

// Issue creates a certificate signed by issuer (self-signed if issuer is nil).
func Issue(t testing.TB, issuer *Cert, o Options) *Cert {
	t.Helper()
	key := newKey(t, o.RSABits)
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(90 * 24 * time.Hour)
	}
	serial := o.Serial
	if serial == nil {
		var err error
		serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"certloom test"}},
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPs,
		BasicConstraintsValid: true,
		IsCA:                  o.IsCA,
		SubjectKeyId:          ski(t, key.Public()),
	}
	if o.IsCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if o.SHA1Sig {
		tmpl.SignatureAlgorithm = x509.SHA1WithRSA
	}
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.Cert, issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{Cert: c, DER: der, Key: key}
}

// Hierarchy is root -> intermediate -> leaf.
type Hierarchy struct {
	Root, Intermediate, Leaf *Cert
}

// NewHierarchy builds a three-level chain with a leaf for the given DNS names.
func NewHierarchy(t testing.TB, dnsNames ...string) *Hierarchy {
	t.Helper()
	now := time.Now()
	root := Issue(t, nil, Options{CommonName: "certloom test root", IsCA: true, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour)})
	inter := Issue(t, root, Options{CommonName: "certloom test intermediate", IsCA: true, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour)})
	cn := "leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	leaf := Issue(t, inter, Options{CommonName: cn, DNSNames: dnsNames, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	return &Hierarchy{Root: root, Intermediate: inter, Leaf: leaf}
}

// IssueWithKey issues a certificate for an existing key (e.g. one generated
// by the code under test).
func IssueWithKey(t testing.TB, issuer *Cert, key crypto.Signer, o Options) *Cert {
	t.Helper()
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(90 * 24 * time.Hour)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: o.CommonName}, NotBefore: o.NotBefore, NotAfter: o.NotAfter,
		DNSNames: o.DNSNames, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, key.Public(), issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &Cert{Cert: c, DER: der, Key: key}
}
