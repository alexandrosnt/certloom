package certparse

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/testpki"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestSameCertificateAcrossFormatsHasOneIdentity(t *testing.T) {
	h := testpki.NewHierarchy(t, "www.example.test")
	pass := secret.FromString("correct horse")

	pfx, err := pkcs12.Modern.Encode(h.Leaf.Key, h.Leaf.Cert, []*x509.Certificate{h.Intermediate.Cert}, pass.RevealString())
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"pem":    append(h.Leaf.PEM(), h.Intermediate.PEM()...),
		"der":    h.Leaf.DER,
		"pkcs12": pfx,
	}
	var fps []string
	for name, in := range inputs {
		res, err := Parse(in, pass)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Format != name {
			t.Fatalf("format = %q, want %q", res.Format, name)
		}
		fps = append(fps, res.Certificates[0].SHA256)
		if name == "pkcs12" {
			if !res.PrivateKeySeen || res.KeyMatchesLeaf == nil || !*res.KeyMatchesLeaf {
				t.Fatalf("pkcs12: key should be seen and match: %+v", res)
			}
			if len(res.Certificates) != 2 {
				t.Fatalf("pkcs12: want leaf + intermediate, got %d", len(res.Certificates))
			}
		}
	}
	for _, fp := range fps[1:] {
		if fp != fps[0] {
			t.Fatalf("fingerprints differ across formats: %v", fps)
		}
	}
}

func TestMetadata(t *testing.T) {
	h := testpki.NewHierarchy(t, "a.example.test", "b.example.test")
	res, err := Parse(h.Leaf.PEM(), secret.Value{})
	if err != nil {
		t.Fatal(err)
	}
	c := res.Certificates[0]
	if c.KeyAlgorithm != "ECDSA" || c.Curve != "P-256" || c.KeyBits != 256 {
		t.Errorf("key: %s %s %d", c.KeyAlgorithm, c.Curve, c.KeyBits)
	}
	if strings.Join(c.DNSNames, ",") != "a.example.test,b.example.test" {
		t.Errorf("dns: %v", c.DNSNames)
	}
	if len(c.IPAddresses) != 1 || c.IPAddresses[0] != "127.0.0.1" {
		t.Errorf("ips: %v", c.IPAddresses)
	}
	if c.IsCA || c.SelfSigned {
		t.Error("leaf must not be CA or self-signed")
	}
	if c.AuthorityKeyID == "" || c.AuthorityKeyID != hexOf(h.Intermediate.Cert.SubjectKeyId) {
		t.Errorf("AKI %q should equal intermediate SKI", c.AuthorityKeyID)
	}
	if strings.Join(c.ExtKeyUsage, ",") != "serverAuth" {
		t.Errorf("eku: %v", c.ExtKeyUsage)
	}
	root, _ := Parse(h.Root.PEM(), secret.Value{})
	if !root.Certificates[0].IsCA || !root.Certificates[0].SelfSigned {
		t.Error("root must be CA and self-signed")
	}
}

func TestPrivateKeyInPEMIsFlaggedNotReturned(t *testing.T) {
	h := testpki.NewHierarchy(t, "k.example.test")
	in := append(h.Leaf.PEM(), h.Leaf.KeyPEM(t)...)
	res, err := Parse(in, secret.Value{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.PrivateKeySeen {
		t.Fatal("private key should be flagged")
	}
	if len(res.Certificates) != 1 {
		t.Fatalf("want 1 cert, got %d", len(res.Certificates))
	}
}

func TestPKCS12PasswordHandling(t *testing.T) {
	h := testpki.NewHierarchy(t, "p.example.test")
	pfx, err := pkcs12.Modern.Encode(h.Leaf.Key, h.Leaf.Cert, nil, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(pfx, secret.Value{}); !errors.Is(err, ErrPasswordNeeded) {
		t.Fatalf("empty password: got %v, want ErrPasswordNeeded", err)
	}
	_, err = Parse(pfx, secret.FromString("wrong"))
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("wrong password: got %v (must not echo the password)", err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"garbage":      []byte("not a certificate at all"),
		"pem-no-certs": []byte("-----BEGIN FOO-----\nAAAA\n-----END FOO-----\n"),
	}
	for name, in := range cases {
		if _, err := Parse(in, secret.Value{}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	big := bytes.Repeat([]byte("A"), MaxInputBytes+1)
	if _, err := Parse(big, secret.Value{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: got %v", err)
	}
}

func TestVerify(t *testing.T) {
	h := testpki.NewHierarchy(t, "v.example.test")
	roots := x509.NewCertPool()
	roots.AddCert(h.Root.Cert)
	leaf, inter := h.Leaf.Cert, h.Intermediate.Cert

	t.Run("trusted complete chain", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{leaf, inter}, VerifyOptions{Roots: roots, DNSName: "v.example.test"})
		if !r.Trusted || !r.ChainComplete || !r.HostnameOK || len(r.Chain) != 3 {
			t.Fatalf("%+v", r)
		}
		if r.Chain[0] != Fingerprint(leaf) || r.Chain[2] != Fingerprint(h.Root.Cert) {
			t.Fatal("chain order should be leaf..root")
		}
	})
	t.Run("missing intermediate is untrusted", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{leaf}, VerifyOptions{Roots: roots})
		if r.Trusted || r.ErrorClass != "unknown_authority" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("missing intermediate known to inventory is incomplete", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{leaf}, VerifyOptions{Roots: roots, KnownIntermediates: []*x509.Certificate{inter}})
		if !r.Trusted || r.ChainComplete {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("wrong hostname", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{inter}, VerifyOptions{Roots: roots, DNSName: "other.example.test"})
		if !r.Trusted || r.HostnameOK || r.ErrorClass != "hostname" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("expired", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{inter}, VerifyOptions{Roots: roots, At: leaf.NotAfter.Add(time.Hour)})
		if r.Trusted || !r.Expired || r.ErrorClass != "expired" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		r := Verify(leaf, []*x509.Certificate{inter}, VerifyOptions{Roots: roots, At: leaf.NotBefore.Add(-time.Hour)})
		if r.Trusted || !r.NotYetValid || r.ErrorClass != "not_yet_valid" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("self-signed leaf untrusted", func(t *testing.T) {
		ss := testpki.Issue(t, nil, testpki.Options{CommonName: "self", DNSNames: []string{"self.example.test"}})
		r := Verify(ss.Cert, nil, VerifyOptions{Roots: roots})
		if r.Trusted || r.ErrorClass != "unknown_authority" {
			t.Fatalf("%+v", r)
		}
	})
}

func FuzzParse(f *testing.F) {
	h := testpki.NewHierarchy(f, "fuzz.example.test")
	f.Add(h.Leaf.DER)
	f.Add(append(h.Leaf.PEM(), h.Intermediate.PEM()...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	junk := make([]byte, 64)
	_, _ = rand.Read(junk)
	f.Add(junk)
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Parse(data, secret.Value{})
		if err == nil && (res == nil || len(res.Certificates) == 0) {
			t.Fatal("nil error must come with at least one certificate")
		}
	})
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
