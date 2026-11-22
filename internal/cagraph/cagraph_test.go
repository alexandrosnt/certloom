package cagraph

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"
)

func day(n int) time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n) }

func TestKeySharedByCrossSignedCopies(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	mk := func(cn string, pub *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: day(0), NotAfter: day(365), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	oldKey, newRootKey, interKey := newKey(), newKey(), newKey()
	oldRoot := mk("Old Root", &oldKey.PublicKey, nil, oldKey)
	newRoot := mk("New Root", &newRootKey.PublicKey, nil, newRootKey)
	a := mk("Issuing CA", &interKey.PublicKey, newRoot, newRootKey)
	b := mk("Issuing CA", &interKey.PublicKey, oldRoot, oldKey)
	if Key(a) != Key(b) {
		t.Fatal("cross-signed copies must share the authority key")
	}
	other := mk("Issuing CA", &newKey().PublicKey, newRoot, newRootKey)
	if Key(a) == Key(other) {
		t.Fatal("a different key must give a different authority")
	}
	if Key(oldRoot) == Key(newRoot) {
		t.Fatal("different roots must differ")
	}
}

func TestExpiryFollowsTheLongestValidPath(t *testing.T) {
	g := Build([]Cert{
		{SHA256: "r-new", Key: "R", IssuerKey: "R", SelfSigned: true, NotAfter: day(3000)},
		{SHA256: "r-old", Key: "O", IssuerKey: "O", SelfSigned: true, NotAfter: day(400)},
		// Issuing CA, cross-signed: under the new root until day 1500, under
		// the old root until day 600 (cut to 400 by the old root).
		{SHA256: "i-new", Key: "I", IssuerKey: "R", NotAfter: day(1500)},
		{SHA256: "i-old", Key: "I", IssuerKey: "O", NotAfter: day(600)},
		// Sub-CA only under the old root.
		{SHA256: "s", Key: "S", IssuerKey: "O", NotAfter: day(2000)},
		// Unknown parent: own validity.
		{SHA256: "u", Key: "U", IssuerKey: "missing", NotAfter: day(50)},
	})
	cases := map[string]time.Time{"R": day(3000), "O": day(400), "I": day(1500), "S": day(400), "U": day(50)}
	for k, want := range cases {
		got, ok := g.Expiry(k)
		if !ok || !got.Equal(want) {
			t.Errorf("Expiry(%s) = %v %v, want %v", k, got, ok, want)
		}
	}
	i := g.Get("I")
	if !slices.Equal(i.Parents, []string{"O", "R"}) {
		t.Errorf("parents = %v", i.Parents)
	}
	if i.Root || !g.Get("R").Root {
		t.Error("root flags wrong")
	}
	if c := i.Copies[0]; c.SHA256 != "i-old" || !c.ChainExpiry.Equal(day(400)) {
		t.Errorf("copy chain expiry = %+v", c)
	}
	if got := g.Descendants("O"); !slices.Equal(sorted(got), []string{"I", "O", "S"}) {
		t.Errorf("descendants(O) = %v", got)
	}
	if got := g.Ancestors("I"); !slices.Equal(sorted(got), []string{"I", "O", "R"}) {
		t.Errorf("ancestors(I) = %v", got)
	}
	if all := g.All(); all[0].Key != "U" || all[len(all)-1].Key != "R" {
		t.Errorf("order = %v", all)
	}
	if _, ok := g.Expiry("nope"); ok || g.Descendants("nope") != nil {
		t.Error("unknown key must not resolve")
	}
}

func TestMutualCrossSignTerminates(t *testing.T) {
	g := Build([]Cert{
		{SHA256: "a", Key: "A", IssuerKey: "B", NotAfter: day(100)},
		{SHA256: "b", Key: "B", IssuerKey: "A", NotAfter: day(200)},
	})
	if a, _ := g.Expiry("A"); !a.Equal(day(100)) {
		t.Errorf("A = %v", a)
	}
	if b, _ := g.Expiry("B"); b.After(day(200)) {
		t.Errorf("B = %v", b)
	}
	if len(g.Descendants("A")) != 2 {
		t.Error("cycle walk")
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
