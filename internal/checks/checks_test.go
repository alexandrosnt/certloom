package checks

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func parsed(t *testing.T, c *testpki.Cert) *certparse.Certificate {
	t.Helper()
	pc, err := certparse.FromX509(c.Cert)
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func has(fs []Finding, check string, sev Severity) bool {
	for _, f := range fs {
		if f.Check == check && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestExpiryThresholdsScaleWithLifetime(t *testing.T) {
	var p Policy
	w, c := p.ExpiryThresholds(90 * 24 * time.Hour)
	if w != 30*24*time.Hour || c != 7*24*time.Hour {
		t.Fatalf("90d: %v %v", w, c)
	}
	w, c = p.ExpiryThresholds(160 * time.Hour) // Let's Encrypt shortlived
	if w != 160*time.Hour/3 || c != 16*time.Hour {
		t.Fatalf("6d: %v %v", w, c)
	}
}

func TestCertificateExpiry(t *testing.T) {
	now := time.Now()
	mk := func(left time.Duration) *certparse.Certificate {
		return parsed(t, testpki.Issue(t, nil, testpki.Options{CommonName: "x", NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(left)}))
	}
	cases := []struct {
		left time.Duration
		sev  Severity // "" = no expiry finding
	}{
		{60 * 24 * time.Hour, ""},
		{20 * 24 * time.Hour, Warning},
		{3 * 24 * time.Hour, Critical},
		{-time.Hour, Critical},
	}
	for _, c := range cases {
		fs := Certificate(mk(c.left), now, Policy{})
		if c.sev == "" {
			if len(fs) != 0 {
				t.Errorf("left %v: unexpected %+v", c.left, fs)
			}
			continue
		}
		if !has(fs, CheckExpiry, c.sev) {
			t.Errorf("left %v: want %s expiry, got %+v", c.left, c.sev, fs)
		}
	}
}

func TestWeakKeyAndSignature(t *testing.T) {
	root := testpki.Issue(t, nil, testpki.Options{CommonName: "rsa root", IsCA: true, RSABits: 2048})
	weak := testpki.Issue(t, root, testpki.Options{CommonName: "weak", RSABits: 1024, SHA1Sig: true})
	fs := Certificate(parsed(t, weak), time.Now(), Policy{})
	if !has(fs, CheckWeakKey, Critical) || !has(fs, CheckWeakSignature, Critical) {
		t.Fatalf("%+v", fs)
	}
	if fs := Certificate(parsed(t, root), time.Now(), Policy{}); len(fs) != 0 {
		t.Fatalf("strong self-signed root should be clean: %+v", fs)
	}
}

func obsFor(t *testing.T, chain ...*testpki.Cert) *probe.Observation {
	o := &probe.Observation{ObservedAt: time.Now()}
	for _, c := range chain {
		o.Chain = append(o.Chain, parsed(t, c))
	}
	return o
}

func TestEndpoint(t *testing.T) {
	h := testpki.NewHierarchy(t, "www.example.test")
	other := testpki.NewHierarchy(t, "www.example.test")
	roots := x509.NewCertPool()
	roots.AddCert(h.Root.Cert)
	base := EndpointInput{ExpectedName: "www.example.test", Roots: roots, Now: time.Now()}

	t.Run("healthy endpoint has no findings", func(t *testing.T) {
		in := base
		in.Observation = obsFor(t, h.Leaf, h.Intermediate)
		if fs := Endpoint(in); len(fs) != 0 {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("missing intermediate known to inventory", func(t *testing.T) {
		in := base
		in.Observation = obsFor(t, h.Leaf)
		in.KnownIntermediates = []*x509.Certificate{h.Intermediate.Cert}
		if fs := Endpoint(in); !has(fs, CheckChainIncomplete, Warning) {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("untrusted", func(t *testing.T) {
		in := base
		in.Observation = obsFor(t, other.Leaf, other.Intermediate)
		if fs := Endpoint(in); !has(fs, CheckUntrusted, Critical) {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("hostname mismatch", func(t *testing.T) {
		in := base
		in.ExpectedName = "api.example.test"
		in.Observation = obsFor(t, h.Leaf, h.Intermediate)
		if fs := Endpoint(in); !has(fs, CheckHostnameMismatch, Critical) {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("unexpected fingerprint change and lineage mismatch", func(t *testing.T) {
		in := base
		in.Observation = obsFor(t, h.Leaf, h.Intermediate)
		in.PreviousLeaf = certparse.Fingerprint(other.Leaf.Cert)
		in.ExpectedLeaf = certparse.Fingerprint(other.Leaf.Cert)
		fs := Endpoint(in)
		if !has(fs, CheckFingerprintChanged, Warning) || !has(fs, CheckLineageMismatch, Critical) {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("expected replacement is info only", func(t *testing.T) {
		in := base
		in.Observation = obsFor(t, h.Leaf, h.Intermediate)
		in.PreviousLeaf = certparse.Fingerprint(other.Leaf.Cert)
		in.ExpectedLeaf = certparse.Fingerprint(h.Leaf.Cert)
		fs := Endpoint(in)
		if !has(fs, CheckFingerprintChanged, Info) || has(fs, CheckLineageMismatch, Critical) {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("probe failures alert only after threshold", func(t *testing.T) {
		in := base
		in.Observation = &probe.Observation{ErrorClass: "timeout", Error: "i/o timeout"}
		in.ConsecutiveFailures = 2
		if fs := Endpoint(in); len(fs) != 0 {
			t.Fatalf("below threshold: %+v", fs)
		}
		in.ConsecutiveFailures = 3
		if fs := Endpoint(in); !has(fs, CheckProbeFailed, Warning) {
			t.Fatalf("%+v", fs)
		}
	})
}

// Every finding names its condition: the same certificate gives the same
// fingerprint, another certificate with the same weakness a different one.
func TestFingerprints(t *testing.T) {
	root := testpki.Issue(t, nil, testpki.Options{CommonName: "rsa root", IsCA: true, RSABits: 2048})
	a := parsed(t, testpki.Issue(t, root, testpki.Options{CommonName: "a", RSABits: 1024}))
	b := parsed(t, testpki.Issue(t, root, testpki.Options{CommonName: "b", RSABits: 1024}))
	now := time.Now()
	fa, fa2, fb := Certificate(a, now, Policy{}), Certificate(a, now, Policy{}), Certificate(b, now, Policy{})
	if len(fa) == 0 {
		t.Fatal("want a weak_key finding")
	}
	for i, f := range fa {
		if f.Fingerprint == "" || f.Fingerprint != fa2[i].Fingerprint {
			t.Fatalf("fingerprint not stable: %+v", f)
		}
		if f.Fingerprint == fb[i].Fingerprint {
			t.Fatalf("two certificates share a fingerprint for %s", f.Check)
		}
	}
	for _, id := range []string{CheckExpiry, CheckNotYetValid, CheckHostnameMismatch, CheckChainIncomplete, CheckUntrusted, CheckWeakKey,
		CheckWeakSignature, CheckFingerprintChanged, CheckLineageMismatch, CheckProbeFailed} {
		if !KnownCheck(id) || Version(id) < 1 {
			t.Errorf("check %s has no version", id)
		}
	}
}
