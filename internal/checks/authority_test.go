package checks

import (
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
)

var t0 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func days(n int) time.Time { return t0.AddDate(0, 0, n) }

func TestAuthorityThresholds(t *testing.T) {
	cases := []struct {
		left   int
		public bool
		want   Severity
	}{
		{400, false, ""}, {170, false, Warning}, {20, false, Critical}, {-1, false, Critical}, {20, true, Info},
	}
	for _, c := range cases {
		fs := Authority(AuthorityInput{Key: "k", Subject: "CN=CA", Expiry: days(c.left), PubliclyTrusted: c.public, Now: t0})
		got := Severity("")
		if len(fs) == 1 {
			got = fs[0].Severity
			if fs[0].Check != CheckCAExpiring || fs[0].Fingerprint == "" {
				t.Errorf("finding %+v", fs[0])
			}
		}
		if got != c.want {
			t.Errorf("left %dd public %t: %q, want %q", c.left, c.public, got, c.want)
		}
	}
	// The policy moves the thresholds.
	fs := Authority(AuthorityInput{Key: "k", Expiry: days(300), Now: t0, Policy: Policy{CAExpiryWarning: 365 * 24 * time.Hour, CAExpiryCritical: 90 * 24 * time.Hour}})
	if len(fs) != 1 || fs[0].Severity != Warning {
		t.Errorf("policy thresholds: %+v", fs)
	}
}

func TestChainOutlived(t *testing.T) {
	leaf := &certparse.Certificate{SHA256: "l", NotAfter: days(90)}
	if fs := ChainOutlived(leaf, days(365), t0); fs != nil {
		t.Errorf("chain outlives leaf: %+v", fs)
	}
	if fs := ChainOutlived(leaf, days(60), t0); len(fs) != 1 || fs[0].Severity != Warning {
		t.Errorf("chain ends day 60: %+v", fs)
	}
	if fs := ChainOutlived(leaf, days(10), t0); len(fs) != 1 || fs[0].Severity != Critical {
		t.Errorf("chain ends day 10: %+v", fs)
	}
	if fs := ChainOutlived(leaf, days(-5), t0); len(fs) != 1 || fs[0].Severity != Critical {
		t.Errorf("chain ended: %+v", fs)
	}
	expired := &certparse.Certificate{SHA256: "e", NotAfter: days(-1)}
	if fs := ChainOutlived(expired, days(-5), t0); fs != nil {
		t.Errorf("expired leaf belongs to the expiry check: %+v", fs)
	}
	a := ChainOutlived(leaf, days(60), t0)[0].Fingerprint
	if b := ChainOutlived(leaf, days(61), t0)[0].Fingerprint; a == b {
		t.Error("a different chain expiry is a different condition")
	}
}

func TestServedChain(t *testing.T) {
	leaf := &certparse.Certificate{SHA256: "leaf", NotAfter: days(90)}
	inter := func(sha string, n int) *certparse.Certificate {
		return &certparse.Certificate{SHA256: sha, Subject: "CN=" + sha, IsCA: true, NotAfter: days(n)}
	}
	if fs := servedChain([]*certparse.Certificate{leaf, inter("ok", 400)}, t0); fs != nil {
		t.Errorf("healthy chain: %+v", fs)
	}
	if fs := servedChain([]*certparse.Certificate{leaf, inter("later", 60)}, t0); fs != nil {
		t.Errorf("60 days left is not yet a finding: %+v", fs)
	}
	fs := servedChain([]*certparse.Certificate{leaf, inter("a", 20), inter("b", 5)}, t0)
	if len(fs) != 1 || fs[0].Severity != Critical || fs[0].Check != CheckChainCertExpiring {
		t.Fatalf("soonest is critical: %+v", fs)
	}
	if fs := servedChain([]*certparse.Certificate{leaf, inter("a", 20)}, t0); len(fs) != 1 || fs[0].Severity != Warning {
		t.Errorf("20 days: %+v", fs)
	}
	short := &certparse.Certificate{SHA256: "short", NotAfter: days(3)}
	if fs := servedChain([]*certparse.Certificate{short, inter("a", 20)}, t0); fs != nil {
		t.Errorf("intermediate outlives leaf: %+v", fs)
	}
}
