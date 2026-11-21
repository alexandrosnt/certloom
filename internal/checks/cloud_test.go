package checks

import (
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

func TestCloudObject(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	day := 24 * time.Hour
	cases := []struct {
		name  string
		o     agentproto.CloudObject
		check string
		sev   Severity
	}{
		{"healthy managed", agentproto.CloudObject{Managed: true, NotAfter: at(60 * day)}, "", ""},
		{"pending briefly", agentproto.CloudObject{Managed: true, Renewal: agentproto.RenewalPending, RenewalSince: at(-time.Hour)}, "", ""},
		{"pending without since", agentproto.CloudObject{Managed: true, Renewal: agentproto.RenewalPending}, "", ""},
		{"pending long", agentproto.CloudObject{Managed: true, Renewal: agentproto.RenewalPending, RenewalSince: at(-4 * day)},
			CheckCloudRenewalFailing, Warning},
		{"failed far from expiry", agentproto.CloudObject{Managed: true, Renewal: agentproto.RenewalFailed, NotAfter: at(200 * day)},
			CheckCloudRenewalFailing, Warning},
		{"managed but not renewed", agentproto.CloudObject{Managed: true, NotAfter: at(3 * day)}, CheckCloudRenewalFailing, Critical},
		{"manual inside window", agentproto.CloudObject{NotAfter: at(20 * day)}, CheckCloudRenewalManual, Warning},
		{"manual critical", agentproto.CloudObject{NotAfter: at(2 * day)}, CheckCloudRenewalManual, Critical},
		{"manual far", agentproto.CloudObject{NotAfter: at(90 * day)}, "", ""},
		{"manual expired is left to expiry checks", agentproto.CloudObject{NotAfter: at(-day)}, "", ""},
		{"CA is left to expiry checks", agentproto.CloudObject{CA: true, NotAfter: at(2 * day)}, "", ""},
	}
	for _, c := range cases {
		c.o.Provider, c.o.ID = agentproto.CloudAWSACM, "arn:x"
		fs := CloudObject(c.o, now, Policy{})
		switch {
		case c.check == "" && len(fs) != 0:
			t.Errorf("%s: unexpected %+v", c.name, fs)
		case c.check != "" && (len(fs) != 1 || fs[0].Check != c.check || fs[0].Severity != c.sev):
			t.Errorf("%s: got %+v, want %s %s", c.name, fs, c.check, c.sev)
		}
	}
}

func TestCloudVersionNotAdopted(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	o := agentproto.CloudObject{Provider: agentproto.CloudAzureKeyVault, ID: "v/api",
		Versions: []agentproto.CloudVersion{{ID: "v2", Created: now.Add(-time.Hour).Format(time.RFC3339), Enabled: true}}}
	if fs := CloudVersionNotAdopted(o, now, []string{"api:443"}); len(fs) != 0 {
		t.Fatal("inside the grace period")
	}
	o.Versions[0].Created = now.Add(-25 * time.Hour).Format(time.RFC3339)
	a := CloudVersionNotAdopted(o, now, []string{"b:443", "a:443"})
	b := CloudVersionNotAdopted(o, now, []string{"a:443", "b:443"})
	if len(a) != 1 || a[0].Fingerprint != b[0].Fingerprint {
		t.Fatalf("finding must not depend on endpoint order: %+v %+v", a, b)
	}
}
