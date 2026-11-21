package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseValidAndDefaults(t *testing.T) {
	d, err := Parse([]byte(`
apiVersion: certloom/v1
kind: MonitoringPolicy
spec:
  expiry: {warning: 45d, critical: 10d}
  keys: {minRSABits: 3072}
  escalation: {after: 24h, channels: [oncall]}
`))
	if err != nil {
		t.Fatal(err)
	}
	c := d.Checks()
	if c.ExpiryWarning != 45*24*time.Hour || c.ExpiryCritical != 10*24*time.Hour || c.MinRSABits != 3072 {
		t.Fatalf("%+v", c)
	}
	if c.MinECDSABits != 256 || c.ProbeFailuresToAlert != 3 { // defaults filled
		t.Fatalf("defaults not filled: %+v", c)
	}
	if time.Duration(d.Spec.Retention.Observations) != DefaultObservationRetention {
		t.Fatal("retention default not filled")
	}
	y, err := d.YAML()
	if err != nil || !strings.Contains(string(y), "warning: 45d") {
		t.Fatalf("yaml round trip: %s %v", y, err)
	}
	if _, err := Parse(y); err != nil {
		t.Fatalf("rendered YAML must re-parse: %v", err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":        "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {expiry: {warn: 30d}}",
		"wrong kind":           "apiVersion: certloom/v1\nkind: Other\nspec: {}",
		"warning <= critical":  "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {expiry: {warning: 5d, critical: 7d}}",
		"weaker RSA":           "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {keys: {minRSABits: 1024}}",
		"weaker ECDSA":         "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {keys: {minECDSABits: 224}}",
		"bad duration":         "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {expiry: {warning: soon}}",
		"escalation too eager": "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {escalation: {after: 1m}}",
		"retention too short":  "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {retention: {observations: 1h}}",
		"not yaml":             "{{{",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
