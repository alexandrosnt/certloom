package certtemplate

import (
	"strings"
	"testing"
)

func TestNameAllowed(t *testing.T) {
	pats := []string{"*.example.com", "api-*.corp.example.com", "example.com", "*-edge.*.cdn.example.net"}
	for _, c := range []struct {
		name      string
		wildcards bool
		want      bool
	}{
		{"www.example.com", false, true},
		{"WWW.Example.COM.", false, true},
		{"example.com", false, true},
		{"a.b.example.com", false, false}, // * is one label
		{"api-eu.corp.example.com", false, true},
		{"api-.corp.example.com", false, false}, // * needs at least one character
		{"web.corp.example.com", false, false},
		{"eu-edge.fra.cdn.example.net", false, true},
		{"-edge.fra.cdn.example.net", false, false},
		{"*.example.com", false, false}, // wildcard not allowed
		{"*.example.com", true, true},
		{"*.corp.example.com", true, false}, // pattern label is not a bare *
		{"evil-example.com", false, false},
		{"www.example.com.evil.test", false, false},
	} {
		if got := NameAllowed(c.name, pats, c.wildcards); got != c.want {
			t.Errorf("%s (wildcards=%v): %v", c.name, c.wildcards, got)
		}
	}
}

const valid = `apiVersion: certloom/v1
kind: CertificateTemplate
metadata: {name: public-web}
spec:
  issuer: le-prod
  sans: {allowed: ["*.Example.com."]}
`

func TestParse(t *testing.T) {
	d, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if d.Spec.Challenge != "http-01" || d.Spec.KeyAlgorithms[0] != "ecdsa-p256" || d.Spec.SANs.MaxNames != DefaultMaxNames ||
		d.Spec.SANs.Allowed[0] != "*.example.com" {
		t.Fatalf("defaults: %+v", d.Spec)
	}
	for name, src := range map[string]string{
		"unknown field":  strings.Replace(valid, "issuer: le-prod", "issuer: le-prod\n  validity: 90d", 1),
		"no issuer":      strings.Replace(valid, "issuer: le-prod", "issuer: ''", 1),
		"bad name":       strings.Replace(valid, "public-web", "Public Web", 1),
		"bare star":      strings.Replace(valid, `"*.Example.com."`, `"*"`, 1),
		"star tld":       strings.Replace(valid, `"*.Example.com."`, `"example.*"`, 1),
		"two stars":      strings.Replace(valid, `"*.Example.com."`, `"a*b*.example.com"`, 1),
		"one label":      strings.Replace(valid, `"*.Example.com."`, `"localhost"`, 1),
		"key":            strings.Replace(valid, "issuer: le-prod", "issuer: le-prod\n  keyAlgorithms: [rsa-1024]", 1),
		"wildcard http":  strings.Replace(valid, `allowed: ["*.Example.com."]`, `allowed: ["*.Example.com."], wildcards: true`, 1),
		"wrong kind":     strings.Replace(valid, "CertificateTemplate", "MonitoringPolicy", 1),
		"too many names": strings.Replace(valid, `allowed: ["*.Example.com."]`, `allowed: ["*.Example.com."], maxNames: 101`, 1),
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckNames(t *testing.T) {
	d, _ := Parse([]byte(strings.Replace(valid, `allowed: ["*.Example.com."]`, `allowed: ["*.Example.com."], maxNames: 2`, 1)))
	if p := d.CheckNames([]string{"a.example.com", "b.example.com"}); len(p) != 0 {
		t.Fatal(p)
	}
	if p := d.CheckNames([]string{"a.example.com", "b.example.com", "c.example.com"}); len(p) != 1 {
		t.Fatal(p)
	}
	if p := d.CheckNames([]string{"*.example.com", "x.other.test"}); len(p) != 2 {
		t.Fatal(p)
	}
}
