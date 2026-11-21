package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/dnsplugin"
	"github.com/miekg/dns"
)

// rfc2136 adds and removes challenge TXT records with RFC 2136 dynamic
// updates signed with TSIG (RFC 8945). GSS-TSIG (Kerberos, Active Directory)
// is not built in; it is available through the lego plugin.
type rfc2136 struct {
	nameserver string
	keyName    string
	algorithm  string
	secret     string // base64
}

var tsigKeyFile = regexp.MustCompile(`(?s)key\s+"?([A-Za-z0-9._-]+)"?\s*\{(.*?)\}\s*;`)
var tsigField = regexp.MustCompile(`(?m)^\s*(algorithm|secret)\s+"?([^";\s]+)"?\s*;`)

var tsigAlgorithms = map[string]string{
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// loadTSIGKey reads a BIND key file as written by tsig-keygen.
func loadTSIGKey(path string) (name, algorithm, secret string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}
	return parseTSIGKey(string(b), path)
}

// parseTSIGKey parses a BIND key block; src names it in errors.
func parseTSIGKey(text, src string) (name, algorithm, secret string, err error) {
	path := src
	m := tsigKeyFile.FindStringSubmatch(text)
	if m == nil {
		return "", "", "", fmt.Errorf("%s: no key block", path)
	}
	name = dns.Fqdn(strings.ToLower(m[1]))
	for _, f := range tsigField.FindAllStringSubmatch(m[2], -1) {
		switch f[1] {
		case "algorithm":
			alg, ok := tsigAlgorithms[strings.ToLower(f[2])]
			if !ok {
				return "", "", "", fmt.Errorf("%s: TSIG algorithm %s is not supported (use hmac-sha256 or stronger)", path, f[2])
			}
			algorithm = alg
		case "secret":
			if _, err := base64.StdEncoding.DecodeString(f[2]); err != nil {
				return "", "", "", fmt.Errorf("%s: secret is not base64", path)
			}
			secret = f[2]
		}
	}
	if algorithm == "" || secret == "" {
		return "", "", "", fmt.Errorf("%s: key needs algorithm and secret", path)
	}
	return name, algorithm, secret, nil
}

func newRFC2136(c *DNSSolverConfig) (*rfc2136, error) {
	var name, alg, secret string
	var err error
	if c.central {
		name, alg, secret, err = parseTSIGKey(c.secret["tsig_key"], "tsig_key of dns solver "+c.Name)
	} else {
		name, alg, secret, err = loadTSIGKey(c.TSIGFile)
	}
	if err != nil {
		return nil, err
	}
	return &rfc2136{nameserver: c.Nameserver, keyName: name, algorithm: alg, secret: secret}, nil
}

// Present adds the TXT record. Adding a record that already exists is a
// no-op in RFC 2136, and other values at the same name are kept (a wildcard
// and its apex share one record name).
func (r *rfc2136) Present(ctx context.Context, req dnsplugin.Request) error {
	return r.update(ctx, req, true)
}

// Cleanup removes only this value; removing a missing record succeeds.
func (r *rfc2136) Cleanup(ctx context.Context, req dnsplugin.Request) error {
	return r.update(ctx, req, false)
}

func (r *rfc2136) update(ctx context.Context, req dnsplugin.Request, add bool) error {
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(req.FQDN), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{req.Value}}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(req.Zone))
	if add {
		m.Insert([]dns.RR{txt})
	} else {
		m.Remove([]dns.RR{txt})
	}
	m.SetTsig(r.keyName, r.algorithm, 300, time.Now().Unix())
	c := &dns.Client{Net: "tcp", Timeout: 15 * time.Second, TsigSecret: map[string]string{r.keyName: r.secret}}
	resp, _, err := c.ExchangeContext(ctx, m, r.nameserver)
	if err != nil {
		return &dnsplugin.Classified{Class: dnsplugin.ClassTransient, Err: fmt.Errorf("rfc2136 update via %s: %w", r.nameserver, err)}
	}
	if resp.Rcode != dns.RcodeSuccess {
		class := dnsplugin.ClassTransient
		switch resp.Rcode {
		case dns.RcodeNotAuth, dns.RcodeRefused:
			class = dnsplugin.ClassAuth
		case dns.RcodeNotZone, dns.RcodeNameError:
			class = dnsplugin.ClassPermanent
		}
		return &dnsplugin.Classified{Class: class,
			Err: fmt.Errorf("rfc2136 update of %s in zone %s refused: %s", req.FQDN, req.Zone, dns.RcodeToString[resp.Rcode])}
	}
	return nil
}
