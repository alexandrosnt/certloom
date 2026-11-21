package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// tlsServer serves certificates chosen by SNI. Returns its port.
func tlsServer(t *testing.T, bySNI map[string]tls.Certificate, def tls.Certificate) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c, ok := bySNI[h.ServerName]; ok {
			return &c, nil
		}
		return &def, nil
	}}
	tl := tls.NewListener(ln, cfg)
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func keyPair(t *testing.T, c *testpki.Cert, chain ...*testpki.Cert) tls.Certificate {
	kp := tls.Certificate{Certificate: [][]byte{c.DER}, PrivateKey: c.Key}
	for _, x := range chain {
		kp.Certificate = append(kp.Certificate, x.DER)
	}
	return kp
}

// staticResolver resolves every name to fixed addresses.
type staticResolver []netip.Addr

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if len(r) == 0 {
		return nil, errors.New("no such host")
	}
	return r, nil
}

func TestProbeCapturesChainBySNI(t *testing.T) {
	a := testpki.NewHierarchy(t, "a.example.test")
	b := testpki.NewHierarchy(t, "b.example.test")
	port := tlsServer(t, map[string]tls.Certificate{
		"a.example.test": keyPair(t, a.Leaf, a.Intermediate),
		"b.example.test": keyPair(t, b.Leaf),
	}, keyPair(t, a.Leaf))

	p := &Prober{Resolver: staticResolver{netip.MustParseAddr("127.0.0.1")}, Timeout: 5 * time.Second}
	scope := &Scope{Name: "test", AllowLoopback: true, Ports: []int{port}}

	oa := p.Probe(context.Background(), scope, Target{Host: "a.example.test", Port: port})
	if oa.Error != "" {
		t.Fatal(oa.Error)
	}
	if len(oa.Chain) != 2 || oa.Leaf().SHA256 != fp(a.Leaf) {
		t.Fatalf("a: got %d certs", len(oa.Chain))
	}
	if oa.Address != "127.0.0.1:"+strconv.Itoa(port) || oa.TLSVersion == "" || oa.Cipher == "" {
		t.Fatalf("a: missing connection details: %+v", oa)
	}
	ob := p.Probe(context.Background(), scope, Target{Host: "b.example.test", Port: port})
	if ob.Error != "" || ob.Leaf().SHA256 != fp(b.Leaf) || len(ob.Chain) != 1 {
		t.Fatalf("b: %+v", ob)
	}
}

func TestProbeRecordsUntrustedAndExpired(t *testing.T) {
	ss := testpki.Issue(t, nil, testpki.Options{CommonName: "expired.example.test", DNSNames: []string{"expired.example.test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	port := tlsServer(t, nil, keyPair(t, ss))
	p := &Prober{Resolver: staticResolver{netip.MustParseAddr("127.0.0.1")}}
	o := p.Probe(context.Background(), &Scope{AllowLoopback: true, Ports: []int{port}}, Target{Host: "expired.example.test", Port: port})
	if o.Error != "" || o.Leaf() == nil || o.Leaf().SHA256 != fp(ss) {
		t.Fatalf("expired self-signed cert must still be recorded: %+v", o)
	}
}

func TestScopeDenials(t *testing.T) {
	p := &Prober{Resolver: staticResolver{netip.MustParseAddr("127.0.0.1")}, Timeout: time.Second}
	cases := []struct {
		name   string
		scope  Scope
		target Target
	}{
		{"loopback denied by default", Scope{}, Target{Host: "127.0.0.1", Port: 443}},
		{"name resolving to loopback denied", Scope{}, Target{Host: "rebind.example.test", Port: 443}},
		{"metadata always denied", Scope{AllowLinkLocal: true, AllowPrivate: true, AllowLoopback: true}, Target{Host: "169.254.169.254", Port: 443}},
		{"metadata v6 always denied", Scope{AllowLinkLocal: true, AllowPrivate: true}, Target{Host: "fd00:ec2::254", Port: 443}},
		{"private denied by default", Scope{}, Target{Host: "10.1.2.3", Port: 443}},
		{"cgnat denied by default", Scope{}, Target{Host: "100.64.1.1", Port: 443}},
		{"link-local denied", Scope{}, Target{Host: "169.254.1.1", Port: 443}},
		{"ipv4-mapped loopback denied", Scope{}, Target{Host: "::ffff:127.0.0.1", Port: 443}},
		{"unspecified denied", Scope{AllowLoopback: true}, Target{Host: "0.0.0.0", Port: 443}},
		{"port outside scope", Scope{}, Target{Host: "8.8.8.8", Port: 22}},
		{"host outside allowlist", Scope{AllowHosts: []string{"*.example.com"}}, Target{Host: "evil.test", Port: 443}},
		{"cidr outside allowlist", Scope{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, Target{Host: "198.51.100.7", Port: 443}},
		{"invalid port", Scope{}, Target{Host: "8.8.8.8", Port: 70000}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := p.Probe(context.Background(), &c.scope, c.target)
			if o.ErrorClass != "scope_denied" {
				t.Fatalf("want scope_denied, got %q (%s)", o.ErrorClass, o.Error)
			}
		})
	}
}

func TestScopeAllowsHostPattern(t *testing.T) {
	s := &Scope{AllowHosts: []string{"*.example.com"}}
	if err := s.CheckHost("www.example.com.", 443); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAddr(netip.MustParseAddr("93.184.216.34")); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRefusedAndDNS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listening now
	p := &Prober{Resolver: staticResolver{netip.MustParseAddr("127.0.0.1")}, Timeout: 3 * time.Second}
	o := p.Probe(context.Background(), &Scope{AllowLoopback: true, Ports: []int{port}}, Target{Host: "127.0.0.1", Port: port})
	if o.ErrorClass != "refused" {
		t.Fatalf("want refused, got %q (%s)", o.ErrorClass, o.Error)
	}
	p.Resolver = staticResolver{}
	o = p.Probe(context.Background(), &Scope{}, Target{Host: "nx.example.test", Port: 443})
	if o.ErrorClass != "dns" {
		t.Fatalf("want dns, got %q", o.ErrorClass)
	}
}

func fp(c *testpki.Cert) string {
	return certparse.Fingerprint(c.Cert)
}
