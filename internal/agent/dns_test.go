package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/alexandrosnt/certloom/dnsplugin"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"
)

const testTSIGSecret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="

// fakeDNS is an authoritative server for a few test zones. It accepts
// TSIG-signed RFC 2136 updates and answers SOA, CNAME and TXT queries.
type fakeDNS struct {
	addr  string
	mu    sync.Mutex
	txt   map[string][]string
	zones []string
	cname map[string]string
}

func startFakeDNS(t *testing.T, zones ...string) *fakeDNS {
	t.Helper()
	f := &fakeDNS{txt: map[string][]string{}, zones: zones, cname: map[string]string{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skipf("tcp port taken: %v", err)
	}
	f.addr = pc.LocalAddr().String()
	secrets := map[string]string{"certloom-test.": testTSIGSecret}
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: f, TsigSecret: secrets, MsgAcceptFunc: acceptAll}, {Listener: l, Handler: f, TsigSecret: secrets, MsgAcceptFunc: acceptAll}} {
		go func() { _ = s.ActivateAndServe() }()
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	return f
}

// acceptAll lets UPDATE messages through; the default accept func refuses them.
func acceptAll(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }

func (f *fakeDNS) zoneOf(name string) string {
	for _, z := range f.zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return z
		}
	}
	return ""
}

func (f *fakeDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Opcode == dns.OpcodeUpdate {
		if r.IsTsig() == nil || w.TsigStatus() != nil {
			m.Rcode = dns.RcodeNotAuth
		} else {
			for _, rr := range r.Ns {
				t, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}
				name := strings.ToLower(t.Hdr.Name)
				if t.Hdr.Class == dns.ClassNONE { // delete this value
					var keep []string
					for _, v := range f.txt[name] {
						if v != t.Txt[0] {
							keep = append(keep, v)
						}
					}
					f.txt[name] = keep
				} else if !slices.Contains(f.txt[name], t.Txt[0]) {
					f.txt[name] = append(f.txt[name], t.Txt[0])
				}
			}
			m.SetTsig(r.IsTsig().Hdr.Name, r.IsTsig().Algorithm, 300, int64(r.IsTsig().TimeSigned))
		}
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	zone := f.zoneOf(name)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns." + zone, Mbox: "admin." + zone, Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60}
	switch {
	case zone == "":
		m.Rcode = dns.RcodeRefused
	case f.cname[name] != "":
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: f.cname[name]})
	case q.Qtype == dns.TypeSOA && name == zone:
		m.Answer = append(m.Answer, soa)
	case q.Qtype == dns.TypeTXT && len(f.txt[name]) > 0:
		for _, v := range f.txt[name] {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
		}
	default:
		m.Ns = append(m.Ns, soa)
	}
	_ = w.WriteMsg(m)
}

func (f *fakeDNS) records(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.txt[name]...)
}

func writeTSIGKey(t *testing.T, alg, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.key")
	body := "key \"certloom-test\" {\n\talgorithm " + alg + ";\n\tsecret \"" + secret + "\";\n};\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestDNSConfigValidation(t *testing.T) {
	dir := t.TempDir()
	key, plugin := filepath.Join(dir, "k.key"), filepath.Join(dir, "plugin")
	sha := strings.Repeat("ab", 32)
	for _, c := range []struct {
		name string
		s    []DNSSolverConfig
		res  []string
		want string
	}{
		{"ok", []DNSSolverConfig{{Name: "a", Provider: "rfc2136", Nameserver: "ns:53", TSIGFile: key, Zones: []string{"example.com"}},
			{Name: "b", Plugin: plugin, SHA256: sha, Zones: []string{"sub.example.com"}}}, []string{"10.0.0.1:53"}, ""},
		{"both", []DNSSolverConfig{{Name: "a", Provider: "cloudflare", Plugin: "/p", Zones: []string{"x"}}}, nil, "not both"},
		{"unknown", []DNSSolverConfig{{Name: "a", Provider: "route53", Zones: []string{"x"}}}, nil, "unknown provider"},
		{"no tsig", []DNSSolverConfig{{Name: "a", Provider: "rfc2136", Nameserver: "ns:53", Zones: []string{"x"}}}, nil, "tsig_file"},
		{"no zones", []DNSSolverConfig{{Name: "a", Provider: "cloudflare", TokenFile: key}}, nil, "zones"},
		{"plugin sha", []DNSSolverConfig{{Name: "a", Plugin: "/p", SHA256: "abc", Zones: []string{"x"}}}, nil, "sha256"},
		{"relative plugin", []DNSSolverConfig{{Name: "a", Plugin: "p", SHA256: sha, Zones: []string{"x"}}}, nil, "absolute"},
		{"dup zone", []DNSSolverConfig{{Name: "a", Provider: "cloudflare", TokenFile: key, Zones: []string{"Example.com"}},
			{Name: "b", Provider: "cloudflare", TokenFile: key, Zones: []string{"example.com."}}}, nil, "claimed by"},
		{"dup name", []DNSSolverConfig{{Name: "a", Provider: "cloudflare", TokenFile: key, Zones: []string{"x"}},
			{Name: "a", Provider: "cloudflare", TokenFile: key, Zones: []string{"y"}}}, nil, "unique"},
		{"resolver", nil, []string{"10.0.0.1"}, "host:port"},
	} {
		cfg := &Config{DNSSolvers: c.s, Resolvers: c.res}
		got := strings.Join(cfg.validateDNS(), "; ")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDNSMuxPicksLongestZone(t *testing.T) {
	m := &dnsMux{log: quietLog}
	for _, s := range []struct{ name, zone string }{{"outer", "example.com."}, {"inner", "corp.example.com."}} {
		m.solvers = append(m.solvers, &dnsSolver{cfg: &DNSSolverConfig{Name: s.name}, zones: []string{s.zone}})
	}
	for fqdn, want := range map[string]string{
		"_acme-challenge.www.example.com.":   "outer",
		"_acme-challenge.a.corp.example.com": "inner",
		"_acme-challenge.CORP.example.com.":  "inner",
		"_acme-challenge.notexample.com.":    "",
	} {
		s, _, err := m.pick(fqdn)
		switch {
		case want == "" && !dnsplugin.IsClass(err, dnsplugin.ClassPermanent):
			t.Errorf("%s: want permanent error, got %v", fqdn, err)
		case want != "" && (err != nil || s.cfg.Name != want):
			t.Errorf("%s: got %v %v, want %s", fqdn, s, err, want)
		}
	}
}

func TestLoadTSIGKey(t *testing.T) {
	name, alg, secret, err := loadTSIGKey(writeTSIGKey(t, "hmac-sha256", testTSIGSecret))
	if err != nil || name != "certloom-test." || alg != dns.HmacSHA256 || secret != testTSIGSecret {
		t.Fatalf("%s %s %s %v", name, alg, secret, err)
	}
	if _, _, _, err := loadTSIGKey(writeTSIGKey(t, "hmac-sha1", testTSIGSecret)); err == nil {
		t.Fatal("hmac-sha1 accepted")
	}
	if _, _, _, err := loadTSIGKey(writeTSIGKey(t, "hmac-sha256", "not base64!")); err == nil {
		t.Fatal("bad secret accepted")
	}
}

func TestRFC2136PresentAndCleanup(t *testing.T) {
	f := startFakeDNS(t, "example.test.")
	r, err := newRFC2136(&DNSSolverConfig{Nameserver: f.addr, TSIGFile: writeTSIGKey(t, "hmac-sha256", testTSIGSecret)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := "_acme-challenge.example.test."
	a := dnsplugin.Request{FQDN: name, Value: "apex", Zone: "example.test."}
	w := dnsplugin.Request{FQDN: name, Value: "wildcard", Zone: "example.test."}
	for _, req := range []dnsplugin.Request{a, w, a} { // repeating present is a no-op
		if err := r.Present(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.records(name); len(got) != 2 {
		t.Fatalf("records after present: %v", got)
	}
	if err := r.Cleanup(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := f.records(name); len(got) != 1 || got[0] != "wildcard" {
		t.Fatalf("cleanup removed the wrong value: %v", got)
	}
	if err := r.Cleanup(ctx, a); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}

	bad, _ := newRFC2136(&DNSSolverConfig{Nameserver: f.addr, TSIGFile: writeTSIGKey(t, "hmac-sha256", "d3JvbmctZnJvbmctd3Jvbmctd3Jvbmctd3Jvbmc=")})
	if err := bad.Present(ctx, a); err == nil {
		t.Fatal("update with the wrong key accepted")
	}
}

// The record name is resolved through the _acme-challenge CNAME before a
// solver is chosen, so a delegated validation zone gets the record.
func TestDNSMuxFollowsCNAME(t *testing.T) {
	f := startFakeDNS(t, "example.test.", "validation.example.net.")
	f.cname["_acme-challenge.app.example.test."] = "app.validation.example.net."
	setDNSResolvers([]string{f.addr})
	t.Cleanup(func() { dns01.SetDefaultClient(dns01.NewClient(nil)) })
	key := writeTSIGKey(t, "hmac-sha256", testTSIGSecret)
	m, err := newDNSMux([]DNSSolverConfig{
		{Name: "validation", Provider: ProviderRFC2136, Nameserver: f.addr, TSIGFile: key, Zones: []string{"validation.example.net"}},
	}, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Present(context.Background(), "app.example.test", "tok", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if got := f.records("app.validation.example.net."); len(got) != 1 {
		t.Fatalf("delegated record not written: %v", got)
	}
	if err := m.CleanUp(context.Background(), "app.example.test", "tok", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if err := m.Present(context.Background(), "other.example.test", "tok", "tok.thumb"); !dnsplugin.IsClass(err, dnsplugin.ClassPermanent) {
		t.Fatalf("uncovered name: %v", err)
	}
}

func TestCloudflareSolver(t *testing.T) {
	f := startFakeDNS(t, "example.test.")
	setDNSResolvers([]string{f.addr})
	t.Cleanup(func() { dns01.SetDefaultClient(dns01.NewClient(nil)) })
	var mu sync.Mutex
	var created, deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone1","name":"` + r.URL.Query().Get("name") + `"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone1/dns_records":
			var rec struct{ Type, Name, Content string }
			_ = json.NewDecoder(r.Body).Decode(&rec)
			created = append(created, rec.Type+" "+rec.Name)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec1","type":"TXT"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone1/dns_records/rec1":
			deleted = append(deleted, "rec1")
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec1"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "cf.token")
	_ = os.WriteFile(tok, []byte("good-token\n"), 0o600)
	cfg := DNSSolverConfig{Name: "cf", Provider: ProviderCloudflare, TokenFile: tok, APIURL: srv.URL, Zones: []string{"example.test"}}
	m, err := newDNSMux([]DNSSolverConfig{cfg}, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := m.Present(ctx, "www.example.test", "tok", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if err := m.CleanUp(ctx, "www.example.test", "tok", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(created, ",") != "TXT _acme-challenge.www.example.test" || len(deleted) != 1 {
		t.Fatalf("created %v deleted %v", created, deleted)
	}

	_ = os.WriteFile(tok, []byte("rotated-but-wrong"), 0o600)
	m, err = newDNSMux([]DNSSolverConfig{cfg}, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Present(ctx, "www.example.test", "tok", "tok.thumb"); err == nil || !strings.Contains(err.Error(), "Authentication") {
		t.Fatalf("bad token: %v", err)
	}
}

func TestWildcardSANRules(t *testing.T) {
	allowed := []string{"*.example.com", "www.example.org"}
	for _, c := range []struct {
		san       string
		wildcards bool
		want      bool
	}{
		{"*.example.com", true, true},
		{"*.example.com", false, false},
		{"*.example.org", true, false}, // a plain name never permits its wildcard
		{"a.example.com", false, true},
		{"*.*.example.com", true, false},
		{"a.*.example.com", true, false},
	} {
		if got := agentproto.SANAllowed(c.san, allowed, c.wildcards); got != c.want {
			t.Errorf("%s wildcards=%v: got %v", c.san, c.wildcards, got)
		}
	}
}

func TestIssueDNS01NeedsSolvers(t *testing.T) {
	_, err := newDNSMux(nil, quietLog)
	if err == nil || !strings.Contains(err.Error(), "no dns_solvers") {
		t.Fatalf("got %v", err)
	}
}

func TestCheckDNSSolver(t *testing.T) {
	f := startFakeDNS(t, "example.test.")
	t.Cleanup(func() { dns01.SetDefaultClient(dns01.NewClient(nil)) })
	cfg := &Config{Resolvers: []string{f.addr}, DNSSolvers: []DNSSolverConfig{{Name: "internal", Provider: ProviderRFC2136,
		Nameserver: f.addr, TSIGFile: writeTSIGKey(t, "hmac-sha256", testTSIGSecret), Zones: []string{"example.test"},
		PropagationTimeoutSeconds: 5}}}
	var out strings.Builder
	if err := CheckDNSSolver(context.Background(), cfg, "internal", "www.example.test", &out, quietLog); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"PASS  present again", "PASS  record visible", "PASS  cleanup again", "PASS  record removed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if got := f.records("_acme-challenge.www.example.test."); len(got) != 0 {
		t.Fatalf("left behind: %v", got)
	}

	cfg.DNSSolvers[0].TSIGFile = writeTSIGKey(t, "hmac-sha256", "d3JvbmctZnJvbmctd3Jvbmctd3Jvbmctd3Jvbmc=")
	out.Reset()
	if err := CheckDNSSolver(context.Background(), cfg, "internal", "www.example.test", &out, quietLog); err == nil ||
		!strings.Contains(out.String(), "FAIL  present") {
		t.Fatalf("wrong key: %v\n%s", err, out.String())
	}
}
