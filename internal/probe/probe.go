package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/alexandrosnt/certloom/internal/certparse"
)

// Target is one endpoint to probe.
type Target struct {
	Host string // hostname or IP literal
	Port int
	SNI  string // empty => Host if Host is a name, none if Host is an IP
}

// Observation is what a single probe saw. Error fields are set on failure.
type Observation struct {
	ObservedAt time.Time                `json:"observed_at"`
	Address    string                   `json:"address,omitempty"` // pinned IP:port actually dialed
	SNI        string                   `json:"sni,omitempty"`
	Chain      []*certparse.Certificate `json:"chain,omitempty"` // as served, leaf first
	TLSVersion string                   `json:"tls_version,omitempty"`
	Cipher     string                   `json:"cipher,omitempty"`
	ALPN       string                   `json:"alpn,omitempty"`
	LatencyMS  int64                    `json:"latency_ms"`
	ErrorClass string                   `json:"error_class,omitempty"` // scope_denied, dns, refused, timeout, tls, parse, network
	Error      string                   `json:"error,omitempty"`
}

// Leaf returns the served leaf or nil.
func (o *Observation) Leaf() *certparse.Certificate {
	if len(o.Chain) == 0 {
		return nil
	}
	return o.Chain[0]
}

// Resolver is the subset of net.Resolver used, for testing.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Prober performs scoped TLS probes.
type Prober struct {
	Resolver Resolver
	Timeout  time.Duration // per probe, default 10s
	Now      func() time.Time
}

// New returns a Prober with the system resolver.
func New() *Prober {
	return &Prober{Resolver: net.DefaultResolver, Timeout: 10 * time.Second, Now: time.Now}
}

// Probe resolves the target once, checks every candidate address against the
// scope, dials the first allowed address (pinning it, so DNS rebinding cannot
// redirect the connection), and records the presented chain. The chain is
// recorded even when untrusted; trust is evaluated separately (certparse.Verify).
func (p *Prober) Probe(ctx context.Context, scope *Scope, t Target) *Observation {
	now := p.Now
	if now == nil {
		now = time.Now
	}
	obs := &Observation{ObservedAt: now().UTC(), SNI: t.SNI}
	fail := func(class string, err error) *Observation {
		obs.ErrorClass, obs.Error = class, err.Error()
		return obs
	}
	if t.Port <= 0 || t.Port > 65535 {
		return fail("scope_denied", fmt.Errorf("invalid port %d", t.Port))
	}
	if err := scope.CheckHost(t.Host, t.Port); err != nil {
		return fail("scope_denied", err)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var addrs []netip.Addr
	if a, err := netip.ParseAddr(t.Host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		if obs.SNI == "" {
			obs.SNI = t.Host
		}
		res, err := p.Resolver.LookupNetIP(ctx, "ip", t.Host)
		if err != nil {
			return fail("dns", err)
		}
		addrs = res
	}
	var addr netip.Addr
	var denyErr error
	for _, a := range addrs {
		if err := scope.CheckAddr(a); err != nil {
			denyErr = err
			continue
		}
		addr = a
		break
	}
	if !addr.IsValid() {
		if denyErr == nil {
			denyErr = errors.New("no addresses")
		}
		return fail("scope_denied", denyErr)
	}
	obs.Address = net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(t.Port))

	cfg := &tls.Config{
		ServerName: obs.SNI,
		// We must capture certificates the client would reject (expired,
		// untrusted, wrong host) in order to report on them. Nothing is sent
		// after the handshake, and trust is evaluated separately.
		InsecureSkipVerify: true, //nolint:gosec // see comment above
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	start := time.Now()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", obs.Address)
	obs.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		return fail(classifyDialErr(err), err)
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	obs.TLSVersion = tls.VersionName(st.Version)
	obs.Cipher = tls.CipherSuiteName(st.CipherSuite)
	obs.ALPN = st.NegotiatedProtocol
	for _, c := range st.PeerCertificates {
		pc, err := certparse.FromX509(c)
		if err != nil {
			return fail("parse", err)
		}
		obs.Chain = append(obs.Chain, pc)
	}
	if len(obs.Chain) == 0 {
		return fail("tls", errors.New("server presented no certificates"))
	}
	return obs
}

func classifyDialErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case isRefused(err):
		return "refused"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return "network"
	}
	return "tls"
}
