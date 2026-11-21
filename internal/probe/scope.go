// Package probe performs TLS handshakes against explicitly scoped endpoints
// and records the served certificate chain. It never sends application data.
package probe

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
)

// Scope is an opt-in network scope. An address is probed
// only if it is allowed by the scope AND not caught by the default denylist,
// unless the scope explicitly overrides that denylist category.
type Scope struct {
	Name string
	// AllowCIDRs lists permitted destination networks. Empty means "any
	// public address" (still subject to the denylist).
	AllowCIDRs []netip.Prefix
	// AllowHosts lists permitted hostname patterns (path.Match syntax, e.g.
	// "*.example.com"). Empty means any hostname.
	AllowHosts []string
	// Overrides for default-denied categories. Each override is audited by the caller.
	AllowLoopback  bool
	AllowPrivate   bool // RFC 1918 / RFC 4193 / CGNAT
	AllowLinkLocal bool
	// Ports permitted; empty means 443 only.
	Ports []int
}

// DeniedError is returned when the scope forbids a target.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return "probe denied by scope: " + e.Reason }

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	metadata4 = netip.MustParseAddr("169.254.169.254")
	metadata6 = netip.MustParseAddr("fd00:ec2::254")
)

// CheckHost validates the hostname and port before resolution.
func (s *Scope) CheckHost(host string, port int) error {
	ports := s.Ports
	if len(ports) == 0 {
		ports = []int{443}
	}
	okPort := false
	for _, p := range ports {
		okPort = okPort || p == port
	}
	if !okPort {
		return &DeniedError{fmt.Sprintf("port %d not in scope %q", port, s.Name)}
	}
	if len(s.AllowHosts) == 0 {
		return nil
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range s.AllowHosts {
		if ok, _ := path.Match(strings.ToLower(pat), h); ok {
			return nil
		}
	}
	return &DeniedError{fmt.Sprintf("host %q not in scope %q", host, s.Name)}
}

// CheckAddr validates a resolved destination address.
func (s *Scope) CheckAddr(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified():
		return &DeniedError{"unspecified address"}
	case a == metadata4 || a == metadata6:
		// Cloud metadata endpoints are never probe targets, regardless of overrides.
		return &DeniedError{"cloud metadata address"}
	case a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return &DeniedError{"multicast address"}
	case a.IsLoopback() && !s.AllowLoopback:
		return &DeniedError{"loopback address (enable allow_loopback on the scope to permit)"}
	case (a.IsLinkLocalUnicast()) && !s.AllowLinkLocal:
		return &DeniedError{"link-local address"}
	case (a.IsPrivate() || cgnat.Contains(a)) && !s.AllowPrivate:
		return &DeniedError{"private address (enable allow_private on the scope to permit)"}
	}
	if len(s.AllowCIDRs) == 0 {
		return nil
	}
	for _, p := range s.AllowCIDRs {
		if p.Contains(a) {
			return nil
		}
	}
	return &DeniedError{fmt.Sprintf("address %s not in scope %q", a, s.Name)}
}
