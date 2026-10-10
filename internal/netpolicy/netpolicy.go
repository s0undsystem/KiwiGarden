// Package netpolicy decides which IP addresses and ports the relay may
// connect to, and provides a net.Dialer whose Control hook enforces that
// decision on the resolved address of every connection attempt.
package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// ErrForbidden is wrapped by every policy rejection.
var ErrForbidden = errors.New("netpolicy: forbidden")

// Policy holds the (few) knobs. The zero value is the production policy.
type Policy struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1. TEST ONLY, for the mock
	// receiver. cmd/kiwi-garden never sets it.
	AllowLoopback bool
}

// Prefixes that are never a public KiwiSDR.
var blockedV4 = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // CGNAT shared address space
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, includes 255.255.255.255 broadcast
)

var blockedV6 = mustPrefixes(
	"::/128",         // unspecified
	"::1/128",        // loopback
	"::ffff:0:0/96",  // IPv4-mapped (handled by unwrapping, listed for completeness)
	"64:ff9b::/96",   // NAT64 well-known prefix (unwrapped and checked as v4)
	"64:ff9b:1::/48", // local-use NAT64
	"100::/64",       // discard-only
	"2001::/32",      // Teredo (tunnels to arbitrary v4)
	"2001:2::/48",    // benchmarking
	"2001:db8::/32",  // documentation
	"2001:10::/28",   // ORCHID
	"2001:20::/28",   // ORCHIDv2
	"2002::/16",      // 6to4
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"fec0::/10",      // deprecated site-local
	"ff00::/8",       // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// CheckIP reports whether addr is a public unicast address we may dial.
func (p Policy) CheckIP(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrForbidden)
	}
	// Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d)
	// so the embedded IPv4 is judged on its own merits.
	if addr.Is4In6() {
		addr = addr.Unmap()
	} else if addr.Is6() && netip.MustParsePrefix("64:ff9b::/96").Contains(addr) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%w: zoned address", ErrForbidden)
	}
	if addr.IsLoopback() {
		if p.AllowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback %s", ErrForbidden, addr)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsPrivate() {
		return fmt.Errorf("%w: non-public %s", ErrForbidden, addr)
	}
	blocked := blockedV6
	if addr.Is4() {
		blocked = blockedV4
	}
	for _, pfx := range blocked {
		if pfx.Contains(addr) {
			return fmt.Errorf("%w: %s in %s", ErrForbidden, addr, pfx)
		}
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("%w: not global unicast %s", ErrForbidden, addr)
	}
	return nil
}

// CheckPort reports whether port is one we may dial: 80, 443, or 1024+.
func (p Policy) CheckPort(port int) error {
	switch {
	case port == 80, port == 443:
		return nil
	case port >= 1024 && port <= 65535:
		return nil
	}
	return fmt.Errorf("%w: port %d", ErrForbidden, port)
}

// CheckAddrPort checks a resolved "ip:port" string as seen by Dialer.Control.
func (p Policy) CheckAddrPort(address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrForbidden, address)
	}
	if err := p.CheckPort(int(ap.Port())); err != nil {
		return err
	}
	return p.CheckIP(ap.Addr())
}

// Dialer returns a net.Dialer that refuses, at connect time, any resolved
// address the policy rejects. Because Control runs per attempt with the
// concrete IP, DNS answers that change between validation and connect
// (rebinding) cannot bypass it.
func (p Policy) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return fmt.Errorf("%w: network %q", ErrForbidden, network)
			}
			return p.CheckAddrPort(address)
		},
	}
}

// ParsePort parses a decimal port string strictly.
func ParsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != s {
		return 0, fmt.Errorf("%w: bad port %q", ErrForbidden, s)
	}
	return n, nil
}
