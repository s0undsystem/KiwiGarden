package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestCheckIP(t *testing.T) {
	cases := []struct {
		ip   string
		ok   bool
		note string
	}{
		{"8.8.8.8", true, "public v4"},
		{"50.116.2.70", true, "kiwisdr.com proxy"},
		{"193.253.49.125", true, "a real receiver"},
		{"2606:4700::1111", true, "public v6"},
		{"127.0.0.1", false, "loopback"},
		{"127.255.255.254", false, "loopback range"},
		{"::1", false, "v6 loopback"},
		{"0.0.0.0", false, "unspecified"},
		{"0.1.2.3", false, "this network"},
		{"::", false, "v6 unspecified"},
		{"10.0.0.1", false, "private 10/8"},
		{"10.255.255.255", false, "private 10/8 end"},
		{"172.16.0.1", false, "private 172.16/12"},
		{"172.31.255.255", false, "private 172.16/12 end"},
		{"172.32.0.1", true, "just outside 172.16/12"},
		{"192.168.1.1", false, "private 192.168/16"},
		{"169.254.169.254", false, "link-local (cloud metadata)"},
		{"100.64.0.1", false, "CGNAT"},
		{"100.127.255.255", false, "CGNAT end"},
		{"100.128.0.1", true, "just outside CGNAT"},
		{"224.0.0.1", false, "multicast"},
		{"239.255.255.255", false, "multicast end"},
		{"255.255.255.255", false, "broadcast"},
		{"240.0.0.1", false, "reserved"},
		{"192.0.2.1", false, "TEST-NET-1"},
		{"198.51.100.1", false, "TEST-NET-2"},
		{"203.0.113.1", false, "TEST-NET-3"},
		{"198.18.0.1", false, "benchmarking"},
		{"192.0.0.1", false, "IETF assignments"},
		{"192.88.99.1", false, "6to4 anycast"},
		{"::ffff:127.0.0.1", false, "v4-mapped loopback"},
		{"::ffff:10.0.0.1", false, "v4-mapped private"},
		{"::ffff:169.254.1.1", false, "v4-mapped link-local"},
		{"::ffff:8.8.8.8", true, "v4-mapped public"},
		{"64:ff9b::7f00:1", false, "NAT64 loopback"},
		{"64:ff9b::a00:1", false, "NAT64 private"},
		{"64:ff9b::808:808", true, "NAT64 public"},
		{"64:ff9b:1::1", false, "local-use NAT64"},
		{"fe80::1", false, "v6 link-local"},
		{"fec0::1", false, "v6 site-local"},
		{"fc00::1", false, "ULA"},
		{"fd12:3456::1", false, "ULA fd"},
		{"ff02::1", false, "v6 multicast"},
		{"ff01::1", false, "v6 interface-local multicast"},
		{"100::1", false, "discard-only"},
		{"2001::1", false, "Teredo"},
		{"2002:0a00:0001::1", false, "6to4"},
		{"2001:db8::1", false, "documentation"},
		{"2001:2::1", false, "v6 benchmarking"},
		{"2001:10::1", false, "ORCHID"},
		{"2001:20::1", false, "ORCHIDv2"},
	}
	var p Policy
	for _, c := range cases {
		t.Run(c.ip+" "+c.note, func(t *testing.T) {
			addr := netip.MustParseAddr(c.ip)
			err := p.CheckIP(addr)
			if c.ok && err != nil {
				t.Fatalf("expected allow, got %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("expected reject")
				}
				if !errors.Is(err, ErrForbidden) {
					t.Fatalf("error not wrapped: %v", err)
				}
			}
		})
	}
}

func TestZonedAddressRejected(t *testing.T) {
	var p Policy
	if err := p.CheckIP(netip.MustParseAddr("fe80::1%en0")); err == nil {
		t.Fatal("zoned address accepted")
	}
	if err := p.CheckIP(netip.MustParseAddr("2606:4700::1111%en0")); err == nil {
		t.Fatal("zoned public address accepted")
	}
}

func TestAllowLoopbackIsTestOnly(t *testing.T) {
	var p Policy
	if p.AllowLoopback {
		t.Fatal("zero value must not allow loopback")
	}
	if err := p.CheckIP(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("loopback allowed by default")
	}
	p.AllowLoopback = true
	if err := p.CheckIP(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatal("test policy should allow loopback")
	}
	// AllowLoopback must not loosen anything else.
	if err := p.CheckIP(netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Fatal("AllowLoopback leaked into private ranges")
	}
}

func TestCheckPort(t *testing.T) {
	cases := []struct {
		port int
		ok   bool
	}{
		{80, true}, {443, true}, {1024, true}, {8073, true}, {65535, true},
		{0, false}, {1, false}, {22, false}, {25, false}, {53, false}, {79, false}, {81, false},
		{139, false}, {445, false}, {631, false}, {1023, false}, {65536, false}, {-1, false},
	}
	var p Policy
	for _, c := range cases {
		err := p.CheckPort(c.port)
		if c.ok != (err == nil) {
			t.Errorf("port %d: ok=%v err=%v", c.port, c.ok, err)
		}
	}
}

func TestParsePort(t *testing.T) {
	good := map[string]int{"80": 80, "8073": 8073, "65535": 65535}
	for s, want := range good {
		if got, err := ParsePort(s); err != nil || got != want {
			t.Errorf("ParsePort(%q) = %d, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "0", "08073", "+80", "80 ", "65536", "abc", "-1", "0x50"} {
		if _, err := ParsePort(s); err == nil {
			t.Errorf("ParsePort(%q) accepted", s)
		}
	}
}

func TestCheckAddrPort(t *testing.T) {
	var p Policy
	bad := []string{"127.0.0.1:8073", "8.8.8.8:22", "[::1]:80", "[fe80::1]:8073", "garbage", "8.8.8.8", ":80", "8.8.8.8:0"}
	for _, a := range bad {
		if err := p.CheckAddrPort(a); err == nil {
			t.Errorf("accepted %q", a)
		}
	}
	for _, a := range []string{"8.8.8.8:8073", "8.8.8.8:80", "[2606:4700::1111]:443"} {
		if err := p.CheckAddrPort(a); err != nil {
			t.Errorf("rejected %q: %v", a, err)
		}
	}
}

// TestDialerRefusesLoopback proves the Control hook fires on the resolved
// address: a listener on 127.0.0.1 must be unreachable through the dialer.
func TestDialerRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var p Policy
	d := p.Dialer(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		c.Close()
		t.Fatal("dialer connected to loopback")
	}
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	// The hostname form must also be caught after resolution.
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err = d.DialContext(ctx, "tcp", "localhost:"+port)
	if err == nil {
		c.Close()
		t.Fatal("dialer connected to localhost by name")
	}
	// With the test switch the same dial must succeed.
	pt := Policy{AllowLoopback: true}
	c, err = pt.Dialer(2*time.Second).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("test policy dial failed: %v", err)
	}
	c.Close()
}

func TestDialerRefusesNonTCP(t *testing.T) {
	var p Policy
	d := p.Dialer(time.Second)
	if err := d.Control("udp", "8.8.8.8:53", nil); err == nil {
		t.Fatal("udp accepted")
	}
	if err := d.Control("unix", "/tmp/x", nil); err == nil {
		t.Fatal("unix accepted")
	}
}
