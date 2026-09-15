package ban

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	t.Parallel()

	// Shaped like LocalInterfacePrefixes' output: host addresses, not subnets.
	ifaces := func() ([]netip.Prefix, error) {
		return []netip.Prefix{
			netip.MustParsePrefix("192.0.2.10/32"),
			netip.MustParsePrefix("2001:db8::1/128"),
		}, nil
	}

	tests := []struct {
		name       string
		allowlist  []string
		allowLocal bool
		ifaces     InterfaceLister
		ip         string
		want       bool
	}{
		{name: "unlisted v4", ip: "203.0.113.7", want: false},
		{name: "unlisted v6", ip: "2001:db8:ffff::1", want: false},
		{name: "explicit v4 host", allowlist: []string{"203.0.113.7/32"}, ip: "203.0.113.7", want: true},
		{name: "explicit v4 cidr", allowlist: []string{"10.0.0.0/8"}, ip: "10.1.2.3", want: true},
		{name: "outside v4 cidr", allowlist: []string{"10.0.0.0/8"}, ip: "11.1.2.3", want: false},
		{name: "explicit v6 cidr", allowlist: []string{"2001:db8::/32"}, ip: "2001:db8:1::99", want: true},
		{name: "outside v6 cidr", allowlist: []string{"2001:db8::/32"}, ip: "2001:db9::1", want: false},
		{name: "v4 cidr does not match v6", allowlist: []string{"10.0.0.0/8"}, ip: "::a01:203", want: false},
		// The v4-in-v6 spellings of an allowlisted v4 address must match; this
		// is the lockout footgun.
		{name: "v4-in-v6 of allowlisted v4", allowlist: []string{"10.0.0.0/8"}, ip: "::ffff:10.1.2.3", want: true},
		{name: "v4-mapped prefix in allowlist", allowlist: []string{"::ffff:10.0.0.0/104"}, ip: "10.5.5.5", want: true},

		{name: "loopback v4 with allow_local", allowLocal: true, ip: "127.0.0.1", want: true},
		{name: "loopback v4 alt with allow_local", allowLocal: true, ip: "127.2.3.4", want: true},
		{name: "loopback v6 with allow_local", allowLocal: true, ip: "::1", want: true},
		{name: "v4-in-v6 loopback with allow_local", allowLocal: true, ip: "::ffff:127.0.0.1", want: true},
		{name: "loopback without allow_local", ip: "127.0.0.1", want: false},
		{name: "v4-in-v6 loopback without allow_local", ip: "::ffff:127.0.0.1", want: false},

		{name: "own interface v4", allowLocal: true, ifaces: ifaces, ip: "192.0.2.10", want: true},
		// Only the host address is exempt, never its whole subnet.
		{name: "neighbour on interface subnet", allowLocal: true, ifaces: ifaces, ip: "192.0.2.11", want: false},
		{name: "own interface v6", allowLocal: true, ifaces: ifaces, ip: "2001:db8::1", want: true},
		{name: "interfaces ignored without allow_local", ifaces: ifaces, ip: "192.0.2.10", want: false},

		{name: "unspecified v4 is never banned", ip: "0.0.0.0", want: true},
		{name: "unspecified v6 is never banned", ip: "::", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var list []netip.Prefix
			for _, s := range tt.allowlist {
				list = append(list, prefix(t, s))
			}
			m, _, _, _ := newTestManager(t, func(o *Options) {
				o.Allowlist = list
				o.AllowLocal = tt.allowLocal
				if tt.ifaces != nil {
					o.Interfaces = tt.ifaces
				}
			})
			if got := m.Allowed(addr(t, tt.ip)); got != tt.want {
				t.Errorf("Allowed(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestAllowedInvalidAddr(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	if !m.Allowed(netip.Addr{}) {
		t.Error("the zero Addr must be treated as allowed; there is nothing to enforce")
	}
}

func TestAllowedZoneIsIgnored(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, func(o *Options) {
		o.Allowlist = []netip.Prefix{prefix(t, "fe80::/10")}
	})
	if !m.Allowed(addr(t, "fe80::1%eth0")) {
		t.Error("a zone-suffixed address must still match its prefix")
	}
}

func TestInterfaceListerFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, func(o *Options) {
		o.AllowLocal = true
		o.Allowlist = []netip.Prefix{prefix(t, "10.0.0.0/8")}
		o.Interfaces = func() ([]netip.Prefix, error) { return nil, errors.New("no netlink for you") }
	})
	if !m.Allowed(addr(t, "127.0.0.1")) {
		t.Error("loopback must stay allowed when the interface lister fails")
	}
	if !m.Allowed(addr(t, "10.1.1.1")) {
		t.Error("explicit allowlist must survive an interface lister failure")
	}
	if m.Allowed(addr(t, "203.0.113.1")) {
		t.Error("a failing lister must not allow everything")
	}
}

func TestNormalizePrefixesDropsUnusable(t *testing.T) {
	t.Parallel()
	in := []netip.Prefix{
		{}, // invalid
		netip.PrefixFrom(addr(t, "::ffff:0.0.0.0"), 8), // v4-mapped with too few bits
		netip.MustParsePrefix("10.1.2.3/8"),            // must come back masked
	}
	out, bad := normalizePrefixes(in)
	if len(bad) != 2 {
		t.Fatalf("bad = %v, want 2 entries", bad)
	}
	if len(out) != 1 || out[0].String() != "10.0.0.0/8" {
		t.Fatalf("out = %v, want [10.0.0.0/8]", out)
	}
}

func TestLocalInterfacePrefixesIsHostScoped(t *testing.T) {
	t.Parallel()
	// The real lister is allowed to touch the host's NICs (read-only); we only
	// assert the shape, never the contents, so the test stays hermetic.
	got, err := LocalInterfacePrefixes()
	if err != nil {
		t.Skipf("interface enumeration unavailable: %v", err)
	}
	for _, p := range got {
		if p.Bits() != p.Addr().BitLen() {
			t.Errorf("%v: want a single-host prefix, got /%d", p, p.Bits())
		}
	}
}

func TestOffendOnAllowlistedIPIsSilentNoop(t *testing.T) {
	t.Parallel()
	m, _, fe, fp := newTestManager(t, func(o *Options) {
		o.AllowLocal = true
		o.Allowlist = []netip.Prefix{prefix(t, "203.0.113.0/24")}
	})
	m.SetPolicy("sshd", Policy{Bantime: time.Hour})

	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::1", "203.0.113.9"} {
		m.Offend("sshd", addr(t, ip), 10)
	}
	if n := len(fe.banned()); n != 0 {
		t.Errorf("enforcer saw %d bans, want 0", n)
	}
	if n := fp.calls(); n != 0 {
		t.Errorf("persister called %d times, want 0", n)
	}
	if n := len(m.Snapshot()); n != 0 {
		t.Errorf("snapshot has %d bans, want 0", n)
	}
	if got := m.Stats().Allowlisted; got != 4 {
		t.Errorf("Stats().Allowlisted = %d, want 4", got)
	}
}

func TestManualBanOnAllowlistedIPErrors(t *testing.T) {
	t.Parallel()
	m, _, fe, _ := newTestManager(t, func(o *Options) { o.AllowLocal = true })
	err := m.Ban(addr(t, "::ffff:127.0.0.1"), "manual", time.Hour)
	if !errors.Is(err, ErrAllowlisted) {
		t.Fatalf("Ban(loopback) = %v, want ErrAllowlisted", err)
	}
	if n := len(fe.banned()); n != 0 {
		t.Errorf("enforcer saw %d bans, want 0", n)
	}
}

func TestManualBanInvalidAddr(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	if err := m.Ban(netip.Addr{}, "manual", time.Hour); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("Ban(invalid) = %v, want ErrInvalidAddr", err)
	}
}
