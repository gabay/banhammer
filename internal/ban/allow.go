package ban

import (
	"fmt"
	"net"
	"net/netip"
)

// InterfaceLister reports the addresses that belong to this host. It is a field
// on Options so tests never depend on the machine's real NICs.
type InterfaceLister func() ([]netip.Prefix, error)

// LocalInterfacePrefixes is the default InterfaceLister: every unicast address
// configured on a local interface, as a single-host prefix.
//
// Host addresses, not the interface subnets: allowlisting the whole /24 an
// interface sits on would silently exempt an attacker sharing the LAN.
func LocalInterfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("listing interface addresses: %w", err)
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		out = append(out, hostPrefix(addr))
	}
	return out, nil
}

// hostPrefix turns an address into its /32 or /128, normalised: v4-in-v6 is
// unmapped and any zone is dropped so that comparisons key on the address
// alone (::ffff:127.0.0.1 and 127.0.0.1 must behave identically).
func hostPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen())
}

// normalizePrefixes canonicalises operator-supplied prefixes so Contains works:
// a v4-mapped prefix such as ::ffff:10.0.0.0/104 becomes 10.0.0.0/8, and every
// prefix is masked. Prefixes that cannot be interpreted are dropped and
// reported to the caller for logging rather than failing construction — a bad
// allowlist entry must not stop the daemon from starting.
func normalizePrefixes(in []netip.Prefix) (out []netip.Prefix, bad []netip.Prefix) {
	out = make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			bad = append(bad, p)
			continue
		}
		addr := p.Addr()
		bits := p.Bits()
		if addr.Is4In6() {
			bits -= 96
			if bits < 0 {
				bad = append(bad, p)
				continue
			}
			addr = addr.Unmap()
		}
		np := netip.PrefixFrom(addr.WithZone(""), bits)
		if !np.IsValid() {
			bad = append(bad, p)
			continue
		}
		out = append(out, np.Masked())
	}
	return out, bad
}

// Allowed reports whether ip must never be banned. It is the lockout guard, so
// it is consulted before anything else and errs towards "allowed": an invalid
// address is allowed (there is nothing sane to enforce against), as is the
// unspecified address, whose firewall rule would match every packet.
//
// Safe for concurrent use: the allowlist is immutable after NewManager.
func (m *Manager) Allowed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsUnspecified() {
		return true
	}
	if m.allowLocal && ip.IsLoopback() {
		return true
	}
	for _, p := range m.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
