package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// duration is a time.Duration that decodes from a Go duration string.
//
// Decoding straight into time.Duration would make yaml.v3 read `bantime: 1h`
// as a type error and `bantime: 3600` as 3.6µs — precisely the kind of silent
// surprise this config loader exists to prevent.
type duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	s, ok := scalarText(n)
	if !ok {
		return nodeErrs(msgAt(n, "expected a duration such as \"30s\", \"10m\" or \"24h\", got %s", describeNode(n)))
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		// time.ParseDuration's own text leaks its package name and never says
		// what a good value looks like, so it is replaced wholesale.
		if _, numErr := strconv.ParseFloat(strings.TrimSpace(s), 64); numErr == nil {
			return nodeErrs(msgAt(n, "invalid duration %q: a unit is required, try %q or %q", s, s+"s", s+"m"))
		}
		return nodeErrs(msgAt(n, "invalid duration %q: use a Go duration string such as \"30s\", \"10m\" or \"24h\"", s))
	}
	*d = duration(v)
	return nil
}

// get dereferences an optional duration.
func (d *duration) get() time.Duration { return time.Duration(*d) }

// intVal is an int that only accepts a plain decimal integer.
//
// yaml.v3 would otherwise truncate `threshold: 3.5` to 3 and reinterpret
// `threshold: 0x10` as 16 without a word — the same silent-coercion family as
// durations, and just as dangerous in a tool that bans people.
type intVal int

// UnmarshalYAML implements yaml.Unmarshaler.
func (i *intVal) UnmarshalYAML(n *yaml.Node) error {
	s, ok := scalarText(n)
	if !ok {
		return nodeErrs(msgAt(n, "expected a whole number, got %s", describeNode(n)))
	}
	if tag := resolveAlias(n).Tag; tag != "!!int" {
		return nodeErrs(msgAt(n, "expected a whole number, got %s (%s)", describeNode(n), s))
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		// Reachable for !!int values Atoi rejects: 0x10, 0o17, 1_000, and
		// anything past the platform's int range.
		return nodeErrs(msgAt(n, "invalid number %q: write it in plain decimal digits", s))
	}
	*i = intVal(v)
	return nil
}

// floatVal is a float64 that rejects strings, keeping `bantime_factor: "2"`
// from looking like it worked.
type floatVal float64

// UnmarshalYAML implements yaml.Unmarshaler.
func (f *floatVal) UnmarshalYAML(n *yaml.Node) error {
	s, ok := scalarText(n)
	if !ok {
		return nodeErrs(msgAt(n, "expected a number, got %s", describeNode(n)))
	}
	switch resolveAlias(n).Tag {
	case "!!int", "!!float":
	default:
		return nodeErrs(msgAt(n, "expected a number, got %s (%s)", describeNode(n), s))
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nodeErrs(msgAt(n, "invalid number %q", s))
	}
	*f = floatVal(v)
	return nil
}

// rawPrefix decodes one allowlist entry. A bare address is accepted and widened
// to a host prefix (/32 or /128) because "allowlist: [127.0.0.1]" is what people
// actually type.
type rawPrefix struct{ Prefix netip.Prefix }

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *rawPrefix) UnmarshalYAML(n *yaml.Node) error {
	s, ok := scalarText(n)
	if !ok {
		return nodeErrs(msgAt(n, "expected an IP or CIDR such as \"10.0.0.0/8\" or \"::1\", got %s", describeNode(n)))
	}
	p, err := parsePrefix(s)
	if err != nil {
		return nodeErrs(msgAt(n, "allowlist: %s", err))
	}
	r.Prefix = p
	return nil
}

// parsePrefix accepts both CIDR notation and a bare address.
//
// The result is masked so that `String()` shows what the entry actually covers:
// a user who writes 127.0.0.1/8 is better served by seeing 127.0.0.0/8 than by
// being quietly told what they typed.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty entry")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", s)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q: zone suffixes are not supported", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
