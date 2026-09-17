package rule

import (
	"fmt"
	"net/netip"
	"strings"
)

// The <IP> macro. Writing an address regex by hand is miserable and easy to
// get subtly wrong, so every user writes <IP> and never thinks about it again;
// this is therefore the single most load-bearing string in the package.
//
// The grammar below is RFC 3986's IPv6address, written out in the same order
// the RFC lists its alternatives. Order matters: Go's regexp is leftmost-first
// (not leftmost-longest), so alternatives that can match more must come first
// or a valid address gets truncated to a prefix that netip then rejects.
const (
	// A dotted-quad octet. Leading zeros are deliberately unmatchable: "010"
	// is octal in some resolvers and decimal in others, and banning the wrong
	// host because of it is worse than not banning at all.
	octetPattern = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

	// ipv4Pattern is a dotted-quad. It is not anchored; boundary conditions
	// that RE2 cannot express (no lookaround) are checked after the match by
	// boundaryOK.
	ipv4Pattern = octetPattern + `(?:\.` + octetPattern + `){3}`

	h16Pattern  = `[0-9A-Fa-f]{1,4}`
	ls32Pattern = `(?:` + h16Pattern + `:` + h16Pattern + `|` + ipv4Pattern + `)`

	ipv6Pattern = `(?:` +
		`(?:` + h16Pattern + `:){6}` + ls32Pattern + `|` +
		`::(?:` + h16Pattern + `:){5}` + ls32Pattern + `|` +
		`(?:` + h16Pattern + `)?::(?:` + h16Pattern + `:){4}` + ls32Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,1}` + h16Pattern + `)?::(?:` + h16Pattern + `:){3}` + ls32Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,2}` + h16Pattern + `)?::(?:` + h16Pattern + `:){2}` + ls32Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,3}` + h16Pattern + `)?::` + h16Pattern + `:` + ls32Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,4}` + h16Pattern + `)?::` + ls32Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,5}` + h16Pattern + `)?::` + h16Pattern + `|` +
		`(?:(?:` + h16Pattern + `:){0,6}` + h16Pattern + `)?::` +
		`)`

	// A DNS name, for <HOST> only. Matching one is not the same as resolving
	// it: a non-address host yields OutcomeNoIP.
	dnsPattern = `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*`

	// addrPattern matches an IPv4 or IPv6 literal. IPv6 comes first so that
	// the v4 tail of ::ffff:1.2.3.4 is not matched on its own.
	addrPattern = `(?:` + ipv6Pattern + `|` + ipv4Pattern + `)`

	// hostPattern is addrPattern plus DNS names, used by <HOST>.
	hostPattern = `(?:` + ipv6Pattern + `|` + ipv4Pattern + `|` + dnsPattern + `)`
)

// ipGroup is the capture group name every IP-bearing pattern must end up with,
// whether it came from a macro or the user wrote it themselves.
const ipGroup = "ip"

const (
	macroIP   = "<IP>"
	macroHost = "<HOST>"
)

// expansion is what the macro scanner made of a pattern: the text to hand to
// regexp.Compile, plus the two counts compilePattern needs to decide how to
// treat the result.
type expansion struct {
	pattern string // macro-expanded, ready to compile
	macros  int    // <IP>/<HOST> occurrences replaced
	// ipGroups is how many capture groups named ipGroup the pattern ends up
	// with, whether this scanner wrote them or the user did.
	ipGroups int
}

// expandMacros rewrites <IP> and <HOST> into a named capture group.
//
// Expansion is textual but not blind: it tracks escapes and character classes,
// because splicing a group into a class silently produces a regex that
// compiles and matches the wrong thing (Go reads [<IP>] as the class of
// '<','I','P','>'). A macro inside a class is therefore rejected outright. To
// match the literal text "<IP>", escape the '<' as \x3c.
//
// Capture-group names are likewise copied through untouched: the '<' of
// (?P<IP>...) opens a name, not a macro, and expanding it would splice a group
// into the middle of the syntax and leave the user staring at "invalid or
// unsupported Perl syntax: (?P".
func expandMacros(pattern string) (expansion, error) {
	// Both macros and capture-group names need a '<'; without one there is
	// nothing to scan for.
	if !strings.Contains(pattern, "<") {
		return expansion{pattern: pattern}, nil
	}
	var (
		b        strings.Builder
		exp      expansion
		inClass  bool
		classPos int // index just after '[' (and any '^'), where ']' is a literal
	)
	b.Grow(len(pattern) + len(addrPattern))
	for i := 0; i < len(pattern); {
		c := pattern[i]
		switch {
		case c == '\\':
			// Copy the escape whole; a trailing backslash is left for
			// regexp.Compile to complain about.
			if i+1 < len(pattern) {
				b.WriteString(pattern[i : i+2])
				i += 2
			} else {
				b.WriteByte(c)
				i++
			}
			continue
		case !inClass && c == '[':
			inClass = true
			b.WriteByte(c)
			i++
			if i < len(pattern) && pattern[i] == '^' {
				b.WriteByte('^')
				i++
			}
			classPos = i
			continue
		case inClass && c == '[' && i+1 < len(pattern) && pattern[i+1] == ':':
			// POSIX class such as [:alpha:]; its ']' does not close ours.
			if end := strings.Index(pattern[i:], ":]"); end >= 0 {
				b.WriteString(pattern[i : i+end+2])
				i += end + 2
				continue
			}
			b.WriteByte(c)
			i++
			continue
		case inClass && c == ']':
			if i > classPos {
				inClass = false
			}
			b.WriteByte(c)
			i++
			continue
		case !inClass && c == '(':
			name, n := groupNameAt(pattern[i:])
			if n == 0 {
				break
			}
			if name == ipGroup {
				exp.ipGroups++
			}
			b.WriteString(pattern[i : i+n])
			i += n
			continue
		case c == '<':
			var macro, group string
			switch {
			case strings.HasPrefix(pattern[i:], macroIP):
				macro, group = macroIP, addrPattern
			case strings.HasPrefix(pattern[i:], macroHost):
				macro, group = macroHost, hostPattern
			}
			if macro == "" {
				break
			}
			if inClass {
				return expansion{}, fmt.Errorf("%s inside a character class is not supported (escape the '<' as \\x3c to match it literally)", macro)
			}
			b.WriteString(`(?P<` + ipGroup + `>` + group + `)`)
			i += len(macro)
			exp.macros++
			exp.ipGroups++
			continue
		}
		b.WriteByte(c)
		i++
	}
	exp.pattern = b.String()
	return exp, nil
}

// groupNameAt reports the capture-group name opening s and the length of the
// token that introduces it. Both spellings Go accepts are recognised: the
// original (?P<name> and (?<name>, added in Go 1.22.
//
// A malformed name yields the length of the opener alone and an empty name, so
// that the rest of the pattern reaches regexp.Compile as the user wrote it and
// the error describes the real problem.
func groupNameAt(s string) (name string, n int) {
	var open int
	switch {
	case strings.HasPrefix(s, "(?P<"):
		open = len("(?P<")
	case strings.HasPrefix(s, "(?<"):
		open = len("(?<")
	default:
		return "", 0
	}
	for i := open; i < len(s); i++ {
		switch {
		case s[i] == '>':
			return s[open:i], i + 1
		case !isNameByte(s[i]):
			return "", open
		}
	}
	return "", open
}

// isNameByte reports whether c may appear in a capture-group name; Go's regexp
// parser accepts word characters only.
func isNameByte(c byte) bool {
	return c == '_' || isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'z')
}

// boundaryOK reports whether the address text at sub[s:e] is delimited by
// something that cannot be part of an address.
//
// RE2 has no lookaround, so the regex alone happily finds "99.1.1.1" inside
// "999.1.1.1" and "1.2.3.4" inside "1.2.3.4.5". Rejecting those is a
// correctness requirement — banning a truncation of an address bans a host
// that never appeared in the log — so the check is done here instead, on the
// bytes either side of the capture. It is applied only to macro-generated
// groups; a user who writes their own (?P<ip>...) owns its boundaries.
func boundaryOK[T string | []byte](sub T, s, e int, v6 bool) bool {
	if s > 0 {
		prev := sub[s-1]
		switch {
		case isHexish(prev, v6):
			return false
		case prev == '.' && s > 1 && isDigit(sub[s-2]):
			return false
		case v6 && prev == ':' && s > 1 && (isHexDigit(sub[s-2]) || sub[s-2] == ':'):
			return false
		}
	}
	if e < len(sub) {
		next := sub[e]
		switch {
		case isHexish(next, v6):
			return false
		case next == '.' && e+1 < len(sub) && isDigit(sub[e+1]):
			return false
		case v6 && next == ':' && e+1 < len(sub) && (isHexDigit(sub[e+1]) || sub[e+1] == ':'):
			return false
		case v6 && next == '%':
			// A zone suffix we deliberately did not capture; the address is
			// link-local and scoped, so the bare part is not a usable key.
			return false
		}
	}
	return true
}

// isHexish reports whether c could have continued the address: any digit for
// IPv4, any hex digit for IPv6. Non-hex letters are treated as delimiters so
// that "rhost=1.2.3.4" and "ip1.2.3.4" both yield an address.
func isHexish(c byte, v6 bool) bool {
	if v6 {
		return isHexDigit(c)
	}
	return isDigit(c)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'f')
}

// parseIP turns matched text into the canonical key used everywhere else.
//
// v4-in-v6 is unmapped so ::ffff:1.2.3.4 and 1.2.3.4 count the same attacker.
// Zone-suffixed and unspecified addresses are refused: the first is not a
// stable identity, the second (0.0.0.0 / ::) is never a real offender and is
// usually the result of a truncated match.
func parseIP(text string) (netip.Addr, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		// JSON fields such as nginx's remote_addr often carry a port.
		if ap, perr := netip.ParseAddrPort(text); perr == nil {
			addr = ap.Addr()
		} else if len(text) > 2 && text[0] == '[' && text[len(text)-1] == ']' {
			inner, ierr := netip.ParseAddr(text[1 : len(text)-1])
			if ierr != nil {
				return netip.Addr{}, false
			}
			addr = inner
		} else {
			return netip.Addr{}, false
		}
	}
	if addr.Zone() != "" {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
