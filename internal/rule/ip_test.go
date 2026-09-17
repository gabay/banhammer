package rule

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// matchOne compiles a single line pattern and runs it, returning the extracted
// address (or "") and the outcome.
func matchOne(t *testing.T, pattern, line string) (string, Outcome) {
	t.Helper()
	set, err := Compile(Spec{Line: []string{pattern}})
	if err != nil {
		t.Fatalf("Compile(%q) error: %v", pattern, err)
	}
	res, out := set.Match([]byte(line))
	if res.IP.IsValid() {
		return res.IP.String(), out
	}
	return "", out
}

// TestIPMacroExtracts is the core of the package: every user writes <IP> and
// then never thinks about it again, so it has to be right for every address
// form that turns up in a real log.
func TestIPMacroExtracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		line    string
		want    string
	}{
		{"ipv4 bare", "<IP>", "192.168.1.10", "192.168.1.10"},
		{"ipv4 zero octets", "<IP>", "0.0.0.1", "0.0.0.1"},
		{"ipv4 max", "<IP>", "255.255.255.255", "255.255.255.255"},
		{"ipv4 with port", "<IP>", "1.2.3.4:5678", "1.2.3.4"},
		{"ipv4 after colon", "<IP>", "client:1.2.3.4 done", "1.2.3.4"},
		{"ipv4 in brackets", "<IP>", "[1.2.3.4]", "1.2.3.4"},
		{"ipv4 at end of sentence", "<IP>", "banned 1.2.3.4.", "1.2.3.4"},

		{"ipv6 full", "<IP>", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
		{"ipv6 eight groups", "<IP>", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
		{"ipv6 compressed", "<IP>", "2001:db8::1", "2001:db8::1"},
		{"ipv6 loopback", "<IP>", "::1", "::1"},
		{"ipv6 trailing compression", "<IP>", "2001:db8:: end", "2001:db8::"},
		{"ipv6 leading compression", "<IP>", "::2:3", "::2:3"},
		{"ipv6 bracketed with port", "<IP>", "client [2001:db8::1]:443 blah", "2001:db8::1"},
		{"ipv6 followed by colon", "<IP>", "2001:db8::1: connection reset", "2001:db8::1"},
		// netip only keeps the dotted form for v4-mapped addresses; an
		// embedded v4 elsewhere canonicalises to hex.
		{"ipv6 embedded v4", "<IP>", "64:ff9b::1.2.3.4", "64:ff9b::102:304"},
		{"ipv6 full with v4 tail", "<IP>", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
		{"ipv6 link local without zone", "<IP>", "fe80::1 x", "fe80::1"},
		{"ipv6 uppercase", "<IP>", "2001:DB8::AB", "2001:db8::ab"},

		// v4-mapped must unmap: the same attacker must not get two keys.
		{"v4 mapped", "<IP>", "::ffff:1.2.3.4", "1.2.3.4"},
		{"v4 mapped uppercase", "<IP>", "::FFFF:1.2.3.4", "1.2.3.4"},
		{"v4 plain for comparison", "<IP>", "1.2.3.4", "1.2.3.4"},

		// Realistic lines with realistic patterns.
		{
			"sshd failed password",
			"Failed password for .* from <IP> port",
			"Sep 15 12:00:01 host sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 55234 ssh2",
			"203.0.113.42",
		},
		{
			"sshd invalid user ipv6",
			"Invalid user .* from <IP>",
			"Sep 15 12:00:01 host sshd[1234]: Invalid user root from 2001:db8:85a3::8a2e:370:7334 port 22",
			"2001:db8:85a3::8a2e:370:7334",
		},
		{
			"sshd preauth disconnect",
			`Disconnected from authenticating user \S+ <IP> port \d+`,
			"Sep 15 12:00:01 host sshd[1]: Disconnected from authenticating user root 198.51.100.9 port 40012 [preauth]",
			"198.51.100.9",
		},
		{
			"nginx access log",
			`^<IP> - .*"(GET|POST) /wp-login`,
			`203.0.113.7 - - [15/Sep/2025:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 403 153 "-" "curl/8.0"`,
			"203.0.113.7",
		},
		{
			"nginx error log with client",
			`client: <IP>, server:`,
			`2025/09/15 12:00:00 [error] 1#1: *1 open() failed, client: 198.51.100.23, server: example.com`,
			"198.51.100.23",
		},
		{
			"caddy text log with bracketed v6",
			`\[<IP>\]:\d+`,
			`ERROR http.log.access handled request {"remote_addr": "[2001:db8::dead:beef]:51234"}`,
			"2001:db8::dead:beef",
		},
		{
			"pam authentication failure",
			"authentication failure.*rhost=<IP>",
			"Sep 15 12:00:01 host sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=192.0.2.55 user=root",
			"192.0.2.55",
		},
		{
			"postfix sasl",
			`SASL LOGIN authentication failed.*\[<IP>\]`,
			"Sep 15 12:00:01 mail postfix/smtpd[1]: warning: unknown[192.0.2.77]: SASL LOGIN authentication failed: [192.0.2.77]",
			"192.0.2.77",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, out := matchOne(t, tc.pattern, tc.line)
			if out != OutcomeMatch {
				t.Fatalf("outcome = %v, want match (ip=%q)", out, got)
			}
			if got != tc.want {
				t.Errorf("ip = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIPMacroNearMisses is the other half: text that looks like an address but
// is not. Extracting a truncation of one of these would ban a host that never
// appeared in the log.
func TestIPMacroNearMisses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want Outcome // NoMatch when nothing resembles an address at all
	}{
		{"octet too large", "999.1.1.1", OutcomeNoIP},
		{"octet 256", "256.1.1.1", OutcomeNoIP},
		{"five octets", "1.2.3.4.5", OutcomeNoIP},
		{"six octets", "1.2.3.4.5.6", OutcomeNoIP},
		{"leading zero octet", "010.1.1.1", OutcomeNoIP},
		{"leading zero later octet", "1.2.3.04", OutcomeNoIP},
		{"long digit run", "12345.1.1.1", OutcomeNoIP},
		{"trailing digits", "1.2.3.45678", OutcomeNoIP},
		{"three octets", "1.2.3", OutcomeNoMatch},
		{"version string", "version 1.2.3 build 4", OutcomeNoMatch},
		{"triple colon", ":::", OutcomeNoIP},
		{"unspecified v6", "::", OutcomeNoIP},
		{"unspecified v4", "0.0.0.0", OutcomeNoIP},
		{"nine groups", "1:2:3:4:5:6:7:8:9", OutcomeNoIP},
		{"too many groups compressed", "2001:db8::1:2:3:4:5:6:7", OutcomeNoIP},
		{"five hex digits", "2001:db8::12345", OutcomeNoIP},
		{"zone suffix", "fe80::1%eth0", OutcomeNoIP},
		{"zone suffix numeric", "fe80::1%2", OutcomeNoIP},
		{"no address at all", "no ip here, just words", OutcomeNoMatch},
		// Three groups without "::" is not IPv6, so the regex never even
		// offers a candidate: log timestamps cost nothing.
		{"timestamp", "12:00:01", OutcomeNoMatch},
		{"empty", "", OutcomeNoMatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, out := matchOne(t, "<IP>", tc.line)
			if out == OutcomeMatch {
				t.Fatalf("extracted %q from %q, want no address", got, tc.line)
			}
			if out != tc.want {
				t.Errorf("outcome = %v, want %v", out, tc.want)
			}
		})
	}
}

// A near-miss in the middle of an otherwise realistic line must not become a
// ban of a truncated address — and, just as important, must not swallow the
// real address that follows it. boundaryOK is a filter the RE2 engine knows
// nothing about, so "the leftmost match was rejected" says nothing about the
// rest of the line; an attacker who can get a near-miss token logged before
// their own address would otherwise suppress their own ban.
func TestIPMacroNearMissInContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, pattern, line string
		want                string // "" when no address may be extracted
	}{
		{"five octets in sshd line", "from <IP>", "Failed password from 1.2.3.4.5 port 22", ""},
		{"oversized octet", "from <IP> port", "Failed password from 999.1.1.1 port 22", ""},
		{"zone scoped", "from <IP> port", "Failed password from fe80::1%eth0 port 22", ""},

		// The iptables/kernel shape: the IPv6 alternative matches the MAC
		// prefix, boundaryOK rejects it, and SRC= is the actual offender.
		{
			"mac address before the real source",
			"<IP>",
			"IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:08:00 SRC=203.0.113.9 DST=10.0.0.1 PROTO=TCP",
			"203.0.113.9",
		},
		{
			"five octets then a real address",
			"from <IP>",
			"denied from 1.2.3.4.5 then from 9.9.9.9",
			"9.9.9.9",
		},
		{
			"oversized octet then a real address",
			"<IP>",
			"999.1.1.1 retried as 198.51.100.7",
			"198.51.100.7",
		},
		{
			"zone scoped then a real address",
			"<IP>",
			"fe80::1%eth0 relayed 2001:db8::5",
			"2001:db8::5",
		},
		{
			"long digit run then a real address",
			"<IP>",
			"id=12345.1.1.1 addr=192.0.2.8",
			"192.0.2.8",
		},
		// Nothing acceptable follows the near miss: still no address.
		{"near miss twice", "<IP>", "1.2.3.4.5 and 999.1.1.1", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, out := matchOne(t, tc.pattern, tc.line)
			if tc.want == "" {
				if out == OutcomeMatch {
					t.Fatalf("extracted %q from %q, want no address", got, tc.line)
				}
				return
			}
			if out != OutcomeMatch {
				t.Fatalf("outcome = %v, want match (ip=%q)", out, got)
			}
			if got != tc.want {
				t.Errorf("ip = %q, want %q", got, tc.want)
			}
		})
	}

	// The same subject reached through a decoded JSON field, which is the
	// string half of the matcher and had the identical bug.
	t.Run("string path", func(t *testing.T) {
		t.Parallel()
		for _, tc := range tests {
			set, err := Compile(Spec{Format: "json", Fields: map[string]string{"msg": tc.pattern}})
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.pattern, err)
			}
			line, err := json.Marshal(map[string]string{"msg": tc.line})
			if err != nil {
				t.Fatal(err)
			}
			res, out := set.Match(line)
			if tc.want == "" {
				if out == OutcomeMatch {
					t.Errorf("%s: extracted %v from %q, want no address", tc.name, res.IP, tc.line)
				}
				continue
			}
			if out != OutcomeMatch {
				t.Errorf("%s: outcome = %v, want match", tc.name, out)
				continue
			}
			if res.IP.String() != tc.want {
				t.Errorf("%s: ip = %v, want %v", tc.name, res.IP, tc.want)
			}
		}
	})
}

func TestHostMacro(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want string
		out  Outcome
	}{
		{"address still works", "from 1.2.3.4 port", "1.2.3.4", OutcomeMatch},
		{"ipv6 still works", "from 2001:db8::1 port", "2001:db8::1", OutcomeMatch},
		{"dns name is not an address", "from evil.example.com port", "", OutcomeNoIP},
		{"single label host", "from localhost port", "", OutcomeNoIP},
		{"near miss becomes a host", "from 999.1.1.1 port", "", OutcomeNoIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, out := matchOne(t, "from <HOST> port", tc.line)
			if out != tc.out {
				t.Fatalf("outcome = %v, want %v (ip=%q)", out, tc.out, got)
			}
			if got != tc.want {
				t.Errorf("ip = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExpandMacros(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		count   int
		groups  int
		wantErr string
		// wantSub is text the expansion must contain.
		wantSub string
	}{
		{name: "no macro", in: `Failed password`, wantSub: "Failed password"},
		{name: "ip macro", in: `from <IP>`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "host macro", in: `from <HOST>`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "two macros", in: `<IP> -> <IP>`, count: 2, groups: 2},
		{name: "angle brackets that are not a macro", in: `a<b>c`, wantSub: `a<b>c`},
		{name: "lowercase is not a macro", in: `<ip>`, wantSub: `<ip>`},
		{name: "prefix only", in: `<I`, wantSub: `<I`},
		{name: "escaped angle is left alone", in: `\x3cIP>`, wantSub: `\x3cIP>`},
		{name: "macro after an escaped bracket", in: `\[<IP>\]`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "macro after a closed class", in: `[abc]<IP>`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "macro after a negated class", in: `[^]]<IP>`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "macro after a posix class", in: `[[:digit:]]<IP>`, count: 1, groups: 1, wantSub: `(?P<ip>`},
		{name: "macro after a class containing a bracket", in: `[]a]<IP>`, count: 1, groups: 1, wantSub: `(?P<ip>`},

		// A group name is a token, not pattern text. Expanding the <IP> in
		// (?P<IP>...) used to produce (?P(?P<ip>...)...) and an error about
		// Perl syntax that named nothing the user had written.
		{name: "user group named IP", in: `(?P<IP>[0-9.]+)`, wantSub: `(?P<IP>[0-9.]+)`},
		{name: "user group named HOST", in: `(?P<HOST>\S+)`, wantSub: `(?P<HOST>\S+)`},
		{name: "user group named ip", in: `(?P<ip>[0-9.]+)`, groups: 1, wantSub: `(?P<ip>[0-9.]+)`},
		{name: "go 1.22 spelling", in: `(?<ip>[0-9.]+)`, groups: 1, wantSub: `(?<ip>[0-9.]+)`},
		{name: "go 1.22 spelling named IP", in: `(?<IP>[0-9.]+)`, wantSub: `(?<IP>[0-9.]+)`},
		{name: "other group name", in: `(?P<user>\S+) from <IP>`, count: 1, groups: 1, wantSub: `(?P<user>\S+)`},
		{name: "macro inside a named group", in: `(?P<outer><IP>)`, count: 1, groups: 1, wantSub: `(?P<outer>(?P<ip>`},
		{name: "group name in a class is just text", in: `[(?P<]<IP>`, count: 1, groups: 1, wantSub: `[(?P<]`},
		{name: "escaped paren is not a group", in: `\(?P<IP>`, count: 1, groups: 1, wantSub: `\(?P(?P<ip>`},
		{name: "unnamed group", in: `(?:a|b) <IP>`, count: 1, groups: 1, wantSub: `(?:a|b) `},

		// The documented decision: a macro inside a character class is an
		// error rather than a silently wrong regex.
		{name: "ip in class", in: `[<IP>]`, wantErr: "character class"},
		{name: "host in class", in: `[a<HOST>]`, wantErr: "character class"},
		{name: "ip in negated class", in: `[^<IP>]`, wantErr: "character class"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := expandMacros(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expandMacros(%q) = %q, want error containing %q", tc.in, got.pattern, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandMacros(%q) error: %v", tc.in, err)
			}
			if got.macros != tc.count {
				t.Errorf("macro count = %d, want %d", got.macros, tc.count)
			}
			if got.ipGroups != tc.groups {
				t.Errorf("ip group count = %d, want %d", got.ipGroups, tc.groups)
			}
			if tc.wantSub != "" && !strings.Contains(got.pattern, tc.wantSub) {
				t.Errorf("expansion %q does not contain %q", got.pattern, tc.wantSub)
			}
		})
	}
}

// A pattern the user wrote with their own (?P<IP>...) group has to compile and
// run, not die inside the macro expander.
func TestUserWrittenUppercaseGroup(t *testing.T) {
	t.Parallel()
	// The group is named "IP", not "ip", so it is not an address source: the
	// pattern matches and reports no_ip, exactly as any other group would.
	set, err := Compile(Spec{Line: []string{`from (?P<IP>[0-9.]+) port`}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, out := set.Match([]byte("from 1.2.3.4 port 22")); out != OutcomeNoIP {
		t.Errorf("outcome = %v, want no_ip", out)
	}
	// Spelled as the extraction group, it is one.
	got, out := matchOne(t, `from (?P<ip>[0-9.]+) port`, "from 1.2.3.4 port 22")
	if out != OutcomeMatch || got != "1.2.3.4" {
		t.Errorf("got (%q,%v), want (1.2.3.4, match)", got, out)
	}
}

// expandMacros counts the ip groups compilePattern rejects duplicates by, so
// its count has to agree with what the compiled regexp actually has. The
// scanner is the authority precisely because regexp.Compile may one day refuse
// the duplicate outright, so nothing else checks this.
func TestIPGroupCountMatchesCompiled(t *testing.T) {
	t.Parallel()
	patterns := append([]string{
		`(?P<ip>a)`,
		`(?<ip>a)`,
		`(?P<ip>a)|(?P<ip>b)`,
		`<IP>`,
		`<IP> -> <IP>`,
		`<IP> (?P<ip>x)`,
		`(?P<IP>a)`,
		`(?P<user>a) (?P<ip>b)`,
		`[(?P<ip>]`,
		`\(?P<ip>x)`,
		`plain`,
	}, differentialPatterns...)

	for _, src := range patterns {
		exp, err := expandMacros(src)
		if err != nil {
			continue
		}
		re, err := regexp.Compile(exp.pattern)
		if err != nil {
			continue
		}
		want := 0
		for _, name := range re.SubexpNames() {
			if name == ipGroup {
				want++
			}
		}
		if exp.ipGroups != want {
			t.Errorf("expandMacros(%q).ipGroups = %d, compiled regexp has %d", src, exp.ipGroups, want)
		}
	}
}

// The escape hatch has to actually work, otherwise "<IP> inside a class is an
// error" leaves users with no way to match the literal text.
func TestLiteralAngleIPMatches(t *testing.T) {
	t.Parallel()
	got, out := matchOne(t, `\x3cIP> from <IP>`, "<IP> from 1.2.3.4")
	if out != OutcomeMatch || got != "1.2.3.4" {
		t.Fatalf("got (%q, %v), want (1.2.3.4, match)", got, out)
	}
}

func TestParseIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string // "" means rejected
	}{
		{"1.2.3.4", "1.2.3.4"},
		{" 1.2.3.4 ", "1.2.3.4"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"::FFFF:102:304", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"1.2.3.4:5678", "1.2.3.4"},           // remote_addr style
		{"[2001:db8::1]:443", "2001:db8::1"},  // remote_addr style
		{"[2001:db8::1]", "2001:db8::1"},      // bracketed, no port
		{"fe80::1%eth0", ""},                  // zone: not a stable identity
		{"[fe80::1%eth0]:22", ""},             //
		{"0.0.0.0", ""},                       // never a real offender
		{"::", ""},                            //
		{"", ""},                              //
		{"   ", ""},                           //
		{"example.com", ""},                   //
		{"1.2.3.4.5", ""},                     //
		{"999.1.1.1", ""},                     //
		{"0x01020304", ""},                    // no clever integer forms
		{"1.2.3.4/24", ""},                    // a prefix is not a host
		{"::1", "::1"},                        //
		{"2001:db8::1 and trailing text", ""}, //
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			addr, ok := parseIP(tc.in)
			if tc.want == "" {
				if ok {
					t.Fatalf("parseIP(%q) = %v, want rejected", tc.in, addr)
				}
				return
			}
			if !ok {
				t.Fatalf("parseIP(%q) rejected, want %s", tc.in, tc.want)
			}
			if addr.String() != tc.want {
				t.Errorf("parseIP(%q) = %v, want %s", tc.in, addr, tc.want)
			}
		})
	}
}

// v4-in-v6 and plain v4 must land on the same map key, or an attacker gets two
// counters and twice the threshold.
func TestUnmapGivesOneKey(t *testing.T) {
	t.Parallel()
	a, ok1 := parseIP("::ffff:198.51.100.7")
	b, ok2 := parseIP("198.51.100.7")
	if !ok1 || !ok2 {
		t.Fatalf("parse failed: %v %v", ok1, ok2)
	}
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func TestBoundaryOKStringAndBytes(t *testing.T) {
	t.Parallel()
	const line = "x 1.2.3.4 y"
	if !boundaryOK(line, 2, 9, false) {
		t.Errorf("string form rejected a well delimited address")
	}
	if !boundaryOK([]byte(line), 2, 9, false) {
		t.Errorf("byte form rejected a well delimited address")
	}
	if boundaryOK("91.2.3.4", 1, 8, false) {
		t.Errorf("accepted an address preceded by a digit")
	}
	if boundaryOK("1.2.3.4.5", 0, 7, false) {
		t.Errorf("accepted an address followed by .digit")
	}
	if boundaryOK("2001:db8::1:2", 0, 11, true) {
		t.Errorf("accepted a v6 address followed by :hex")
	}
	if !boundaryOK("2001:db8::1: msg", 0, 11, true) {
		t.Errorf("rejected a v6 address followed by a bare colon")
	}
}

// A capture group that did not participate in the match must be reported as
// "no address", not dereferenced.
func TestOptionalIPGroup(t *testing.T) {
	t.Parallel()
	set, err := Compile(Spec{Line: []string{`blocked(?: from (?P<ip>[0-9.]+))?`}})
	if err != nil {
		t.Fatal(err)
	}
	if res, out := set.Match([]byte("blocked")); out != OutcomeNoIP {
		t.Errorf("got (%v,%v), want no_ip", res.IP, out)
	}
	res, out := set.Match([]byte("blocked from 1.2.3.4"))
	if out != OutcomeMatch || res.IP.String() != "1.2.3.4" {
		t.Errorf("got (%v,%v), want match 1.2.3.4", res.IP, out)
	}
}

// The boundary check applies to macro groups inside JSON field patterns too,
// where the subject is a decoded string rather than the raw line.
func TestFieldValueBoundaryCheck(t *testing.T) {
	t.Parallel()
	set, err := Compile(Spec{Format: "json", Fields: map[string]string{"msg": "from <IP>"}})
	if err != nil {
		t.Fatal(err)
	}
	if res, out := set.Match([]byte(`{"msg":"from 1.2.3.4.5"}`)); out != OutcomeNoIP {
		t.Errorf("got (%v,%v), want no_ip", res.IP, out)
	}
	if res, out := set.Match([]byte(`{"msg":"from 1.2.3.4"}`)); out != OutcomeMatch || res.IP.String() != "1.2.3.4" {
		t.Errorf("got (%v,%v), want match 1.2.3.4", res.IP, out)
	}
}

// Malformed pattern text must reach regexp.Compile intact rather than being
// mangled (or looped on) by the macro expander.
func TestExpandMacrosDegenerateInput(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`trailing backslash \`,
		`unterminated class [abc`,
		`unterminated posix [[:alpha`,
		`<`,
		`<IP`,
		`<HOS`,
		`[^`,
		`[]`,
		// An unterminated or malformed group name: the expander must not
		// swallow it, so that the compiler's error is about the name.
		`(?P<`,
		`(?P<ip`,
		`(?P<IP`,
		`(?<`,
		`(?<=x)`,
		`(?P`,
		`(`,
	} {
		got, err := expandMacros(in)
		if err != nil {
			t.Errorf("expandMacros(%q) = error %v, want it to pass the text through", in, err)
			continue
		}
		if !strings.Contains(got.pattern, strings.TrimSuffix(in, `\`)) && got.pattern != in {
			t.Errorf("expandMacros(%q) = %q, want the text preserved", in, got.pattern)
		}
	}
}
