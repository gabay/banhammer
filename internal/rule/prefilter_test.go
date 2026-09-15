package rule

import (
	"regexp"
	"strings"
	"testing"
)

func TestRequiredLiteral(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"plain literal", "Failed password", "Failed password"},
		{"literal with a wildcard tail", "Failed password .* from", "Failed password "},
		{"anchored", "^Failed password", "Failed password"},
		{"character class", "[abc]defgh", "defgh"},
		{"alternation with a common suffix", "(Failed|Invalid) password", " password"},
		{"alternation with a common infix", "(xxabcyy|zzabc)", "abc"},
		{"alternation with nothing in common", "(abcd|efgh)", ""},
		{"alternation where one branch is free", "(abcd|.*)", ""},
		// Only the shared prefix is required: the "foo" branch never emits
		// "foobar", so using the longer one would drop matches.
		{"prefix alternation", "(foo|foobar)xyz", "foo"},
		{"optional group is not required", "(?:abcd)?efgh", "efgh"},
		{"plus repeats at least once", "(abcd)+", "abcd"},
		{"star guarantees nothing", "(abcd)*", ""},
		{"counted repeat", "(?:abcd){2,}", "abcdabcd"},
		{"case insensitive is unusable", "(?i)Failed password", ""},
		{"partially case insensitive", "(?i:ERROR) from host", " from host"},
		{"single byte is not worth scanning", "a", ""},
		{"dot star only", ".*", ""},
		{"escaped metacharacters", `\[error\] client`, `[error] client`},
		{"digits", `\d+ bytes sent`, " bytes sent"},
		{"unicode literal", "héllo wörld", "héllo wörld"},
		{"word boundary splits the run", `\bfoobar\b`, "foobar"},
		// The expanded <IP> group must not contribute a literal of its own:
		// its branches share no common text.
		{"ip macro alone", "<IP>", ""},
		{"ip macro in context", "Failed password .* from <IP> port", "Failed password "},
		{"invalid regex yields nothing", "(", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expanded, _, err := expandMacros(tc.pattern)
			if err != nil {
				t.Fatalf("expandMacros: %v", err)
			}
			re, cerr := regexp.Compile(expanded)
			got := ""
			if cerr == nil {
				got = requiredLiteral(expanded, re)
			}
			if got != tc.want {
				t.Errorf("requiredLiteral(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// The prefilter has to actually fire on the patterns people really write,
// otherwise the whole mechanism is dead weight.
func TestPrefilterIsDerivedForRealPatterns(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"Failed password for .* from <IP> port",
		"Invalid user .* from <IP>",
		"authentication failure.*rhost=<IP>",
		`^<IP> - .*"(GET|POST) /wp-login`,
		"SASL LOGIN authentication failed",
	} {
		p, err := compilePattern("", src, true)
		if err != nil {
			t.Fatalf("compilePattern(%q): %v", src, err)
		}
		if p.lit == "" {
			t.Errorf("no prefilter literal derived for %q", src)
		}
	}
}

// Any literal the prefilter derives must genuinely appear in every string the
// pattern matches. This is the invariant the whole optimization rests on.
func TestDerivedLiteralAppearsInEveryMatch(t *testing.T) {
	t.Parallel()
	for _, src := range differentialPatterns {
		expanded, _, err := expandMacros(src)
		if err != nil {
			continue
		}
		re, err := regexp.Compile(expanded)
		if err != nil {
			continue
		}
		lit := requiredLiteral(expanded, re)
		if lit == "" {
			continue
		}
		for _, line := range differentialCorpus {
			if loc := re.FindStringIndex(line); loc != nil {
				if !strings.Contains(line, lit) {
					t.Errorf("pattern %q derived literal %q, but matched %q which does not contain it", src, lit, line)
				}
			}
		}
	}
}

// differentialPatterns deliberately mixes patterns whose required literal is
// easy, hard, and impossible to derive.
var differentialPatterns = []string{
	"Failed password for .* from <IP> port",
	"Invalid user .* from <IP>",
	"(Failed|Invalid) .* from <IP>",
	"(?i)failed password from <IP>",
	"^<IP> - -",
	`<IP> .*"(GET|POST) /(wp-login|xmlrpc)`,
	"<IP>",
	"(a|ab)c <IP>",
	"x|xy",
	`(?:abc)?def <IP>`,
	`\bsshd\b.*<IP>`,
	`[[:alpha:]]+ from <IP>`,
	`rhost=<IP>`,
	`(?m)^error .*<IP>$`,
	`(?s)begin.*end`,
	`a+b+c+`,
	`\d{1,3} attempts from <IP>`,
	`user (?P<ip>[0-9.]+) blocked`,
	`.*`,
	`(?U)a+ from <IP>`,
	`password`,
	`[^ ]+ failed for <IP>`,
}

// differentialCorpus is the traffic the patterns above run against: real log
// shapes, near-misses and deliberate junk.
var differentialCorpus = []string{
	"Sep 15 12:00:00 host sshd[1]: Failed password for root from 203.0.113.42 port 55234 ssh2",
	"Sep 15 12:00:00 host sshd[1]: Failed password for invalid user admin from 2001:db8::1 port 22 ssh2",
	"Sep 15 12:00:00 host sshd[1]: Invalid user oracle from 198.51.100.4",
	"Sep 15 12:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.9 port 22 ssh2",
	"Sep 15 12:00:00 host sshd[1]: Disconnected from authenticating user root 198.51.100.9 port 40012 [preauth]",
	"Sep 15 12:00:00 host CRON[1]: pam_unix(cron:session): session opened for user root",
	"Sep 15 12:00:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.55 user=root",
	`203.0.113.7 - - [15/Sep/2025:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 403 153 "-" "curl/8.0"`,
	`2001:db8::7 - - [15/Sep/2025:12:00:00 +0000] "GET /xmlrpc.php HTTP/1.1" 403 153 "-" "-"`,
	`{"level":"error","msg":"failed password from 1.2.3.4","request":{"remote_ip":"1.2.3.4"}}`,
	"failed password from 1.2.3.4",
	"FAILED PASSWORD FROM 1.2.3.4",
	"error something 10.0.0.1",
	"begin middle end",
	"aaabbbccc",
	"5 attempts from 10.1.2.3",
	"user 10.1.2.3 blocked",
	"999.1.1.1",
	"1.2.3.4.5",
	":::",
	"::",
	"0.0.0.0",
	"fe80::1%eth0",
	"1:2:3:4:5:6:7:8:9",
	"abc",
	"ab",
	"x",
	"xy",
	"defdef",
	"",
	" ",
	"no ip here at all",
	strings.Repeat("A", 4096),
	strings.Repeat("1.2.3.4 ", 64),
	"\x00\xff\xfe binary junk 1.2.3.4",
}

// TestPrefilterDifferential is the test that stops the prefilter from
// silently dropping attacks: every verdict must be identical with and without
// it. Contains is left unset here because it is a user assertion that
// legitimately changes the verdict when it is wrong.
func TestPrefilterDifferential(t *testing.T) {
	t.Parallel()
	for _, src := range differentialPatterns {
		spec := Spec{Line: []string{src}}
		with, err1 := compile(spec, true)
		without, err2 := compile(spec, false)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("pattern %q: compile disagreed: %v vs %v", src, err1, err2)
		}
		if err1 != nil {
			continue
		}
		for _, line := range differentialCorpus {
			gotRes, gotOut := with.Match([]byte(line))
			wantRes, wantOut := without.Match([]byte(line))
			if gotOut != wantOut || gotRes != wantRes {
				t.Errorf("pattern %q line %q: prefiltered (%v,%v) != unfiltered (%v,%v)",
					src, line, gotRes, gotOut, wantRes, wantOut)
			}
		}
	}
}

// The same guarantee for JSON mode, where the prefilter runs against decoded
// field values rather than the raw line.
func TestPrefilterDifferentialJSON(t *testing.T) {
	t.Parallel()
	specs := []Spec{
		{Format: "json", Fields: map[string]string{"msg": "authentication failure"}, IPField: "request.remote_ip"},
		{Format: "json", Fields: map[string]string{"msg": "(?i)failed", "level": "^error$"}, IPField: "ip"},
		{Format: "json", Fields: map[string]string{"msg": "from <IP>"}},
		{Format: "json", Line: []string{`"status":40[13]`}, IPField: "ip"},
		{Format: "json", Fields: map[string]string{"msg": "failed"}, IgnoreFields: map[string]string{"user": "backup"}, IPField: "ip"},
	}
	lines := []string{
		`{"level":"error","msg":"authentication failure","request":{"remote_ip":"1.2.3.4"}}`,
		`{"level":"error","msg":"failed password","ip":"1.2.3.4","user":"backup"}`,
		`{"level":"info","msg":"ok","ip":"1.2.3.4"}`,
		`{"msg":"refused from 2001:db8::9"}`,
		`{"status":403,"ip":"9.9.9.9"}`,
		`{"status":200,"ip":"9.9.9.9"}`,
		`{"msg":"authentication failure"}`,
		`{"msg":`,
		`not json`,
		``,
	}
	for _, spec := range specs {
		with, err := compile(spec, true)
		if err != nil {
			t.Fatalf("compile(%+v): %v", spec, err)
		}
		without, err := compile(spec, false)
		if err != nil {
			t.Fatalf("compile(%+v): %v", spec, err)
		}
		for _, line := range lines {
			gotRes, gotOut := with.Match([]byte(line))
			wantRes, wantOut := without.Match([]byte(line))
			if gotOut != wantOut || gotRes != wantRes {
				t.Errorf("spec %+v line %q: prefiltered (%v,%v) != unfiltered (%v,%v)",
					spec, line, gotRes, gotOut, wantRes, wantOut)
			}
		}
	}
}

// FuzzPrefilter hunts for a line where the prefilter changes the verdict.
// Unlike the table above, the fuzzer gets to invent the log line.
func FuzzPrefilter(f *testing.F) {
	for _, line := range differentialCorpus {
		f.Add([]byte(line))
	}
	f.Add([]byte("Failed password for root from 1.2.3.4 port 22"))
	f.Add([]byte("\xff\xfe\x00"))

	type pair struct {
		src              string
		with, without    *Set
		prefilterLiteral string
	}
	pairs := make([]pair, 0, len(differentialPatterns))
	for _, src := range differentialPatterns {
		with, err := compile(Spec{Line: []string{src}}, true)
		if err != nil {
			continue
		}
		without, err := compile(Spec{Line: []string{src}}, false)
		if err != nil {
			continue
		}
		pairs = append(pairs, pair{src: src, with: with, without: without, prefilterLiteral: with.line[0].lit})
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, p := range pairs {
			gotRes, gotOut := p.with.Match(raw)
			wantRes, wantOut := p.without.Match(raw)
			if gotOut != wantOut || gotRes != wantRes {
				t.Fatalf("pattern %q (literal %q) on %q: prefiltered (%v,%v) != unfiltered (%v,%v)",
					p.src, p.prefilterLiteral, raw, gotRes, gotOut, wantRes, wantOut)
			}
		}
	})
}

// FuzzMatch checks the invariants that must hold for any input at all.
func FuzzMatch(f *testing.F) {
	for _, line := range differentialCorpus {
		f.Add([]byte(line))
	}
	textSet, err := Compile(Spec{
		Line:       []string{"Failed password for .* from <IP> port", "<IP>"},
		IgnoreLine: []string{"from 10\\."},
	})
	if err != nil {
		f.Fatal(err)
	}
	jsonSet, err := Compile(Spec{
		Format:       "json",
		Fields:       map[string]string{"msg": "fail"},
		IgnoreFields: map[string]string{"user": "backup"},
		IPField:      "ip",
	})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, set := range []*Set{textSet, jsonSet} {
			res, out := set.Match(raw)
			switch out {
			case OutcomeMatch:
				if !res.IP.IsValid() {
					t.Fatalf("match without an address: %q", raw)
				}
				if res.IP.Is4In6() {
					t.Fatalf("v4-in-v6 address escaped Unmap: %v", res.IP)
				}
				if res.IP.Zone() != "" {
					t.Fatalf("zone-scoped address accepted: %v", res.IP)
				}
				if res.IP.IsUnspecified() {
					t.Fatalf("unspecified address accepted: %v", res.IP)
				}
				if res.Pattern == "" {
					t.Fatalf("match without a pattern: %q", raw)
				}
			case OutcomeNoMatch, OutcomeDecodeError:
				if res.IP.IsValid() || res.Pattern != "" {
					t.Fatalf("non-match carried a result %+v for %q", res, raw)
				}
			case OutcomeIgnored, OutcomeNoIP:
				if res.IP.IsValid() {
					t.Fatalf("outcome %v carried an address %v", out, res.IP)
				}
			default:
				t.Fatalf("unknown outcome %v", out)
			}
		}
	})
}
