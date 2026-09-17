package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"banhammer/internal/rule"
)

// monitorWith wraps a monitor body in a minimal document.
func monitorWith(body string) string {
	return "monitors:\n  m:\n" + body
}

// TestPatternsMustCompile covers the patterns a textual scan waves through but
// the regex engine does not. Every one of these used to make `banhammer check`
// print OK on a config that kills the daemon at startup.
func TestPatternsMustCompile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{
			name: "invalid repetition",
			src:  `    match: "*bad regex <IP>"` + "\n",
			err:  "missing argument to repetition operator",
		},
		{
			name: "unclosed group",
			src:  `    match: "(unclosed <IP>"` + "\n",
			err:  "missing closing )",
		},
		{
			name: "macro inside a character class",
			src:  `    match: "class [<IP>] here"` + "\n",
			err:  "character class",
		},
		{
			// rule reads this as a group named "IP", not as the macro, so it
			// compiles cleanly and captures nothing: config has to be the one
			// to notice.
			name: "macro inside a group name",
			src:  `    match: "(?P<IP>[0-9.]+)"` + "\n",
			err:  "a name in (?P<...>) is a name, not the macro",
		},
		{
			name: "two ip groups",
			src:  `    match: "from <IP> to <IP>"` + "\n",
			err:  "capture groups",
		},
		{
			name: "bad ignore pattern still compiles the monitor",
			src:  "    match: \"from <IP>\"\n    ignore: \"(oops\"\n",
			err:  "ignore:",
		},
		{
			name: "bad json field pattern",
			src:  "    format: json\n    ip_field: ip\n    match:\n      status: \"(\"\n",
			err:  "field status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := parseErr(t, monitorWith("    file: /a\n"+tc.src))
			wantContains(t, err.Error(), `monitor "m": `)
			wantContains(t, err.Error(), tc.err)
			// rule's package prefix is noise under a monitor heading.
			if strings.Contains(err.Error(), "rule: ") {
				t.Errorf("message leaks rule's package prefix:\n%v", err)
			}
		})
	}
}

// TestCompileAgreesWithRule is the anti-drift guard for the delegation: if
// rule.Compile refuses a pattern, Load must refuse it too. The converse is not
// required — config rejects things rule tolerates, such as a pattern with no
// way to produce an address.
func TestCompileAgreesWithRule(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"Failed password .* from <IP>",
		"from <HOST>",
		"(?P<ip>[0-9.]+) failed",
		"(?<ip>[0-9.]+) failed",
		"*bad regex <IP>",
		"(unclosed <IP>",
		"class [<IP>] here",
		"(?P<IP>[0-9.]+)",
		"<IP> and <IP>",
		`^<IP> .* "(GET|POST) [^"]*" 40[13] `,
		`a{2,1} <IP>`,
		`(?i)invalid user .* from <IP>`,
		`[z-a] <IP>`,
	}

	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			t.Parallel()

			_, ruleErr := rule.Compile(rule.Spec{Format: "text", Line: []string{p}})
			_, cfgErr := parse([]byte(monitorWith("    file: /a\n    match: "+quoteYAML(p)+"\n")), "t.yaml")
			if ruleErr != nil && cfgErr == nil {
				t.Errorf("rule.Compile rejects %q (%v) but Load accepted it", p, ruleErr)
			}
		})
	}
}

// TestNonPCaptureGroupAccepted covers the newer (?<name>...) spelling, valid
// since Go 1.22, which must not be reported as a missing <IP> group.
func TestNonPCaptureGroupAccepted(t *testing.T) {
	t.Parallel()

	for _, p := range []string{`from (?P<ip>[0-9.]+)`, `from (?<ip>[0-9.]+)`} {
		c := mustParse(t, monitorWith("    file: /a\n    match: "+quoteYAML(p)+"\n"))
		if got := c.Monitors["m"].Match.Line[0]; got != p {
			t.Errorf("pattern = %q, want %q", got, p)
		}
	}
}

// TestLowercaseMacroHint covers the macro typed in lower case, which is just
// ordinary regex: the message has to say why it did not work.
func TestLowercaseMacroHint(t *testing.T) {
	t.Parallel()

	err := parseErr(t, monitorWith("    file: /a\n    match: \"from <ip>\"\n"))
	wantContains(t, err.Error(), "the macro is spelled in capitals: <IP>")
}

// TestIntegersAreStrict covers the numbers yaml.v3 would truncate, re-base or
// otherwise reinterpret without a word.
func TestIntegersAreStrict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{name: "fractional", src: "threshold: 3.5", err: `expected a whole number, got a number (3.5)`},
		{name: "exponent", src: "max_tracked: 1e9", err: "expected a whole number, got a number (1e9)"},
		{name: "hex", src: "threshold: 0x10", err: `invalid number "0x10": write it in plain decimal digits`},
		{name: "octal", src: "threshold: 0o17", err: `invalid number "0o17"`},
		{name: "underscores", src: "max_tracked: 1_000", err: `invalid number "1_000"`},
		{
			// Plain decimal digits already: the advice to write plain decimal
			// digits sent people hunting for a typo that was not there.
			name: "out of range",
			src:  "max_tracked: 9223372036854775808",
			err:  `number "9223372036854775808" is out of range: whole numbers here run from -9223372036854775808 to 9223372036854775807`,
		},
		{name: "quoted", src: `threshold: "5"`, err: "expected a whole number, got a string (5)"},
		{name: "list", src: "threshold: [5]", err: "expected a whole number, got a list"},
		{name: "float factor is fine", src: "bantime_factor: 1.5"},
		{name: "int factor is fine", src: "bantime_factor: 2"},
		{name: "quoted factor", src: `bantime_factor: "2"`, err: "expected a number, got a string (2)"},
		{name: "plain int is fine", src: "threshold: 7"},
		{name: "negative is a number", src: "threshold: -1", err: "threshold must be at least 1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := monitorWith("    file: /a\n    match: \"<IP>\"\n    " + tc.src + "\n")
			if tc.err == "" {
				mustParse(t, src)
				return
			}
			wantContains(t, parseErr(t, src).Error(), tc.err)
		})
	}

	// queue_size goes through the same gate.
	wantContains(t, parseErr(t, "queue_size: 8.5\n"+monitorWith("    file: /a\n    match: \"<IP>\"\n")).Error(),
		"expected a whole number")
}

// TestPartialActionBlockRejected covers an action block with neither a name nor
// templates, which would swap an inherited cmd backend for iptables in silence,
// because a monitor's action replaces rather than merges.
func TestPartialActionBlockRejected(t *testing.T) {
	t.Parallel()

	const defaults = `
defaults:
  action:
    ban: "block {ip}"
    unban: "unblock {ip}"
monitors:
  m:
    file: /a
    match: "<IP>"
`
	tests := []struct {
		name  string
		block string
		err   bool
	}{
		{name: "timeout only", block: "    action:\n      timeout: 45s\n", err: true},
		{name: "shell only", block: "    action:\n      shell: true\n", err: true},
		{name: "empty map", block: "    action: {}\n", err: true},
		{name: "name given", block: "    action:\n      name: ipset\n      timeout: 45s\n"},
		{name: "chain given", block: "    action:\n      chain: DOCKER-USER\n      timeout: 45s\n"},
		{name: "templates given", block: "    action:\n      ban: b\n      unban: u\n      timeout: 45s\n"},
		{name: "scalar name", block: "    action: dryrun\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := defaults + tc.block
			if !tc.err {
				mustParse(t, src)
				return
			}
			wantContains(t, parseErr(t, src).Error(),
				`monitor "m": action: set a backend name, chain, or command templates; timeout/shell alone cannot override the inherited action`)
		})
	}

	// The defaults block itself may tune the built-in backend: there is nothing
	// there to silently replace.
	c := mustParse(t, "defaults:\n  action:\n    timeout: 45s\n"+monitorWith("    file: /a\n    match: \"<IP>\"\n"))
	if got := c.Defaults.Action; got.Name != "iptables" || got.Timeout != 45*time.Second {
		t.Errorf("defaults action = %+v", got)
	}
}

// TestSecondDocumentMustParse covers a stray "---": everything after it is
// dropped, so neither a valid nor a broken document there may pass unmentioned.
func TestSecondDocumentMustParse(t *testing.T) {
	t.Parallel()

	good := monitorWith("    file: /a\n    match: \"<IP>\"\n")
	tests := []struct{ name, src, err string }{
		{name: "valid second doc", src: good + "---\nmonitors: {}\n", err: "more than one YAML document"},
		{name: "broken second doc", src: good + "---\n{{{ not yaml\n", err: "second YAML document"},
		{name: "empty second doc", src: good + "---\n", err: "more than one YAML document"},
		{
			// The probe used to be skipped whenever the first document had a
			// schema error, hiding the more damaging of the two problems.
			name: "second doc after a schema error",
			src:  monitorWith("    file: /a\n    match: \"<IP>\"\n    treshold: 3\n") + "---\nmonitors: {}\n",
			err:  "more than one YAML document",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wantContains(t, parseErr(t, tc.src).Error(), tc.err)
		})
	}

	// The typo in the first document must survive alongside it.
	wantContains(t, parseErr(t, monitorWith("    file: /a\n    match: \"<IP>\"\n    treshold: 3\n")+"---\nmonitors: {}\n").Error(),
		`unknown key "treshold"`)
}

// TestStrayDocumentDoesNotSilenceGlobals covers the attribution of a problem
// that belongs to no block. A stray second document has a line number past the
// end of the first one, which used to resolve to the global scope and take
// every global check down with it.
func TestStrayDocumentDoesNotSilenceGlobals(t *testing.T) {
	t.Parallel()

	const src = `
log_format: xml
queue_size: 0
monitors:
  m:
    file: /a
    match: "no address here"
---
monitors: {}
`
	err := parseErr(t, src)
	for _, want := range []string{
		"more than one YAML document",
		`log_format must be one of text, json, got "xml"`,
		"queue_size must be at least 1, got 0",
		`monitor "m": match "no address here" contains no <IP>`,
	} {
		wantContains(t, err.Error(), want)
	}
}

// TestMergeKeys covers anchors and merges, which must work in every block, not
// just the ones yaml.v3 decodes on its own.
func TestMergeKeys(t *testing.T) {
	t.Parallel()

	const src = `
common: &common
  ban: "block {ip}"
  unban: "unblock {ip}"
  timeout: 20s
patterns: &patterns
  status: "^40[13]$"
monitors:
  a:
    file: /a
    match: "<IP>"
    action:
      <<: *common
  b:
    file: /b
    match: "<IP>"
    action:
      <<: *common
      timeout: 5s
  c:
    file: /c
    format: json
    ip_field: ip
    match:
      <<: *patterns
      ua: "^curl"
`
	// A top-level anchor holder is itself an unknown key, so the document is
	// declared inside monitors' siblings; strip those two keys for the test by
	// declaring them under a key the schema knows nothing about is not
	// possible — so assert the unknown-key errors are the only ones.
	err := parseErr(t, src)
	for _, want := range []string{`unknown key "common"`, `unknown key "patterns"`} {
		wantContains(t, err.Error(), want)
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T", err)
	}
	if len(le.Errs) != 2 {
		t.Fatalf("merge keys produced extra problems:\n%v", le)
	}
}

// TestMergeKeysResolve checks the merged values themselves, using anchors
// defined inside blocks the schema accepts.
func TestMergeKeysResolve(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  action: &base
    name: cmd
    ban: "block {ip}"
    unban: "unblock {ip}"
    timeout: 20s
monitors:
  inherits:
    file: /a
    match: "<IP>"
    action:
      <<: *base
  overrides:
    file: /b
    match: "<IP>"
    action:
      <<: *base
      timeout: 5s
`
	c := mustParse(t, src)

	in := c.Monitors["inherits"].Action
	if in.Name != "cmd" || in.Ban != "block {ip}" || in.Timeout != 20*time.Second {
		t.Errorf("merged action = %+v", in)
	}
	// An explicit key must win over the merged one.
	ov := c.Monitors["overrides"].Action
	if ov.Timeout != 5*time.Second || ov.Ban != "block {ip}" {
		t.Errorf("overridden merged action = %+v", ov)
	}
}

func TestMergeKeyMustReferToAMap(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  action: &base iptables
monitors:
  m:
    file: /a
    match: "<IP>"
    action:
      <<: *base
`
	wantContains(t, parseErr(t, src).Error(), `a "<<" merge must refer to a map, got a string`)
}

// TestIndentationMistakes covers the wrong-shape and tab-indentation mistakes
// every YAML beginner makes at least once.
func TestIndentationMistakes(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, src, err string }{
		{
			name: "monitor body on one line",
			src:  "monitors:\n  m: /var/log/auth.log\n",
			err:  "line 2: a monitor must be a block of indented keys, got a string (/var/lo",
		},
		{
			name: "monitors as a list",
			src:  "monitors:\n  - sshd\n",
			err:  "line 2: monitors must be a block of named monitors, got a list",
		},
		{
			name: "defaults as a scalar",
			src:  "defaults: 5\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
			err:  "line 1: defaults must be a block of indented keys, got a number (5)",
		},
		{
			name: "bool expected",
			src:  monitorWith("    file: /a\n    match: \"<IP>\"\n    strip_syslog: sure\n"),
			err:  "line 5: expected a true/false, got a string (sure)",
		},
		{
			name: "tab indentation",
			src:  "monitors:\n\tm:\n\t\tfile: /a\n",
			err:  "line 2: YAML does not allow tabs for indentation; use spaces",
		},
		{
			name: "tab after spaces",
			src:  "monitors:\n  m:\n  \t  file: /a\n",
			err:  "YAML does not allow tabs for indentation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseErr(t, tc.src).Error()
			wantContains(t, got, tc.err)
			for _, leak := range []string{"config.raw", "!!"} {
				if strings.Contains(got, leak) {
					t.Errorf("message leaks %q at the user:\n%s", leak, got)
				}
			}
		})
	}
}

// TestStdinIsExclusive covers two monitors claiming the one stdin.
func TestStdinIsExclusive(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  a:
    stdin: true
    match: "<IP>"
  b:
    stdin: true
    match: "<IP>"
  c:
    file: /c
    match: "<IP>"
`
	wantContains(t, parseErr(t, src).Error(), `monitors "a", "b" all read stdin, but there is only one stdin`)

	// One reader is fine.
	mustParse(t, "monitors:\n  a:\n    stdin: true\n    match: \"<IP>\"\n  b:\n    file: /b\n    match: \"<IP>\"\n")
}

func TestBlankFilePath(t *testing.T) {
	t.Parallel()

	wantContains(t, parseErr(t, monitorWith("    file: \"   \"\n    match: \"<IP>\"\n")).Error(),
		`monitor "m": file is blank: give a path or a glob`)
}

// TestValidationSurvivesUnrelatedParseErrors covers cross-block attribution: a
// typo in one monitor must not hide real problems in another.
func TestValidationSurvivesUnrelatedParseErrors(t *testing.T) {
	t.Parallel()

	const src = `
log_format: xml
monitors:
  broken:
    file: /a
    match: "<IP>"
    treshold: 3
  alsobad:
    file: /b
    match: "no address"
    threshold: 0
`
	err := parseErr(t, src)
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T", err)
	}
	for _, want := range []string{
		`unknown key "treshold" in a monitor`,             // the parse error
		`monitor "alsobad": threshold must be at least 1`, // a different monitor still validated
		`monitor "alsobad": match "no address" contains no <IP>`,
		`log_format must be one of text, json`, // globals still validated
	} {
		wantContains(t, le.Error(), want)
	}
	// ...but nothing else is said about the monitor that failed to decode.
	if strings.Contains(le.Error(), `monitor "broken"`) {
		t.Errorf("the undecodable monitor was validated anyway:\n%v", le)
	}
}

// TestUndecodableBlockIsNotValidated is the other half of that: a monitor whose
// patterns failed to decode must not also be accused of having no patterns.
func TestUndecodableBlockIsNotValidated(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  m:
    file: /a
    match:
      - key: value
`
	err := parseErr(t, src)
	wantContains(t, err.Error(), "each entry of a pattern list must be a regex string")
	if strings.Contains(err.Error(), "no match patterns") {
		t.Errorf("invented a second problem from the first:\n%v", err)
	}
}

// TestDefaultsParseErrorDoesNotSilenceMonitors keeps attribution honest in the
// other direction.
func TestDefaultsParseErrorDoesNotSilenceMonitors(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  window: soon
monitors:
  m:
    file: /a
    match: "no address here"
`
	err := parseErr(t, src)
	wantContains(t, err.Error(), `invalid duration "soon"`)
	wantContains(t, err.Error(), `monitor "m": match "no address here" contains no <IP>`)
}

// TestUnknownKeyDoesNotHideValidation covers the other half of attribution: an
// unknown key costs the block no value, so everything else wrong with that
// block must still be listed. Reporting the typo alone bought the user a
// second round-trip for problems the loader had already found.
func TestUnknownKeyDoesNotHideValidation(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  m:
    fil: /a
    match: "no ip here"
`
	err := parseErr(t, src)
	for _, want := range []string{
		`unknown key "fil" in a monitor (did you mean "file"?)`,
		`monitor "m": no source: set exactly one of file, listen or stdin`,
		`monitor "m": match "no ip here" contains no <IP>`,
	} {
		wantContains(t, err.Error(), want)
	}
}

// TestUnknownActionKeyDoesNotHideValidation is the same for the action block,
// which this package walks by hand rather than letting yaml.v3 decode.
func TestUnknownActionKeyDoesNotHideValidation(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  m:
    file: /a
    match: "no ip here"
    action:
      ban: b
      unbam: u
`
	err := parseErr(t, src)
	wantContains(t, err.Error(), `unknown key "unbam" in an action`)
	wantContains(t, err.Error(), `monitor "m": match "no ip here" contains no <IP>`)
}

// TestDuplicateKeys covers repeated keys, which yaml.v3 always rejects and
// always describes in its own vocabulary ("mapping key ... already defined").
// Leaking that is exactly what this package exists not to do.
func TestDuplicateKeys(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, src, err string }{
		{
			name: "duplicate monitor name",
			src: "monitors:\n" +
				"  sshd:\n    file: /a\n    match: \"<IP>\"\n" +
				"  sshd:\n    file: /b\n    match: \"<IP>\"\n",
			err: `line 5: key "sshd" is already set at line 2`,
		},
		{
			name: "duplicate top-level key",
			src:  "state_dir: /a\nstate_dir: /b\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
			err:  `line 2: key "state_dir" is already set at line 1`,
		},
		{
			name: "duplicate key in a monitor",
			src:  "monitors:\n  m:\n    file: /a\n    file: /b\n    match: \"<IP>\"\n",
			err:  `line 4: key "file" is already set at line 3`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseErr(t, tc.src).Error()
			wantContains(t, got, tc.err)
			wantContains(t, got, "the whole block is dropped")
			if strings.Contains(got, "mapping key") {
				t.Errorf("message leaks yaml's own wording:\n%s", got)
			}
		})
	}
}

// TestMonitorNamedDefaults covers the reason a problem's scope is an enum and
// not a magic string: "defaults" is a legal monitor name, and its problems
// must not be printed as, or silenced along with, the defaults block's.
func TestMonitorNamedDefaults(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  threshold: 0
monitors:
  defaults:
    file: /a
    match: "no address here"
`
	err := parseErr(t, src)
	wantContains(t, err.Error(), "defaults: threshold must be at least 1, got 0")
	wantContains(t, err.Error(), `monitor "defaults": match "no address here" contains no <IP>`)

	// And with nothing wrong, it is simply a monitor.
	c := mustParse(t, "monitors:\n  defaults:\n    stdin: true\n    match: \"<IP>\"\n")
	if _, ok := c.Monitors["defaults"]; !ok {
		t.Errorf("a monitor named defaults went missing: %v", c.MonitorNames())
	}
}

// TestAliasesInHandWalkedBlocks covers a plain alias (as opposed to a "<<"
// merge) landing on a node this package walks itself, where yaml.v3 does not
// resolve it for us.
func TestAliasesInHandWalkedBlocks(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  threshold: &n 3
  action:
    name: cmd
    ban: &tmpl "block {ip}"
    unban: "unblock {ip}"
monitors:
  scalars:
    file: /a
    match: &pat "from <IP>"
    threshold: *n
    action:
      name: cmd
      ban: *tmpl
      unban: *tmpl
  reused:
    file: /b
    match: *pat
  fields:
    file: /c
    format: json
    ip_field: ip
    match: &fields
      status: "^40[13]$"
  refields:
    file: /d
    format: json
    ip_field: ip
    match: *fields
`
	c := mustParse(t, src)

	scalars := c.Monitors["scalars"]
	if scalars.Threshold != 3 {
		t.Errorf("aliased threshold = %d, want 3", scalars.Threshold)
	}
	if scalars.Action.Ban != "block {ip}" || scalars.Action.Unban != "block {ip}" {
		t.Errorf("aliased action templates = %+v", scalars.Action)
	}
	if got := c.Monitors["reused"].Match.Line; len(got) != 1 || got[0] != "from <IP>" {
		t.Errorf("aliased match = %v", got)
	}
	if got := c.Monitors["refields"].Match.Fields["status"]; got != "^40[13]$" {
		t.Errorf("aliased field map = %v", c.Monitors["refields"].Match.Fields)
	}
}

// quoteYAML renders a pattern as a single-quoted YAML scalar so backslashes
// survive verbatim.
func quoteYAML(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
