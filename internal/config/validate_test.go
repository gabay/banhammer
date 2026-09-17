package config

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{
			name: "no source",
			src:  "    match: \"<IP>\"\n",
			err:  `monitor "m": no source: set exactly one of file, listen or stdin`,
		},
		{
			name: "file and listen",
			src:  "    file: /a\n    listen: tcp://127.0.0.1:99\n    match: \"<IP>\"\n",
			err:  `monitor "m": sources file, listen are mutually exclusive`,
		},
		{
			name: "all three",
			src:  "    file: /a\n    listen: tcp://127.0.0.1:99\n    stdin: true\n    match: \"<IP>\"\n",
			err:  `monitor "m": sources file, listen, stdin are mutually exclusive`,
		},
		{
			name: "stdin false is not a source",
			src:  "    stdin: false\n    match: \"<IP>\"\n",
			err:  `monitor "m": no source`,
		},
		{
			name: "listen without scheme",
			src:  "    listen: 0.0.0.0:5140\n    match: \"<IP>\"\n",
			err:  `listen: "0.0.0.0:5140" needs a scheme, e.g. udp://0.0.0.0:5140`,
		},
		{
			name: "listen with a bad scheme",
			src:  "    listen: sctp://0.0.0.0:5140\n    match: \"<IP>\"\n",
			err:  `listen: scheme "sctp" must be one of udp, tcp, unix`,
		},
		{
			name: "listen without a port",
			src:  "    listen: udp://0.0.0.0\n    match: \"<IP>\"\n",
			err:  `listen: "0.0.0.0" must be host:port`,
		},
		{
			name: "listen with a silly port",
			src:  "    listen: tcp://0.0.0.0:99999\n    match: \"<IP>\"\n",
			err:  `has an invalid port "99999"`,
		},
		{
			name: "unix socket needs a path",
			src:  "    listen: unix://\n    match: \"<IP>\"\n",
			err:  "unix:// needs a socket path",
		},
		{
			name: "named port is not accepted",
			src:  "    listen: tcp://localhost:syslog\n    match: \"<IP>\"\n",
			err:  `has an invalid port "syslog"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertError(t, "monitors:\n  m:\n"+tc.src, tc.err)
		})
	}
}

func TestValidateMonitorRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{
			name: "no match at all",
			src:  "    file: /a\n",
			err:  `monitor "m": no match patterns: the monitor could never fire`,
		},
		{
			name: "empty match string",
			src:  "    file: /a\n    match: \"\"\n",
			err:  "match contains an empty pattern, which would match every line",
		},
		{
			name: "blank pattern in a list",
			src:  "    file: /a\n    match:\n      - \"<IP>\"\n      - \"   \"\n",
			err:  "match contains an empty pattern, which would match every line",
		},
		{
			name: "blank field pattern",
			src:  "    file: /a\n    format: json\n    ip_field: ip\n    match:\n      status: \"\"\n",
			err:  `match pattern for field "status" is empty`,
		},
		{
			name: "no ip source",
			src:  "    file: /a\n    match: \"Failed password\"\n",
			err:  `match "Failed password" contains no <IP>, <HOST> or (?P<ip>...) group`,
		},
		{
			name: "one of several patterns lacks an ip",
			src:  "    file: /a\n    match:\n      - \"a <IP>\"\n      - \"b\"\n",
			err:  `match "b" contains no <IP>`,
		},
		{
			name: "HOST counts as an ip group",
			src:  "    file: /a\n    match: \"from <HOST>\"\n",
		},
		{
			name: "explicit named group counts",
			src:  "    file: /a\n    match: \"from (?P<ip>[0-9.]+)\"\n",
		},
		{
			name: "ip_field needs json",
			src:  "    file: /a\n    ip_field: remote_ip\n    match: \"fail\"\n",
			err:  `monitor "m": ip_field requires format: json`,
		},
		{
			name: "field map needs json",
			src:  "    file: /a\n    match:\n      status: \"^401$\"\n",
			err:  "a field map in match requires format: json",
		},
		{
			name: "ignore field map needs json",
			src:  "    file: /a\n    match: \"<IP>\"\n    ignore:\n      ua: bot\n",
			err:  "a field map in ignore requires format: json",
		},
		{
			name: "field map cannot capture an ip",
			src:  "    file: /a\n    format: json\n    match:\n      status: \"^401$\"\n",
			err:  "a field map in match cannot capture an address: set ip_field",
		},
		{
			name: "ip_field and IP macro conflict",
			src:  "    file: /a\n    format: json\n    ip_field: remote_ip\n    match: \"from <IP>\"\n",
			err:  `ip_field and an <IP> group in match "from <IP>" are mutually exclusive`,
		},
		{
			// <HOST> captures an address too, so it clashes just the same.
			name: "ip_field and HOST macro conflict",
			src:  "    file: /a\n    format: json\n    ip_field: remote_ip\n    match: \"from <HOST>\"\n",
			err:  `ip_field and an <IP> group in match "from <HOST>" are mutually exclusive`,
		},
		{
			// So does a hand-written group, which is the spelling rule uses.
			name: "ip_field and a named group conflict",
			src:  "    file: /a\n    format: json\n    ip_field: remote_ip\n    match: \"from (?P<ip>[0-9.]+)\"\n",
			err:  `ip_field and an <IP> group in match "from (?P<ip>[0-9.]+)" are mutually exclusive`,
		},
		{
			name: "unknown format",
			src:  "    file: /a\n    format: logfmt\n    match: \"<IP>\"\n",
			err:  `format must be one of text, json, got "logfmt"`,
		},
		{
			name: "json with ip_field is fine",
			src:  "    file: /a\n    format: json\n    ip_field: remote_ip\n    match:\n      status: \"^401$\"\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "monitors:\n  m:\n" + tc.src
			if tc.err == "" {
				mustParse(t, src)
				return
			}
			assertError(t, src, tc.err)
		})
	}
}

func TestValidateMonitorName(t *testing.T) {
	t.Parallel()

	const badName = "invalid name: use letters, digits, '.', '-' and '_', starting with a letter, digit or '_'"
	tests := []struct {
		name string
		ok   bool
	}{
		{name: "sshd", ok: true},
		{name: "nginx-auth", ok: true},
		{name: "app.v2", ok: true},
		{name: "a_b", ok: true},
		{name: "m1", ok: true},
		// Names that are used verbatim in {monitor} substitutions must stay
		// boring, and the first character is where "boring" is easiest to
		// lose: a leading '.' hides the state file and a leading '-' reads as
		// a flag. A leading '_' does neither, and the message has always
		// promised underscores work.
		{name: "_internal", ok: true},
		{name: "-dashed"},
		{name: ".hidden"},
		{name: "ssh d!"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "monitors:\n  \"" + tc.name + "\":\n    stdin: true\n    match: \"<IP>\"\n"
			if tc.ok {
				mustParse(t, src)
				return
			}
			assertError(t, src, "monitor \""+tc.name+"\": "+badName)
		})
	}
}

func TestValidateSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{name: "threshold zero", src: "threshold: 0", err: "threshold must be at least 1, got 0"},
		{name: "threshold negative", src: "threshold: -2", err: "threshold must be at least 1, got -2"},
		{name: "window zero", src: "window: 0s", err: "window must be greater than zero, got 0s"},
		{name: "window negative", src: "window: -5m", err: "window must be greater than zero, got -5m"},
		{name: "bantime zero", src: "bantime: 0s", err: "bantime must be greater than zero"},
		{name: "factor below one", src: "bantime_factor: 0.5", err: "bantime_factor must be at least 1 (1 means no escalation), got 0.5"},
		{name: "bantime_max zero", src: "bantime_max: 0s", err: "bantime_max must be greater than zero"},
		{name: "bantime_max below bantime", src: "bantime: 48h\n    bantime_max: 1h", err: "bantime_max (1h) is shorter than bantime (48h)"},
		{name: "find_history zero", src: "find_history: 0s", err: "find_history must be greater than zero"},
		{name: "max_tracked zero", src: "max_tracked: 0", err: "max_tracked must be at least 1, got 0"},
		{name: "start_at", src: "start_at: soon", err: `start_at must be one of checkpoint, end, beginning, got "soon"`},
		{name: "on_repeat", src: "on_repeat: maybe", err: `on_repeat must be one of ignore, extend, got "maybe"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertError(t,
				"monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    "+tc.src+"\n",
				`monitor "m": `+tc.err)
		})
	}
}

// TestInheritedProblemIsReportedOnce keeps a single bad default from producing
// one error per monitor, which would bury everything else.
func TestInheritedProblemIsReportedOnce(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  threshold: 0
monitors:
  a:
    stdin: true
    match: "<IP>"
  b:
    file: /b
    match: "<IP>"
`
	err := parseErr(t, src)
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T, want *LoadError", err)
	}
	if len(le.Errs) != 1 {
		t.Fatalf("got %d problems, want 1:\n%v", len(le.Errs), le)
	}
	wantContains(t, le.Errs[0].Error(), "defaults: threshold must be at least 1")
}

func TestGlobalValidation(t *testing.T) {
	t.Parallel()

	const monitor = "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n"
	tests := []struct{ name, src, err string }{
		{name: "log_format", src: "log_format: xml\n" + monitor, err: `log_format must be one of text, json, got "xml"`},
		{name: "queue_size", src: "queue_size: 0\n" + monitor, err: "queue_size must be at least 1, got 0"},
		{
			// An unbounded queue_size passes `check` and then dies allocating
			// the channel, which is the one failure §6 promises cannot happen.
			name: "queue_size cap",
			src:  "queue_size: 1000000000\n" + monitor,
			err:  "queue_size must be at most 1048576, got 1000000000: the queue is allocated in full at startup",
		},
		{name: "state_dir", src: "state_dir: \"\"\n" + monitor, err: "state_dir must not be empty"},
		{name: "metrics listen", src: "metrics:\n  listen: 9777\n" + monitor, err: `metrics.listen: "9777" must be host:port`},
		{name: "metrics port", src: "metrics:\n  listen: 127.0.0.1:0\n" + monitor, err: `has an invalid port "0"`},
		{name: "no monitors", src: "state_dir: /tmp\n", err: "no monitors defined: nothing would be watched"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertError(t, tc.src, tc.err)
		})
	}

	// The cap itself is allowed; only what is past it is not.
	if c := mustParse(t, "queue_size: 1048576\n"+monitor); c.QueueSize != maxQueueSize {
		t.Errorf("QueueSize = %d, want %d", c.QueueSize, maxQueueSize)
	}

	// A valid metrics endpoint survives.
	c := mustParse(t, "metrics:\n  listen: 127.0.0.1:9777\n"+monitor)
	if c.Metrics.Listen != "127.0.0.1:9777" {
		t.Errorf("Metrics.Listen = %q", c.Metrics.Listen)
	}
}

// TestDuplicateListenAddress covers two monitors claiming one address. Without
// this the clash surfaces as a failed bind at startup, long after the config
// was declared good.
func TestDuplicateListenAddress(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  a:
    listen: udp://0.0.0.0:5140
    match: "<IP>"
  b:
    listen: udp://0.0.0.0:5140
    match: "<IP>"
  c:
    listen: tcp://0.0.0.0:5140
    match: "<IP>"
`
	err := parseErr(t, src)
	wantContains(t, err.Error(), `monitors "a", "b" all listen on "udp://0.0.0.0:5140", but only one of them can bind it`)
	// A different scheme on the same port is a different socket.
	if strings.Contains(err.Error(), "tcp://") {
		t.Errorf("tcp and udp on one port were treated as a clash:\n%v", err)
	}

	// The same address in one monitor is, of course, fine.
	mustParse(t, "monitors:\n  a:\n    listen: udp://0.0.0.0:5140\n    match: \"<IP>\"\n")
}

// TestBlankSourceValues covers the written-but-empty source key. `file: ""` and
// `file: "   "` are the same half-finished edit and must read the same way;
// `file: ""` used to be reported as a missing source instead.
func TestBlankSourceValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{`""`, `"   "`} {
		src := "monitors:\n  m:\n    file: " + value + "\n    match: \"<IP>\"\n"
		err := parseErr(t, src)
		wantContains(t, err.Error(), `monitor "m": file is blank: give a path or a glob`)
		if strings.Contains(err.Error(), "no source") {
			t.Errorf("file: %s was reported as a missing source:\n%v", value, err)
		}
	}
}

// TestContainsPrefilter covers the `contains:` override, whose only failure
// mode is being silently ignored.
func TestContainsPrefilter(t *testing.T) {
	t.Parallel()

	const head = "monitors:\n  m:\n    file: /a\n    match: \"from <IP>\"\n"

	assertError(t, head+"    contains: \"\"\n",
		`monitor "m": contains is empty: give a literal substring to require, or drop the key`)

	// A literal, including one made only of spaces, is a real prefilter.
	for _, value := range []string{`"sshd"`, `"   "`} {
		c := mustParse(t, head+"    contains: "+value+"\n")
		if got := c.Monitors["m"].Contains; got == "" {
			t.Errorf("contains: %s was dropped", value)
		}
	}
	// An absent key is not an empty one.
	if got := mustParse(t, head).Monitors["m"].Contains; got != "" {
		t.Errorf("Contains = %q, want empty when the key is absent", got)
	}
}

// TestValidationGolden pins the complete, ordered report for a thoroughly
// broken file: globals, then defaults, then monitors in name order.
func TestValidationGolden(t *testing.T) {
	t.Parallel()

	const src = `
log_format: xml
queue_size: 0
metrics:
  listen: nine-thousand
defaults:
  threshold: 0
  window: 0s
  bantime: 48h
  bantime_max: 1h
  bantime_factor: 0.5
  start_at: soon
  on_repeat: maybe
monitors:
  zeta:
    file: /z
    match: "nothing useful"
  alpha:
    match: "<IP>"
    threshold: -1
  mid:
    file: /m
    format: json
    match:
      status: "^401$"
`
	const want = `t.yaml: 13 problems
  - log_format must be one of text, json, got "xml"
  - queue_size must be at least 1, got 0
  - metrics.listen: "nine-thousand" must be host:port
  - defaults: threshold must be at least 1, got 0
  - defaults: window must be greater than zero, got 0s
  - defaults: bantime_factor must be at least 1 (1 means no escalation), got 0.5
  - defaults: bantime_max (1h) is shorter than bantime (48h)
  - defaults: start_at must be one of checkpoint, end, beginning, got "soon"
  - defaults: on_repeat must be one of ignore, extend, got "maybe"
  - monitor "alpha": no source: set exactly one of file, listen or stdin
  - monitor "alpha": threshold must be at least 1, got -1
  - monitor "mid": a field map in match cannot capture an address: set ip_field
  - monitor "zeta": match "nothing useful" contains no <IP>, <HOST> or (?P<ip>...) group, so no address could be extracted`

	got := parseErr(t, src).Error()
	if got != want {
		t.Errorf("report mismatch:\ngot:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestLoadErrorUnwrap(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	le := &LoadError{Path: "x.yaml", Errs: []error{errors.New("first"), sentinel}}

	if !errors.Is(le, sentinel) {
		t.Error("errors.Is did not find the wrapped error")
	}
	want := "x.yaml: 2 problems\n  - first\n  - boom"
	if le.Error() != want {
		t.Errorf("Error() = %q, want %q", le.Error(), want)
	}
	one := &LoadError{Errs: []error{sentinel}}
	if one.Error() != "1 problem\n  - boom" {
		t.Errorf("single-problem rendering = %q", one.Error())
	}
}

func assertError(t *testing.T, src, want string) {
	t.Helper()
	err := parseErr(t, src)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("report does not contain\n  %s\ngot:\n%s", want, err)
	}
}

func parseErr(t *testing.T, src string) error {
	t.Helper()
	c, err := parse([]byte(src), "t.yaml")
	if err == nil {
		t.Fatalf("parse succeeded, want an error; config:\n%s", c)
	}
	return err
}
