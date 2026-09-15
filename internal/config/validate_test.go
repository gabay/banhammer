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

	assertError(t,
		"monitors:\n  \"ssh d!\":\n    file: /a\n    match: \"<IP>\"\n",
		`monitor "ssh d!": invalid name: use letters, digits, '.', '-' and '_' only`)

	// Names that are used verbatim in {monitor} substitutions must stay boring.
	for _, ok := range []string{"sshd", "nginx-auth", "app.v2", "a_b", "m1"} {
		mustParse(t, "monitors:\n  "+ok+":\n    stdin: true\n    match: \"<IP>\"\n")
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

	// A valid metrics endpoint survives.
	c := mustParse(t, "metrics:\n  listen: 127.0.0.1:9777\n"+monitor)
	if c.Metrics.Listen != "127.0.0.1:9777" {
		t.Errorf("Metrics.Listen = %q", c.Metrics.Listen)
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
