package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestUnknownKeysAreFatal is the anti-footgun test: fail2ban's silent
// acceptance of misspelled keys is the failure mode this package exists to
// prevent.
func TestUnknownKeysAreFatal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "typo in a monitor setting",
			src: "monitors:\n" +
				"  sshd:\n" +
				"    file: /a\n" +
				"    match: \"<IP>\"\n" +
				"    treshold: 3\n",
			want: `line 5: unknown key "treshold" in a monitor (did you mean "threshold"?)`,
		},
		{
			name: "typo at the top level",
			src:  "state_dirs: /tmp\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
			want: `line 1: unknown key "state_dirs" in the top level (did you mean "state_dir"?)`,
		},
		{
			name: "typo under defaults",
			src:  "defaults:\n  bantime_facter: 2\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
			want: `line 2: unknown key "bantime_facter" in defaults (did you mean "bantime_factor"?)`,
		},
		{
			name: "typo in metrics",
			src:  "metrics:\n  lisen: 127.0.0.1:9777\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
			want: `line 2: unknown key "lisen" in metrics (did you mean "listen"?)`,
		},
		{
			name: "typo in an action block",
			src: "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n" +
				"      ban: b\n      unbam: u\n",
			want: `line 7: unknown key "unbam" in an action (did you mean "unban"?)`,
		},
		{
			name: "unrecognisable key lists the valid ones",
			src:  "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    zzzzzzzzzz: 1\n",
			want: `line 5: unknown key "zzzzzzzzzz" in a monitor; valid keys are "action"`,
		},
		{
			name: "a source typo is not silently a missing source",
			src:  "monitors:\n  m:\n    fil: /a\n    match: \"<IP>\"\n",
			want: `line 3: unknown key "fil" in a monitor (did you mean "file"?)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parse([]byte(tc.src), "t.yaml")
			if err == nil {
				t.Fatalf("unknown key was accepted; want %q", tc.want)
			}
			wantContains(t, err.Error(), tc.want)
		})
	}
}

// TestParseErrorsAccumulate checks that one bad value does not hide the next.
// This is why the unmarshalers return *yaml.TypeError rather than a plain one.
func TestParseErrorsAccumulate(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  windwo: 5m
monitors:
  a:
    file: /a
    match: "<IP>"
    bantime: yesterday
    treshold: 2
  b:
    file: /b
    match:
      - key: value
    action:
      ban: x
      unbam: y
`
	_, err := parse([]byte(src), "t.yaml")
	if err == nil {
		t.Fatal("parse succeeded")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T, want *LoadError", err)
	}
	for _, want := range []string{
		`unknown key "windwo" in defaults`,
		`invalid duration "yesterday"`,
		`unknown key "treshold" in a monitor`,
		"each entry of a pattern list must be a regex string",
		`unknown key "unbam" in an action`,
	} {
		wantContains(t, le.Error(), want)
	}
	if len(le.Errs) != 5 {
		t.Errorf("got %d problems, want 5:\n%v", len(le.Errs), le)
	}
	if !strings.HasPrefix(le.Error(), "t.yaml: 5 problems") {
		t.Errorf("header is wrong:\n%s", le.Error())
	}
}

// TestKnownKeysMatchStructTags guards the suggestion lists against drift: they
// are derived from the tags, so this pins the tags themselves.
func TestKnownKeysMatchStructTags(t *testing.T) {
	t.Parallel()

	want := map[string][]string{
		"config.rawConfig": {
			"allow_local", "allowlist", "defaults", "log_format", "metrics",
			"monitors", "queue_size", "state_dir",
		},
		"config.rawSettings": {
			"action", "bantime", "bantime_factor", "bantime_max", "find_history",
			"max_tracked", "on_repeat", "start_at", "threshold", "window",
		},
		"config.rawMonitor": {
			"action", "bantime", "bantime_factor", "bantime_max", "contains",
			"file", "find_history", "format", "ignore", "ip_field", "listen",
			"match", "max_tracked", "on_repeat", "start_at", "stdin",
			"strip_syslog", "threshold", "window",
		},
		"config.rawMetrics": {"listen"},
		"config.rawAction":  {"ban", "name", "shell", "start", "stop", "timeout", "unban"},
	}

	got := keyIndex()
	if len(got) != len(want) {
		t.Fatalf("keyIndex covers %d types, want %d", len(got), len(want))
	}
	for typ, wantKeys := range want {
		if !slices.Equal(got[typ], wantKeys) {
			t.Errorf("%s keys =\n  %v\nwant\n  %v", typ, got[typ], wantKeys)
		}
	}

	// Every label must name a type that exists, or humanize() would fall back
	// to yaml's raw message.
	for typ := range typeLabels {
		if _, ok := got[typ]; !ok {
			t.Errorf("typeLabels has %q but keyIndex does not", typ)
		}
	}
}

// TestActionSwitchHandlesEveryKey ensures the hand-written key switch in
// rawAction.UnmarshalYAML stays in step with the struct's tags.
func TestActionSwitchHandlesEveryKey(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"name":    "cmd",
		"start":   "s",
		"ban":     "b",
		"unban":   "u",
		"stop":    "p",
		"shell":   "true",
		"timeout": "5s",
	}
	keys := actionKeys()
	if len(keys) == 0 {
		t.Fatal("no action keys")
	}
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			t.Fatalf("action key %q has no test value: was a key added without updating the switch?", k)
		}
		src := "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n      " + k + ": " + v + "\n"
		_, errs := decode([]byte(src))
		for _, err := range errs {
			if strings.Contains(err.Error(), "unknown key") {
				t.Errorf("action key %q rejected: %v", k, err)
			}
		}
	}

	// And the whole block together resolves as expected.
	src := "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n"
	for _, k := range keys {
		src += "      " + k + ": " + values[k] + "\n"
	}
	c := mustParse(t, src)
	a := c.Monitors["m"].Action
	if a.Name != "cmd" || a.Start != "s" || a.Ban != "b" || a.Unban != "u" || a.Stop != "p" || !a.Shell || a.Timeout.String() != "5s" {
		t.Errorf("action = %+v", a)
	}
}

func TestActionShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want ActionSpec
		err  string
	}{
		{
			name: "scalar name",
			src:  "action: ipset\n",
			want: ActionSpec{Name: "ipset", Timeout: defaultActionTimeout},
		},
		{
			name: "templates imply cmd",
			src:  "action:\n      ban: \"block {ip}\"\n      unban: \"unblock {ip}\"\n",
			want: ActionSpec{Name: "cmd", Ban: "block {ip}", Unban: "unblock {ip}", Timeout: defaultActionTimeout},
		},
		{
			name: "ban without unban",
			src:  "action:\n      ban: \"block {ip}\"\n",
			err:  "has a ban template but no unban template",
		},
		{
			name: "unban without ban",
			src:  "action:\n      unban: \"unblock {ip}\"\n",
			err:  "has an unban template but no ban template",
		},
		{
			name: "named cmd without templates",
			src:  "action: cmd\n",
			err:  `action "cmd" requires ban and unban command templates`,
		},
		{
			name: "named backend plus templates is ambiguous",
			src:  "action:\n      name: iptables\n      ban: b\n      unban: u\n",
			err:  `action "iptables" cannot be combined with command templates`,
		},
		{
			name: "unknown backend",
			src:  "action: iptable\n",
			err:  `action "iptable" is not one of iptables, ipset, nft, dryrun, cmd`,
		},
		{
			name: "zero timeout",
			src:  "action:\n      name: nft\n      timeout: 0s\n",
			err:  "action timeout must be greater than zero",
		},
		{
			name: "shell must be a bool",
			src:  "action:\n      name: nft\n      shell: yeah\n",
			err:  `action shell: expected true or false, got "yeah"`,
		},
		{
			name: "list is not an action",
			src:  "action:\n      - iptables\n",
			err:  "action must be a backend name",
		},
		{
			name: "duplicate key",
			src:  "action:\n      name: nft\n      name: ipset\n",
			err:  `key "name" appears twice`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    " + tc.src
			c, err := parse([]byte(src), "t.yaml")
			if tc.err != "" {
				if err == nil {
					t.Fatalf("got no error, want one containing %q", tc.err)
				}
				wantContains(t, err.Error(), tc.err)
				return
			}
			if err != nil {
				t.Fatalf("parse:\n%v", err)
			}
			if got := c.Monitors["m"].Action; got != tc.want {
				t.Errorf("action = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSuggest(t *testing.T) {
	t.Parallel()

	monitor := keysFor("config.rawMonitor")
	tests := []struct {
		key  string
		keys []string
		want string
	}{
		{key: "treshold", keys: monitor, want: "threshold"},
		{key: "Threshold", keys: monitor, want: "threshold"},
		{key: "max_track", keys: monitor, want: "max_tracked"},
		{key: "ip-field", keys: monitor, want: "ip_field"},
		{key: "matches", keys: monitor, want: "match"},
		{key: "completely_different", keys: monitor, want: ""},
		{key: "x", keys: monitor, want: ""},
		{key: "bant", keys: []string{"ban", "bantime"}, want: "ban"},
	}
	for _, tc := range tests {
		if got := suggest(tc.key, tc.keys); got != tc.want {
			t.Errorf("suggest(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"kitten", "sitting", 3},
		{"treshold", "threshold", 1},
		{"match", "match", 0},
		{"ünïcode", "unicode", 2},
	}
	for _, tc := range tests {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestHumanizePassesThroughUnknownShapes keeps yaml's own diagnostics intact
// when they are not the "field not found" form.
func TestHumanizePassesThroughUnknownShapes(t *testing.T) {
	t.Parallel()

	tests := []struct{ in, want string }{
		{
			in:   "line 3: field treshold not found in type config.rawMonitor",
			want: `line 3: unknown key "treshold" in a monitor (did you mean "threshold"?)`,
		},
		{
			in:   "line 3: field x not found in type some.OtherType",
			want: "line 3: field x not found in type some.OtherType",
		},
		{
			in:   "line 7: cannot unmarshal !!str `abc` into int",
			want: "line 7: expected a whole number, got a string (abc)",
		},
		{
			in:   "line 2: cannot unmarshal !!str `hello` into config.rawMonitor",
			want: "line 2: a monitor must be a block of indented keys, got a string (hello)",
		},
		{
			in:   "line 1: cannot unmarshal !!seq into map[string]*config.rawMonitor",
			want: "line 1: monitors must be a block of named monitors, got a list",
		},
		{
			// An unfamiliar target type must not be guessed at.
			in:   "line 4: cannot unmarshal !!str `x` into chan int",
			want: "line 4: cannot unmarshal !!str `x` into chan int",
		},
		{
			in:   "line 9: something yaml has not said before",
			want: "line 9: something yaml has not said before",
		},
	}
	for _, tc := range tests {
		if got := humanize(tc.in); got != tc.want {
			t.Errorf("humanize(%q) =\n  %q\nwant\n  %q", tc.in, got, tc.want)
		}
	}
}

// TestStructKeysFollowsInline documents the reflection helper's contract.
func TestStructKeysFollowsInline(t *testing.T) {
	t.Parallel()

	type inner struct {
		A string `yaml:"a"`
	}
	type outer struct {
		B      string `yaml:"b"`
		Skip   string `yaml:"-"`
		NoTag  string
		Nested inner `yaml:",inline"`
	}
	want := []string{"a", "b", "notag"}
	if got := structKeys(reflect.TypeFor[outer]()); !slices.Equal(got, want) {
		t.Errorf("structKeys = %v, want %v", got, want)
	}
}
