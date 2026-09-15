package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDescribeNode pins the words used in every shape-mismatch message.
func TestDescribeNode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "string", yaml: "v: hello", want: "a string"},
		{name: "quoted", yaml: `v: "hello"`, want: "a string"},
		{name: "int", yaml: "v: 42", want: "a number"},
		{name: "float", yaml: "v: 4.2", want: "a number"},
		{name: "bool", yaml: "v: true", want: "a true/false"},
		{name: "null", yaml: "v:", want: "an empty value"},
		{name: "list", yaml: "v: [a]", want: "a list"},
		{name: "map", yaml: "v: {a: b}", want: "a map"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				V yaml.Node `yaml:"v"`
			}
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			if got := describeNode(&doc.V); got != tc.want {
				t.Errorf("describeNode = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShapeErrorsAreSpecific covers the wrong-type paths of the hand-written
// walkers, which is where a wrong message would be most confusing.
func TestShapeErrorsAreSpecific(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{
			name: "action name is a list",
			src:  "    action:\n      name: [iptables]\n",
			err:  "action name must be a string, got a list",
		},
		{
			name: "action ban is a map",
			src:  "    action:\n      ban: {a: b}\n",
			err:  "action ban must be a string, got a map",
		},
		{
			name: "action timeout is nonsense",
			src:  "    action:\n      name: nft\n      timeout: soon\n",
			err:  `invalid duration "soon"`,
		},
		{
			name: "action timeout is a list",
			src:  "    action:\n      timeout: [1s]\n",
			err:  "expected a duration",
		},
		{
			name: "action shell is a list",
			src:  "    action:\n      shell: [true]\n",
			err:  "action shell: expected true or false, got a list",
		},
		{
			name: "action key is not a scalar",
			src:  "    action:\n      ? [a, b]\n      : c\n",
			err:  "action keys must be names, got a list",
		},
		{
			name: "pattern map key is not a scalar",
			src:  "    match:\n      ? [a, b]\n      : c\n",
			err:  "pattern map keys must be field names, got a list",
		},
		{
			name: "match is a bare nested list",
			src:  "    match: [[a]]\n",
			err:  "each entry of a pattern list must be a regex string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "monitors:\n  m:\n    stdin: true\n" + tc.src
			_, err := parse([]byte(src), "t.yaml")
			if err == nil {
				t.Fatalf("got no error, want one containing %q", tc.err)
			}
			wantContains(t, err.Error(), tc.err)
		})
	}
}

func TestValidUnixListen(t *testing.T) {
	t.Parallel()

	c := mustParse(t, "monitors:\n  m:\n    listen: unix:///run/banhammer.sock\n    match: \"<IP>\"\n")
	if got := c.Monitors["m"].Listen; got != "unix:///run/banhammer.sock" {
		t.Errorf("Listen = %q", got)
	}
	if !strings.Contains(c.String(), "listen unix:///run/banhammer.sock") {
		t.Errorf("String() does not show the socket:\n%s", c.String())
	}
}

func TestRenderHelpers(t *testing.T) {
	t.Parallel()

	if got := sourceOf(&Monitor{}); got != "(none)" {
		t.Errorf("sourceOf(zero) = %q, want (none)", got)
	}
	if got := sourceOf(&Monitor{Stdin: true}); got != "stdin" {
		t.Errorf("sourceOf(stdin) = %q", got)
	}
	if got := patternLines(Patterns{}); len(got) != 1 || got[0] != "(none)" {
		t.Errorf("patternLines(empty) = %v, want [(none)]", got)
	}
}
