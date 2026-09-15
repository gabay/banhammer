package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPatternsShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		yaml   string
		want   Patterns
		errs   []string
		reject bool
	}{
		{
			name: "bare string",
			yaml: `match: "Failed password from <IP>"`,
			want: Patterns{Line: []string{"Failed password from <IP>"}},
		},
		{
			name: "single quoted string keeps backslashes",
			yaml: `match: '^<IP> .* \d+$'`,
			want: Patterns{Line: []string{`^<IP> .* \d+$`}},
		},
		{
			name: "list of strings",
			yaml: "match:\n  - \"a <IP>\"\n  - \"b <IP>\"",
			want: Patterns{Line: []string{"a <IP>", "b <IP>"}},
		},
		{
			name: "empty list",
			yaml: "match: []",
			want: Patterns{Line: []string{}},
		},
		{
			name: "field map",
			yaml: "match:\n  status: \"^40[13]$\"\n  request.uri: \"\\\\.env$\"",
			want: Patterns{Fields: map[string]string{"status": "^40[13]$", "request.uri": `\.env$`}},
		},
		{
			name: "null is empty",
			yaml: "match:",
			want: Patterns{},
		},
		{
			name: "non-string scalars are taken literally",
			yaml: "match: 404",
			want: Patterns{Line: []string{"404"}},
		},
		{
			name:   "list of maps",
			yaml:   "match:\n  - status: \"^404$\"",
			reject: true,
			errs:   []string{"line 2: each entry of a pattern list must be a regex string, got a map"},
		},
		{
			name:   "nested list",
			yaml:   "match:\n  - [a, b]",
			reject: true,
			errs:   []string{"each entry of a pattern list must be a regex string, got a list"},
		},
		{
			name:   "every bad entry is reported",
			yaml:   "match:\n  - {a: 1}\n  - ok\n  - [b]",
			reject: true,
			errs: []string{
				"line 2: each entry of a pattern list must be a regex string, got a map",
				"line 4: each entry of a pattern list must be a regex string, got a list",
			},
		},
		{
			name:   "field value is a list",
			yaml:   "match:\n  status: [a, b]",
			reject: true,
			errs:   []string{`pattern for field "status" must be a regex string, got a list`},
		},
		{
			name:   "duplicate field",
			yaml:   "match:\n  status: a\n  status: b",
			reject: true,
			errs:   []string{`field "status" appears twice in the same pattern map`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				Match Patterns `yaml:"match"`
			}
			err := yaml.Unmarshal([]byte(tc.yaml), &doc)
			if tc.reject {
				if err == nil {
					t.Fatalf("shape was accepted as %+v", doc.Match)
				}
				for _, want := range tc.errs {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error does not contain %q:\n%v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !patternsEqual(doc.Match, tc.want) {
				t.Errorf("Patterns = %+v, want %+v", doc.Match, tc.want)
			}
		})
	}
}

func TestPatternsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    Patterns
		want bool
	}{
		{name: "zero", p: Patterns{}, want: true},
		{name: "empty slices", p: Patterns{Line: []string{}, Fields: map[string]string{}}, want: true},
		{name: "line", p: Patterns{Line: []string{"x"}}},
		{name: "fields", p: Patterns{Fields: map[string]string{"a": "b"}}},
	}
	for _, tc := range tests {
		if got := tc.p.Empty(); got != tc.want {
			t.Errorf("%s: Empty() = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestPatternsInContext checks the shapes once more through the real loader,
// where `ignore:` and JSON-only rules also apply.
func TestPatternsInContext(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  text-list:
    file: /a
    match:
      - "a <IP>"
      - "b <IP>"
    ignore: "c <IP>"
  json-fields:
    file: /b
    format: json
    match:
      status: "^401$"
    ignore:
      ua: "^GoodBot$"
    ip_field: remote_ip
`
	c := mustParse(t, src)

	m := c.Monitors["text-list"]
	if len(m.Match.Line) != 2 || len(m.Ignore.Line) != 1 {
		t.Errorf("text-list patterns = %+v / %+v", m.Match, m.Ignore)
	}
	j := c.Monitors["json-fields"]
	if j.Match.Fields["status"] != "^401$" || j.Ignore.Fields["ua"] != "^GoodBot$" {
		t.Errorf("json-fields patterns = %+v / %+v", j.Match, j.Ignore)
	}
}

func patternsEqual(a, b Patterns) bool {
	if len(a.Line) != len(b.Line) || len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Line {
		if a.Line[i] != b.Line[i] {
			return false
		}
	}
	for k, v := range a.Fields {
		if b.Fields[k] != v {
			return false
		}
	}
	return true
}
