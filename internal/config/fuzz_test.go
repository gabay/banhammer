package config

import (
	"errors"
	"strings"
	"testing"
)

// FuzzParse asserts the loader's contract on arbitrary input: never panic,
// return either a configuration or a *LoadError, and never hand back a problem
// with nothing to say.
//
// The contract is worth fuzzing because so much of the pipeline walks yaml.Node
// trees by hand — Patterns.UnmarshalYAML, rawAction.UnmarshalYAML, mappingPairs
// and the merge-key resolution — and because humanize re-reads yaml's own
// messages with regexes. Both are places where a malformed document can reach
// an index the author did not picture.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"# just a comment\n",
		"monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
		"monitors:\n  m:\n    file: /a\n    match:\n      - \"<IP>\"\n      - \"from <HOST>\"\n",
		"monitors:\n  m:\n    file: /a\n    format: json\n    ip_field: ip\n    match:\n      status: \"^40[13]$\"\n",
		// Shapes the hand-written walkers have to reject rather than index.
		"monitors:\n  m:\n    action:\n      ? [a, b]\n      : c\n",
		"monitors:\n  m:\n    match:\n      ? [a]\n      : b\n",
		"monitors: []\n",
		"monitors: 5\n",
		// Anchors, merges and aliases, including a merge of the wrong shape.
		"defaults:\n  action: &a\n    name: cmd\n    ban: b\n    unban: u\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n      <<: *a\n",
		"defaults:\n  action: &a iptables\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n      <<: *a\n",
		"a: &x\n  <<: *x\n",
		// Documents, duplicates and syntax the humanizer has patterns for.
		"monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n---\nmonitors: {}\n",
		"state_dir: /a\nstate_dir: /b\n",
		"monitors:\n\tm:\n\t\tfile: /a\n",
		"{{{ not yaml\n",
		"queue_size: 99999999999999999999\n",
		"allowlist: [10.0.0.0/8, ::1, nonsense]\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		cfg, err := parse([]byte(src), "fuzz.yaml")
		if err == nil {
			if cfg == nil {
				t.Fatal("parse returned neither a configuration nor an error")
			}
			// String() is the `banhammer check` output, and it walks
			// everything the parse just built.
			_ = cfg.String()
			return
		}
		if cfg != nil {
			t.Fatalf("parse returned a configuration alongside an error:\n%v", err)
		}

		var le *LoadError
		if !errors.As(err, &le) {
			t.Fatalf("error is %T, want *LoadError: %v", err, err)
		}
		if len(le.Errs) == 0 {
			t.Fatal("*LoadError reports no problems")
		}
		for i, problem := range le.Errs {
			if problem == nil {
				t.Fatalf("problem %d is nil", i)
			}
			if strings.TrimSpace(problem.Error()) == "" {
				t.Errorf("problem %d has an empty message; the report would show a blank bullet", i)
			}
			// The marker that carries a tag through yaml's error channel is
			// an implementation detail and must never reach the report.
			if strings.Contains(problem.Error(), keptValuesMark) {
				t.Errorf("problem %d leaks the internal mark: %q", i, problem.Error())
			}
		}
	})
}
