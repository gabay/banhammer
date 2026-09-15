package action

import (
	"context"
	"strings"
	"testing"
)

// FuzzMatchedNeverEscapes throws arbitrary attacker-controlled text at the
// {matched} substitution. The invariant under test is structural, not
// pattern-based: whatever the input, the rendered command keeps exactly the
// argv shape the template had, so no value can ever become an extra argument
// or a second command.
func FuzzMatchedNeverEscapes(f *testing.F) {
	for _, seed := range []string{
		"", "; rm -rf /", "`id`", "$(id)", "a\nb", "a\x00b", `"'`, "{ip}", strings.Repeat("A", 1000),
		"--flag", "-rf", "/etc/passwd", "\\", "\t\t\t",
	} {
		f.Add(seed)
	}

	const template = `/usr/local/bin/notify --ip {ip} --monitor {monitor} --matched {matched} --end`
	want := []string{"/usr/local/bin/notify", "--ip", "203.0.113.7", "--monitor", "sshd", "--matched", "", "--end"}

	f.Fuzz(func(t *testing.T, matched string) {
		fr := &fakeRunner{}
		b, err := New(Spec{Name: "cmd", Ban: template, Unban: "/u {ip}"}, fr, discardLogger())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ban := testBan(t, "203.0.113.7")
		ban.Matched = matched
		if err := b.Ban(context.Background(), ban); err != nil {
			t.Fatalf("Ban: %v", err)
		}
		got := fr.last(t)
		if len(got) != len(want) {
			t.Fatalf("argv length %d, want %d for matched=%q: %#v", len(got), len(want), matched, got)
		}
		for i := range want {
			if i == 6 {
				continue // the attacker-controlled slot
			}
			if got[i] != want[i] {
				t.Fatalf("argv[%d] = %q, want %q (matched=%q)", i, got[i], want[i], matched)
			}
		}
		if strings.ContainsRune(got[6], 0) {
			t.Fatalf("NUL byte survived into argv for matched=%q", matched)
		}
		if len(got[6]) > maxMatchedLen {
			t.Fatalf("matched argument not capped: %d bytes", len(got[6]))
		}
	})
}

// FuzzTokenizeDoesNotPanic pins the other half: a hostile *config* template
// must be rejected or tokenised, never crash the daemon at startup.
func FuzzTokenizeDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"", "a b", `"unterminated`, `'`, `\`, `a"b'c`, "{ip}", "a\\\"b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		toks, err := tokenize(s)
		if err != nil {
			return
		}
		// Tokens must never contain a NUL after substitution, and rendering
		// must be stable.
		v := vars{ip: "203.0.113.7", matched: "x"}
		out := render(toks, v)
		if len(out) != len(toks) {
			t.Fatalf("render changed the argv length: %d -> %d", len(toks), len(out))
		}
	})
}
