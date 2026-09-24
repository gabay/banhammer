package action

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		argv []string
		want string
	}{
		{name: "plain", argv: []string{"iptables", "-I", "BANHAMMER"}, want: "iptables -I BANHAMMER"},
		{name: "empty element", argv: []string{"/b", ""}, want: "/b ''"},
		{name: "spaces", argv: []string{"/b", "a b"}, want: "/b 'a b'"},
		{name: "single quote", argv: []string{"/b", "it's"}, want: `/b 'it'\''s'`},
		{name: "shell metacharacters", argv: []string{"/b", "; rm -rf /"}, want: `/b '; rm -rf /'`},
		{name: "nft braces", argv: []string{"nft", "{ 1.2.3.4 }"}, want: "nft '{ 1.2.3.4 }'"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Quote(tc.argv); got != tc.want {
				t.Fatalf("Quote(%#v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestQuoteRoundTrip checks that what dry-run prints is what would have run:
// feeding the quoted form back through the tokenizer must reproduce the argv.
func TestQuoteRoundTrip(t *testing.T) {
	t.Parallel()

	argvs := [][]string{
		{"iptables", "--wait", "-t", "filter", "-I", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
		{"nft", "add", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
		{"/usr/local/bin/notify", "203.0.113.7", "sshd", "; rm -rf / `id` $(id) 'x' \"y\""},
	}
	for _, argv := range argvs {
		got, err := tokenize(Quote(argv))
		if err != nil {
			t.Fatalf("tokenize(Quote(%#v)): %v", argv, err)
		}
		requireArgv(t, got, argv)
	}
}

func TestCmdErrorReporting(t *testing.T) {
	t.Parallel()
	err := &CmdError{
		Argv:     []string{"iptables", "-D", "BANHAMMER"},
		ExitCode: 1,
		Stderr:   "iptables: Bad rule (does a matching rule exist in that chain?).\nsecond line",
	}
	msg := err.Error()
	for _, want := range []string{"exit 1", "iptables -D BANHAMMER", "Bad rule"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
	if strings.Contains(msg, "second line") {
		t.Fatalf("error should only quote the first stderr line, got %q", msg)
	}
	if ExitCode(err) != 1 {
		t.Fatalf("ExitCode = %d, want 1", ExitCode(err))
	}
	if ExitCode(context.Canceled) != -1 {
		t.Fatal("ExitCode of a non-command error must be -1")
	}
	if !stderrContains(err, "NO CHAIN", "bad RULE") {
		t.Fatal("stderrContains must be case-insensitive")
	}
	if stderrContains(err, "permission denied") {
		t.Fatal("stderrContains matched text that is not there")
	}
}

func TestCapWriterBoundsOutput(t *testing.T) {
	t.Parallel()
	var w capWriter
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 10; i++ {
		n, err := w.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("Write = (%d, %v); a capped writer must never fail the child", n, err)
		}
	}
	if got := len(w.Bytes()); got != maxCapturedOutput {
		t.Fatalf("captured %d bytes, want %d", got, maxCapturedOutput)
	}
}

// TestExecRunner exercises the real fork/exec path against /bin/sh only. It
// must never be pointed at a firewall binary.
func TestExecRunner(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh unavailable")
	}
	r := NewExecRunner()
	ctx := context.Background()

	t.Run("empty argv", func(t *testing.T) {
		t.Parallel()
		if _, err := NewExecRunner().Run(ctx, nil, false); err == nil {
			t.Fatal("empty argv must be rejected")
		}
	})

	t.Run("stdout captured", func(t *testing.T) {
		t.Parallel()
		out, err := r.Run(ctx, []string{"/bin/sh", "-c", "printf hello"}, false)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if string(out) != "hello" {
			t.Fatalf("stdout = %q, want hello", out)
		}
	})

	t.Run("exit code and stderr", func(t *testing.T) {
		t.Parallel()
		_, err := r.Run(ctx, []string{"/bin/sh", "-c", "echo boom >&2; exit 7"}, false)
		if ExitCode(err) != 7 {
			t.Fatalf("ExitCode = %d, want 7 (err=%v)", ExitCode(err), err)
		}
		if !stderrContains(err, "boom") {
			t.Fatalf("stderr not captured: %v", err)
		}
	})

	t.Run("no word splitting without a shell", func(t *testing.T) {
		t.Parallel()
		// If the argument were re-split, sh would see two arguments and print
		// only the first.
		out, err := r.Run(ctx, []string{"/bin/sh", "-c", "printf %s \"$1\"", "sh", "a b c"}, false)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if string(out) != "a b c" {
			t.Fatalf("argument was mangled: %q", out)
		}
	})

	t.Run("shell mode joins argv", func(t *testing.T) {
		t.Parallel()
		out, err := r.Run(ctx, []string{"printf", "hi"}, true)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if string(out) != "hi" {
			t.Fatalf("stdout = %q, want hi", out)
		}
	})

	t.Run("context cancellation kills all children", func(t *testing.T) {
		t.Parallel()
		cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := r.Run(cctx, []string{"/bin/sh", "-c", "sleep 1"}, false)
		if err == nil {
			t.Fatal("expected an error when the deadline passes")
		}
		if elapsed := time.Since(start); elapsed >= 1*time.Second {
			t.Fatalf("Run took %v, want prompt cancellation", elapsed)
		}
	})
}
