package action

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

// fakeRunner records every command it is asked to run and answers from a
// handler. No test in this package may use anything else: a test that forks a
// real iptables would mutate the developer's firewall.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []fakeCall
	handler func(argv []string, shell bool) ([]byte, error)
}

type fakeCall struct {
	argv  []string
	shell bool
}

func (f *fakeRunner) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{argv: slices.Clone(argv), shell: shell})
	h := f.handler
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h == nil {
		return nil, nil
	}
	return h(argv, shell)
}

// argvs returns the recorded argv slices.
func (f *fakeRunner) argvs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.argv
	}
	return out
}

// last returns the most recent argv, failing the test if there is none.
func (f *fakeRunner) last(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no commands were run")
	}
	return f.calls[len(f.calls)-1].argv
}

func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// exitErr builds the error a Runner reports for a command that ran and failed.
func exitErr(code int, stderr string) error {
	return &CmdError{ExitCode: code, Stderr: stderr}
}

// hasArg reports whether argv contains the exact element s.
func hasArg(argv []string, s string) bool { return slices.Contains(argv, s) }

// requireArgv compares argv slices element by element; this is the assertion
// that matters most in this package.
func requireArgv(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("argv mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func requireArgvSeq(t *testing.T, got, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d\ngot:\n%s\nwant:\n%s",
			len(got), len(want), renderSeq(got), renderSeq(want))
	}
	for i := range got {
		if !slices.Equal(got[i], want[i]) {
			t.Fatalf("command %d mismatch\n got: %#v\nwant: %#v", i, got[i], want[i])
		}
	}
}

func renderSeq(seq [][]string) string {
	var sb strings.Builder
	for _, a := range seq {
		sb.WriteString("  " + Quote(a) + "\n")
	}
	return sb.String()
}

// discardLogger keeps test output readable without silencing slog globally.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// bufLogger returns a logger writing into buf, for tests that assert on what
// dry-run printed.
func bufLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return a
}

func testBan(t *testing.T, ip string) model.Ban {
	t.Helper()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return model.Ban{
		IP:      mustAddr(t, ip),
		Monitor: "sshd",
		At:      at,
		Until:   at.Add(time.Hour),
		Count:   5,
		Offense: 1,
	}
}

// newStartedIPTables builds an iptables backend whose Start has already
// succeeded on a clean host, and clears the recorded bootstrap commands.
func newStartedIPTables(t *testing.T, f *fakeRunner) *iptables {
	t.Helper()
	b, err := New(Spec{Name: "iptables"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.reset()
	return b.(*iptables)
}
