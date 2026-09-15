// Package action turns a ban decision into a firewall mutation.
//
// Everything that leaves this process does so through a [Runner], which is the
// single seam the tests replace with a recorder: no test ever forks a real
// iptables/nft/ipset, and nothing here can touch the host firewall during
// `go test`. Backends are deliberately dumb argv builders — all the policy
// (retries, serialisation, timeouts) lives in [Executor], because iptables is
// not safe to call concurrently.
package action

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// maxCapturedOutput bounds how much of a child's stdout/stderr we keep. A
// misbehaving helper command must not be able to balloon the daemon's RSS,
// and we only ever look at the first line or two of stderr anyway.
const maxCapturedOutput = 8 << 10

// Runner executes an external command. Production code uses [NewExecRunner];
// tests substitute a recorder that asserts on the exact argv.
//
// When shell is false, argv[0] is the binary and the remaining elements are
// passed verbatim as arguments — no word splitting, no globbing, no
// interpretation of any kind. When shell is true the elements are joined with
// single spaces and handed to "/bin/sh -c" (see [Spec].Shell for why you
// probably do not want that).
//
// Implementations must honour ctx cancellation and must return a *[CmdError]
// when the command ran but exited non-zero, so callers can tell expected
// control flow (iptables "no such rule") from a real failure.
type Runner interface {
	Run(ctx context.Context, argv []string, shell bool) ([]byte, error)
}

// NewExecRunner returns the Runner that actually forks processes.
func NewExecRunner() Runner { return execRunner{} }

type execRunner struct{}

func (execRunner) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("action: refusing to run empty argv")
	}
	var cmd *exec.Cmd
	if shell {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", strings.Join(argv, " "))
	} else {
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
	}
	var stdout, stderr capWriter
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = nil

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	ce := &CmdError{
		Argv:     argv,
		ExitCode: -1,
		Stderr:   strings.TrimSpace(stderr.String()),
		Err:      err,
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		ce.ExitCode = ee.ExitCode()
	}
	// A cancelled or timed-out command is a real failure, but the caller needs
	// to see the context error to avoid retrying a doomed operation.
	if cerr := ctx.Err(); cerr != nil {
		ce.Err = fmt.Errorf("%w (%w)", err, cerr)
	}
	return stdout.Bytes(), ce
}

// capWriter is a bytes.Buffer that silently discards anything past
// maxCapturedOutput.
type capWriter struct{ b bytes.Buffer }

func (w *capWriter) Write(p []byte) (int, error) {
	if room := maxCapturedOutput - w.b.Len(); room > 0 {
		if len(p) > room {
			w.b.Write(p[:room])
		} else {
			w.b.Write(p)
		}
	}
	return len(p), nil // claim success so the child is never blocked by us
}

func (w *capWriter) Bytes() []byte  { return w.b.Bytes() }
func (w *capWriter) String() string { return w.b.String() }

// CmdError reports an external command that ran and failed. Backends inspect
// ExitCode and Stderr to separate expected outcomes ("chain already exists",
// "no such rule") from genuine errors.
type CmdError struct {
	Argv     []string
	ExitCode int // -1 when the process never started or died from a signal
	Stderr   string
	Err      error
}

func (e *CmdError) Error() string {
	msg := fmt.Sprintf("action: command failed (exit %d): %s", e.ExitCode, Quote(e.Argv))
	if e.Stderr != "" {
		msg += ": " + firstLine(e.Stderr)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *CmdError) Unwrap() error { return e.Err }

// ExitCode returns the process exit status recorded in err, or -1 if err is
// not a command failure.
func ExitCode(err error) int {
	var ce *CmdError
	if errors.As(err, &ce) {
		return ce.ExitCode
	}
	return -1
}

// stderrOf returns the captured stderr of a failed command, or "".
func stderrOf(err error) string {
	var ce *CmdError
	if errors.As(err, &ce) {
		return ce.Stderr
	}
	return ""
}

// stderrContains reports whether the command's stderr mentions any of the
// given substrings (case-insensitive). Matching on message text is fragile,
// so callers must also require a non-zero exit and treat a miss as a real
// error rather than as success.
func stderrContains(err error, subs ...string) bool {
	s := strings.ToLower(stderrOf(err))
	if s == "" {
		return false
	}
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Quote renders argv as a copy-pasteable shell command line. It is used for
// dry-run output and error messages, so operators can paste what the daemon
// would have run straight into a terminal.
func Quote(argv []string) string {
	var sb strings.Builder
	for i, a := range argv {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(shellQuote(a))
	}
	return sb.String()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\r\"'\\$`&;|<>()[]{}*?!#~^") {
		return s
	}
	// Single quotes are literal in sh; the only character needing care is the
	// single quote itself.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
