package source

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"banhammer/internal/model"
)

func TestNewStdinValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewStdin("", strings.NewReader(""), nil); err == nil {
		t.Error("empty monitor accepted")
	}
	if _, err := NewStdin("m", nil, nil); err == nil {
		t.Error("nil reader accepted")
	}
	s, err := NewStdin("m", strings.NewReader(""), nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	if s.Name() != "m" {
		t.Errorf("Name = %q, want m", s.Name())
	}
	if cps := s.Checkpoints(); cps != nil {
		t.Errorf("Checkpoints = %v, want nil for a pipe", cps)
	}
}

func TestStdinReads(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "whole lines", input: "a\nb\nc\n", want: []string{"a", "b", "c"}},
		{name: "trailing partial completed by EOF", input: "a\nb", want: []string{"a", "b"}},
		{name: "crlf", input: "a\r\nb\r\n", want: []string{"a", "b"}},
		{name: "blank lines dropped", input: "\n\na\n", want: []string{"a"}},
		{name: "empty input", input: "", want: nil},
		{
			name:  "oversized truncated, next line intact",
			input: strings.Repeat("q", maxLineBytes+10) + "\ntail\n",
			want:  []string{strings.Repeat("q", maxLineBytes), "tail"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewStdin("mon", strings.NewReader(tc.input), nil)
			if err != nil {
				t.Fatalf("NewStdin: %v", err)
			}
			out := make(chan model.Event, 16)
			if err := s.Run(context.Background(), out); err != nil {
				t.Fatalf("Run = %v", err)
			}
			close(out)
			var got []string
			for ev := range out {
				if ev.Monitor != "mon" {
					t.Errorf("Monitor = %q, want mon", ev.Monitor)
				}
				if ev.Recv.IsZero() {
					t.Error("Recv is zero")
				}
				got = append(got, string(ev.Raw))
			}
			if !equalStrings(got, tc.want) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStdinRunRejectsNilChannel(t *testing.T) {
	t.Parallel()
	s, err := NewStdin("m", strings.NewReader("x\n"), nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	if err := s.Run(context.Background(), nil); err == nil {
		t.Fatal("Run(nil channel) = nil, want error")
	}
}

// With an *os.File pipe the reader supports deadlines, so cancellation is
// prompt and the source leaves no goroutine behind.
func TestStdinPipeCancelPromptlyWithoutLeaking(t *testing.T) {
	// Not parallel: this counts goroutines (see sourceGoroutines).
	before := sourceGoroutines()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = w.Close() }()
	defer func() { _ = r.Close() }()

	s, err := NewStdin("mon", r, nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	out := make(chan model.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx, out) }()

	if _, err := io.WriteString(w, "live\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case ev := <-out:
		if string(ev.Raw) != "live" {
			t.Fatalf("event = %q", ev.Raw)
		}
	case <-time.After(waitTimeout):
		t.Fatal("no event")
	}

	// Now the pipe is quiet: cancellation must not wait for another line.
	begin := time.Now()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("cancellation took %v, want well under a second", d)
	}
	assertNoLeak(t, before)
}

// A reader without deadlines still returns promptly; the abandoned read
// goroutine is documented behaviour, and it exits as soon as the reader does.
func TestStdinBlockingReaderCancels(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	r := &blockingReader{release: release}
	s, err := NewStdin("mon", r, nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx, make(chan model.Event, 4)) }()

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return while a blocking read was in flight")
	}
	close(release) // let the abandoned goroutine finish so the test is clean
}

// The abandoned reader goroutine must never send on the caller's channel after
// Run has returned.
//
// daemon/pipeline.go closes the channel the moment Run returns, so a line that
// surfaces from the in-flight read a moment later used to panic the whole
// daemon with "send on closed channel" at shutdown — reachable with nothing
// more exotic than `banhammer run --stdin < auth.log`, since a regular
// *os.File has no read deadline. This test reproduces that shape exactly: the
// reader yields a line only *after* cancellation, and the channel is closed as
// soon as Run returns.
func TestStdinAbandonedReaderCannotSendOnClosedChannel(t *testing.T) {
	t.Parallel()
	before := sourceGoroutines()

	cancelled := make(chan struct{})
	r := &lateLineReader{afterClose: cancelled}
	s, err := NewStdin("mon", r, nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}

	out := make(chan model.Event) // unbuffered, like the pipeline's own
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx, out) }()

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run = %v, want nil on cancellation", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Run did not return after cancellation")
	}
	// Exactly what the pipeline does next. If the reader goroutine still held
	// this channel, the send below would panic in that goroutine and take the
	// test binary with it.
	close(out)
	close(cancelled) // now let the blocked read produce its line

	// The abandoned goroutine must also go away rather than park forever on a
	// send nobody will ever receive.
	assertNoLeak(t, before)
}

// lateLineReader blocks until afterClose is closed, then returns a line — the
// racy shape of a read that was in flight when the daemon shut down.
type lateLineReader struct {
	afterClose chan struct{}
	done       bool
}

func (r *lateLineReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	<-r.afterClose
	r.done = true
	return copy(p, "too-late\n"), nil
}

// Over-long lines are truncated and *counted* (PROJECT.md §4.1); the count has
// to be readable, not just logged.
func TestStdinCountsTruncatedLines(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("q", maxLineBytes+10) + "\nshort\n" + strings.Repeat("z", maxLineBytes+1) + "\n"
	s, err := NewStdin("mon", strings.NewReader(input), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	out := make(chan model.Event, 8)
	if err := s.Run(context.Background(), out); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if got := s.(StatsReporter).Stats().TruncatedLines; got != 2 {
		t.Errorf("Stats().TruncatedLines = %d, want 2", got)
	}
}

// blockingReader blocks until released, then reports EOF.
type blockingReader struct {
	release chan struct{}
	done    bool
}

func (b *blockingReader) Read([]byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	<-b.release
	b.done = true
	return 0, io.EOF
}

// A *bytes.Buffer has no SetReadDeadline; the probe must not mistake that for
// a fatal error.
func TestStdinNonDeadlineReader(t *testing.T) {
	t.Parallel()
	s, err := NewStdin("mon", bytes.NewBufferString("only\n"), nil)
	if err != nil {
		t.Fatalf("NewStdin: %v", err)
	}
	out := make(chan model.Event, 4)
	if err := s.Run(context.Background(), out); err != nil {
		t.Fatalf("Run = %v", err)
	}
	select {
	case ev := <-out:
		if string(ev.Raw) != "only" {
			t.Fatalf("event = %q", ev.Raw)
		}
	default:
		t.Fatal("no event")
	}
}
