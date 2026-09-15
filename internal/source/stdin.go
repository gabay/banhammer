package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"banhammer/internal/model"
)

// stdinReadSlice bounds a single read when the reader supports deadlines, so
// cancellation does not wait for the next line to arrive.
const stdinReadSlice = 200 * time.Millisecond

// NewStdin returns a Source that reads newline-delimited lines from r, for
// `journalctl -f -u sshd | banhammer run` style pipelines. r is usually
// os.Stdin; taking an io.Reader keeps it testable.
//
// If r supports read deadlines (a pipe or socket opened as an *os.File does),
// cancellation is prompt and the reader goroutine is always joined. For a
// reader without deadlines, Run still returns immediately on cancellation, but
// a goroutine may remain parked inside a blocking Read until that read returns
// — there is no portable way to interrupt a reader we do not own.
func NewStdin(monitor string, r io.Reader, log *slog.Logger) (Source, error) {
	if monitor == "" {
		return nil, errors.New("stdin: monitor name is empty")
	}
	if r == nil {
		return nil, fmt.Errorf("stdin %q: nil reader", monitor)
	}
	return &stdinSource{
		monitor: monitor,
		r:       r,
		log:     orDefaultLogger(log).With("monitor", monitor, "source", "stdin"),
	}, nil
}

type stdinSource struct {
	monitor string
	r       io.Reader
	log     *slog.Logger
}

func (s *stdinSource) Name() string { return s.monitor }

// Checkpoints returns nil: a pipe has no resumable position.
func (s *stdinSource) Checkpoints() []model.Checkpoint { return nil }

// deadlineReader is implemented by *os.File on pipes, ttys and sockets.
type deadlineReader interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

func (s *stdinSource) Run(ctx context.Context, out chan<- model.Event) error {
	if out == nil {
		return fmt.Errorf("stdin %q: nil output channel", s.monitor)
	}
	if dr, ok := s.r.(deadlineReader); ok {
		if err := dr.SetReadDeadline(time.Now()); err == nil {
			// Deadlines work on this reader: reset and use the interruptible
			// path, which leaves no goroutine behind.
			if err := dr.SetReadDeadline(time.Time{}); err == nil {
				return s.readLoop(ctx, dr, out, true)
			}
		}
	}
	// Fallback: the read cannot be interrupted, so it runs in a goroutine and
	// Run abandons it on cancellation (see NewStdin).
	done := make(chan error, 1)
	go func() { done <- s.readLoop(ctx, s.r, out, false) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		s.log.Debug("cancelled with a read in flight; the reader goroutine exits when that read returns")
		return nil
	}
}

func (s *stdinSource) readLoop(ctx context.Context, r io.Reader, out chan<- model.Event, deadlines bool) error {
	em := emitter{monitor: s.monitor, out: out}
	emit := func(line []byte) error { return em.emit(ctx, line) }
	sp := splitter{max: maxLineBytes}
	buf := make([]byte, connReadChunk)

	for {
		if deadlines {
			dr := r.(deadlineReader)
			if err := dr.SetReadDeadline(time.Now().Add(stdinReadSlice)); err != nil {
				return nil
			}
		}
		n, err := r.Read(buf)
		if n > 0 {
			if perr := sp.push(buf[:n], emit); perr != nil {
				return nil // context cancelled
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				// EOF on a pipe is authoritative: emit any trailing line.
				if ferr := sp.flush(emit); ferr != nil {
					return nil
				}
				if sp.truncated > 0 {
					s.log.Warn("over-long lines were truncated", "count", sp.truncated, "max", maxLineBytes)
				}
				s.log.Info("stdin closed")
				return nil
			}
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("stdin %q: read: %w", s.monitor, err)
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
	}
}
