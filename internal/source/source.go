// Package source implements banhammer's input side: tailing log files
// (including globs, rotation and truncation), listening on udp/tcp/unix
// sockets, and reading stdin. Every source turns a byte stream into
// newline-delimited [model.Event]s on a channel.
//
// # Ownership of Event.Raw
//
// [model.Event] documents Raw as "only valid until the consumer returns",
// because model must describe the weakest contract any producer could offer.
// The sources in this package deliberately diverge from — and strengthen —
// that: every emitted Raw points into a write-once arena block that this
// package never writes to again, so a consumer may retain or hand off Raw
// without copying it. Read the two doc comments together: model states the
// floor, this package states what it actually delivers, and the floor is what
// a consumer must assume when it handles events from an unknown producer.
//
// The strengthening is not gratuitous. The pipeline fans events out to worker
// goroutines over a channel, which makes per-read buffer reuse a data race
// that would corrupt roughly one line in a million — the kind of bug nobody
// ever reproduces. Correctness wins; the arena keeps the cost at about one
// allocation per 64 KiB of log rather than one per line.
//
// The only caveat of arena allocation is retention: holding a single Raw keeps
// its whole 64 KiB block alive. Consumers that park events for a long time
// (hours) should copy.
package source

import (
	"context"
	"log/slog"
	"time"

	"banhammer/internal/model"
)

// maxLineBytes is the longest line a source will emit. Longer lines are
// truncated to this length and counted, never dropped: an attacker must not be
// able to hide a matching line behind a megabyte of padding.
const maxLineBytes = 64 << 10

// arenaBlock is the allocation granularity for emitted line copies.
const arenaBlock = 64 << 10

// Source is one configured input for a monitor.
type Source interface {
	// Name returns the monitor name this source feeds.
	Name() string
	// Run pumps events into out until ctx is cancelled, at which point it
	// returns nil. Any other return value is a fatal error for this source.
	// Run must not be called more than once.
	Run(ctx context.Context, out chan<- model.Event) error
	// Checkpoints returns the current read offsets for persistence, or nil
	// for sources that are not seekable (listeners, stdin). It is safe to
	// call concurrently with Run.
	Checkpoints() []model.Checkpoint
}

// Stats counts the log data a source had to mangle in order to stay inside its
// limits. Every Source in this package implements [StatsReporter]; the
// interface is separate from [Source] so that a consumer with its own Source
// implementation (a test fake, say) is not forced to grow a method.
//
// The sources deliberately do not import internal/metrics: they are used by
// `banhammer test` and by unit tests that have no registry, so the daemon
// polls these counters on metrics collection the same way it polls Checkpoints.
type Stats struct {
	// TruncatedLines is how many over-long lines were emitted truncated
	// rather than dropped (PROJECT.md §4.1: "truncated + counted").
	TruncatedLines uint64
	// DiscardedPartialLines is how many unterminated trailing fragments were
	// thrown away because the file holding them was rotated out from under
	// the tailer and nobody can ever finish them.
	DiscardedPartialLines uint64
}

// StatsReporter is a Source that reports what it had to mangle. It is safe to
// call Stats concurrently with Run.
type StatsReporter interface {
	Source
	Stats() Stats
}

// CheckpointLookup resolves a previously persisted offset for a path. It is
// implemented by store.Store; a nil CheckpointLookup means "no saved state",
// which makes start_at: checkpoint degrade to start_at: end.
type CheckpointLookup interface {
	Lookup(path string) (model.Checkpoint, bool)
}

// Accepted values for the startAt argument of [NewTail].
const (
	startAtCheckpoint = "checkpoint"
	startAtEnd        = "end"
	startAtBeginning  = "beginning"
)

// orDefaultLogger tolerates a nil logger, as libraries here are expected to.
func orDefaultLogger(log *slog.Logger) *slog.Logger {
	if log == nil {
		return slog.Default()
	}
	return log
}

// arena hands out write-once byte slices carved from larger blocks. It is not
// safe for concurrent use: each emitting goroutine owns exactly one.
type arena struct {
	buf []byte
}

// copy returns a private copy of p that the arena will never overwrite.
func (a *arena) copy(p []byte) []byte {
	if len(p) > len(a.buf) {
		n := arenaBlock
		if len(p) > n {
			n = len(p)
		}
		a.buf = make([]byte, n)
	}
	n := copy(a.buf, p)
	// Cap the result at its length so a consumer's append cannot scribble
	// over the next line handed out from this block.
	out := a.buf[:n:n]
	a.buf = a.buf[n:]
	return out
}

// emitter serializes lines onto the output channel for a single goroutine.
type emitter struct {
	monitor string
	out     chan<- model.Event
	arena   arena
	// transform optionally rewrites a line before it is copied (syslog
	// prefix stripping). nil means pass through.
	transform func([]byte) []byte
}

// emit copies line into the arena and blocks until the pipeline takes it or
// ctx is cancelled. Empty lines are dropped: they cannot carry an address, and
// forwarding them only burns pipeline capacity.
//
// Recv is stamped from the wall clock deliberately, with no injectable seam:
// it is the moment the line arrived from outside the process, which is not
// something a test or a fake clock gets to decide. Everything downstream that
// does need a controllable clock (windows, ban expiry) takes one of its own.
func (e *emitter) emit(ctx context.Context, line []byte) error {
	if e.transform != nil {
		line = e.transform(line)
	}
	if len(line) == 0 {
		return nil
	}
	ev := model.Event{Monitor: e.monitor, Raw: e.arena.copy(line), Recv: time.Now()}
	select {
	case e.out <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
