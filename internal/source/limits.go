package source

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// defaultWarnInterval is how often one repeating warning is allowed through.
// PROJECT.md §4.9 asks for rate-limited repeated errors, and the failures this
// package sees are overwhelmingly permanent rather than transient: a log file
// we may not read, a socket that refuses every accept, a sender that only ever
// emits over-long lines. Logging each occurrence costs a line per poll tick —
// 86400 a day per file — which buries the one line that mattered.
const defaultWarnInterval = time.Minute

// rateLimiter admits one event per interval and counts what it dropped, so the
// message that does get through still says how much was suppressed behind it.
//
// The clock is injectable because a test must not wait a real minute to prove
// that the second message is swallowed.
type rateLimiter struct {
	every time.Duration // 0 means defaultWarnInterval
	now   func() time.Time

	mu         sync.Mutex
	next       time.Time
	suppressed uint64
}

// allow reports whether the caller may log now and, if so, how many calls were
// suppressed since the previous one that was allowed.
func (r *rateLimiter) allow() (bool, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	if now.Before(r.next) {
		r.suppressed++
		return false, 0
	}
	every := r.every
	if every <= 0 {
		every = defaultWarnInterval
	}
	n := r.suppressed
	r.suppressed, r.next = 0, now.Add(every)
	return true, n
}

// warn logs at most one message per interval, reporting how many identical
// warnings were swallowed in the meantime.
func (r *rateLimiter) warn(log *slog.Logger, msg string, args ...any) {
	ok, suppressed := r.allow()
	if !ok {
		return
	}
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	log.Warn(msg, args...)
}

// sourceStats is the mutable side of [Stats]. One source can have many
// emitting goroutines (a tailer per glob member, a goroutine per connection),
// hence the atomics; the rate limiters are per counter so that a flood of
// truncations cannot starve the warning about discarded fragments.
type sourceStats struct {
	truncated   atomic.Uint64
	discarded   atomic.Uint64
	truncWarn   rateLimiter
	discardWarn rateLimiter
}

func (s *sourceStats) snapshot() Stats {
	return Stats{
		TruncatedLines:        s.truncated.Load(),
		DiscardedPartialLines: s.discarded.Load(),
	}
}

// noteTruncated records n truncated lines and warns about them at a bounded
// rate. max is the limit that was applied, which is worth logging because it
// is what an operator would have to raise.
func (s *sourceStats) noteTruncated(log *slog.Logger, n uint64, max int) {
	if n == 0 {
		return
	}
	total := s.truncated.Add(n)
	s.truncWarn.warn(log, "over-long lines were truncated",
		"count", n, "total", total, "max", max)
}

// noteSplitter drains a splitter's truncation count into the source's stats.
//
// Sources call this after every pump rather than only at EOF: a connection
// that hits its idle timeout, a cancelled stdin and a file tailer (which never
// reaches an authoritative EOF at all) would otherwise lose the count
// entirely, and PROJECT.md §4.1 promises over-long lines are *counted*.
func (s *sourceStats) noteSplitter(log *slog.Logger, sp *splitter) {
	s.noteTruncated(log, sp.takeTruncated(), sp.limit())
}

// noteDiscarded records n unterminated fragments dropped because the file they
// belonged to was rotated away, and warns at a bounded rate. Dropping them is
// deliberate (see handleRotation) but it must not be silent.
func (s *sourceStats) noteDiscarded(log *slog.Logger, n uint64, bytes int) {
	if n == 0 {
		return
	}
	total := s.discarded.Add(n)
	s.discardWarn.warn(log, "discarded an unterminated trailing line from a rotated file",
		"bytes", bytes, "total", total)
}
