// Package stats keeps the ban ledger and turns it into the statistics the
// status page and `banhammer status` report.
//
// # Why a separate ledger
//
// The ban manager forgets a ban the moment it expires, and its offense history
// is pruned at find_history (a day by default). Neither can answer "how many
// addresses did we block last week?". The Ledger is a bounded, append-mostly
// log of ban events that lives for Retention (thirty days by default) and is
// persisted to history.json so a restart does not blank the charts.
//
// # Bounds
//
// Memory is bounded by config, not by traffic (PROJECT.md §6): events older
// than Retention are pruned, and MaxEvents caps the ledger regardless of age
// by dropping the oldest. At the default cap the ledger costs a few megabytes
// at most, and a host that issues 100k bans a month has bigger problems than
// a truncated chart.
//
// # Concurrency
//
// Record is called from the aggregator goroutine (via the ban manager);
// Snapshot and Summarize are called from the control socket and the web
// server. One mutex, short critical sections; Summarize works on a copy.
package stats

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"banhammer/internal/model"
)

// DefaultMaxEvents is the hard cap on remembered ban events. It is a constant
// rather than a knob because the one reason to raise it — wanting a month of
// history on a host that bans more than 100k addresses a month — is better
// served by shipping the events somewhere designed for the volume.
const DefaultMaxEvents = 100_000

// MaxLineBytes bounds one stored log line. Half a kilobyte shows an entire
// sshd or nginx line; anything longer is a payload, and the operator wants
// to see that it is one, not read it.
const MaxLineBytes = 512

// DefaultMaxLineTotal bounds the bytes of log lines the ledger keeps in
// total. Events are cheap and lines are not: at the event cap, a line on
// every event would be 50 MB against a 20 MB RSS target. When the budget is
// exceeded the *oldest* events lose their lines and keep everything else,
// so the charts never change and the recent bans — the ones anyone looks
// at — always have theirs.
const DefaultMaxLineTotal = 4 << 20

// Ledger is the bounded ban event log. The zero value is not usable; use
// NewLedger.
type Ledger struct {
	retention    time.Duration
	maxEvents    int
	maxLineTotal int
	now          func() time.Time

	mu     sync.Mutex
	events []model.BanEvent // oldest first
	dirty  bool

	// lineBytes is the sum of len(Line) over events; linesFrom is the index
	// of the oldest event that may still have a line, so the budget sweep
	// does not rescan blanked history on every ban.
	lineBytes int
	linesFrom int

	// pending is the line handed to Observe for the ban the manager is
	// about to issue. See Observe.
	pending struct {
		ip   netip.Addr
		line string
	}
}

// Options configures a Ledger. Zero values take the defaults documented on
// each field.
type Options struct {
	// Retention is how long an event is kept. Default 30 days.
	Retention time.Duration
	// MaxEvents caps the ledger regardless of age. Default DefaultMaxEvents.
	MaxEvents int
	// MaxLineTotal caps the bytes of stored log lines. Default
	// DefaultMaxLineTotal.
	MaxLineTotal int
	// Now defaults to time.Now; injected so pruning is testable.
	Now func() time.Time
}

// NewLedger builds an empty ledger.
func NewLedger(o Options) *Ledger {
	l := &Ledger{retention: o.Retention, maxEvents: o.MaxEvents, maxLineTotal: o.MaxLineTotal, now: o.Now}
	if l.retention <= 0 {
		l.retention = 30 * 24 * time.Hour
	}
	if l.maxEvents <= 0 {
		l.maxEvents = DefaultMaxEvents
	}
	if l.maxLineTotal <= 0 {
		l.maxLineTotal = DefaultMaxLineTotal
	}
	if l.now == nil {
		l.now = time.Now
	}
	return l
}

// Retention reports how far back the ledger remembers.
func (l *Ledger) Retention() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retention
}

// SetRetention changes the window on a reload. Shrinking it prunes at once;
// growing it cannot bring back what was already dropped. Non-positive values
// are ignored rather than defaulted, so a reload cannot silently reset a
// tuned retention.
func (l *Ledger) SetRetention(d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.retention = d
	l.pruneLocked(l.now())
}

// Observe hands the ledger the log line that just pushed ip over its
// threshold, immediately before the ban manager is asked to act on it. The
// next Record for the same address picks the line up; a Record for any other
// address, or the next Observe, discards it.
//
// This is how a log line reaches the ledger without the ban manager ever
// seeing one. The manager's input is (monitor, ip, count, pattern) and its
// output is a model.Ban, and model.Ban must stay free of log text because it
// is pasted into command templates; threading the line through it would
// make that invariant a matter of discipline rather than of types. Observe
// and the manager's Offend run back to back on the aggregator goroutine, so
// "the next Record for this address" is the ban this line caused — or no
// Record at all, when the address is allowlisted or already banned, in
// which case the line is simply overwritten by the next one.
//
// The line is copied and sanitised here, so the caller's buffer may be
// reused as soon as Observe returns.
func (l *Ledger) Observe(ip netip.Addr, line []byte) {
	s := SanitizeLine(line)
	l.mu.Lock()
	l.pending.ip, l.pending.line = ip.Unmap().WithZone(""), s
	l.mu.Unlock()
}

// Record appends a ban. It implements ban.Recorder.
//
// The ban's own timestamp is kept rather than the ledger's clock, so a ban
// that is recorded late (it cannot be, today, but the contract is cheap) is
// charted when it happened. Events arrive in time order in practice; the
// occasional out-of-order one is tolerated — Summarize does not assume
// sortedness — but pruning assumes the *oldest* events are at the front, so
// an event older than the current head is inserted in place.
func (l *Ledger) Record(b model.Ban) {
	e := b.Event()
	if !e.IP.IsValid() || e.At.IsZero() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending.ip == e.IP && l.pending.line != "" {
		e.Line = l.pending.line
		l.pending.ip, l.pending.line = netip.Addr{}, ""
	}
	if n := len(l.events); n > 0 && e.At.Before(l.events[n-1].At) {
		i, _ := slices.BinarySearchFunc(l.events, e, func(a, b model.BanEvent) int {
			return a.At.Compare(b.At)
		})
		l.events = slices.Insert(l.events, i, e)
		if i < l.linesFrom {
			l.linesFrom++
		}
	} else {
		l.events = append(l.events, e)
	}
	l.lineBytes += len(e.Line)
	l.dirty = true
	l.pruneLocked(l.now())
	l.trimLinesLocked()
}

// trimLinesLocked blanks the oldest lines until the byte budget holds. It
// only ever moves forward through the slice: everything before linesFrom
// has already been blanked. l.mu must be held.
func (l *Ledger) trimLinesLocked() {
	for l.lineBytes > l.maxLineTotal && l.linesFrom < len(l.events) {
		e := &l.events[l.linesFrom]
		l.lineBytes -= len(e.Line)
		e.Line = ""
		l.linesFrom++
	}
}

// SanitizeLine makes a log line safe to show: valid UTF-8, printable
// characters only, at most MaxLineBytes. It is what stands between a log
// file an attacker can write to and an operator's terminal — a line that
// contains "\x1b[2J" must come out as text, not as a cleared screen — and
// between that file and the web page, where html/template does the rest.
//
// Anything that is not printable (control characters, including tab and
// escape, and unassigned code points) becomes U+FFFD so that its presence is
// visible rather than silently dropped. A truncated line ends in "…".
func SanitizeLine(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	truncated := false
	if len(raw) > MaxLineBytes {
		raw = raw[:MaxLineBytes]
		truncated = true
	}
	var b strings.Builder
	b.Grow(len(raw) + 3)
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid byte, or a code point cut by the truncation above;
			// either way it is not a character we can show.
			b.WriteRune(utf8.RuneError)
		case r == ' ' || unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			b.WriteRune(utf8.RuneError)
		}
		raw = raw[size:]
	}
	if truncated {
		b.WriteString("…")
	}
	return b.String()
}

// Restore seeds the ledger from persisted events, typically at startup. It
// discards what is already past retention, sorts the rest, and leaves the
// dirty flag as it found it: nothing new has happened, and the stale entries
// it dropped will go away with the next real write.
func (l *Ledger) Restore(events []model.BanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	wasDirty := l.dirty
	kept := make([]model.BanEvent, 0, len(events)+len(l.events))
	kept = append(kept, l.events...)
	for _, e := range events {
		if e.IP.IsValid() && !e.At.IsZero() {
			// history.json is 0644 and hand-editable; a line that did not
			// go through Observe is sanitised now, so the file is never a
			// way around SanitizeLine.
			e.Line = SanitizeLine([]byte(e.Line))
			kept = append(kept, e)
		}
	}
	slices.SortStableFunc(kept, func(a, b model.BanEvent) int {
		return a.At.Compare(b.At)
	})
	l.events = kept
	l.lineBytes, l.linesFrom = 0, 0
	for _, e := range l.events {
		l.lineBytes += len(e.Line)
	}
	l.pruneLocked(l.now())
	l.trimLinesLocked()
	l.dirty = wasDirty
}

// pruneLocked drops events past retention and, if still over the cap, the
// oldest surplus. l.mu must be held.
func (l *Ledger) pruneLocked(now time.Time) {
	cutoff := now.Add(-l.retention)
	i := 0
	for i < len(l.events) && !l.events[i].At.After(cutoff) {
		i++
	}
	if over := len(l.events) - i - l.maxEvents; over > 0 {
		i += over
	}
	if i > 0 {
		for _, e := range l.events[:i] {
			l.lineBytes -= len(e.Line)
		}
		l.linesFrom = max(0, l.linesFrom-i)
		l.events = slices.Delete(l.events, 0, i)
		l.dirty = true
	}
}

// Snapshot returns a copy of the ledger, oldest first, after pruning.
func (l *Ledger) Snapshot() []model.BanEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(l.now())
	return slices.Clone(l.events)
}

// Len reports how many events the ledger currently holds.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// Dirty reports whether anything changed since the last Flushed. The daemon
// polls it on its checkpoint tick so an idle host never rewrites history.json.
func (l *Ledger) Dirty() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dirty
}

// Flushed clears the dirty flag and returns the events to persist, or nil and
// false if nothing changed. The flag is cleared optimistically: a failed write
// is the caller's to retry, and it can call MarkDirty to do so.
func (l *Ledger) Flushed() ([]model.BanEvent, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.dirty {
		return nil, false
	}
	// Prune first: pruning sets dirty, and clearing the flag after it is
	// what makes this one write instead of one now and one more next tick.
	l.pruneLocked(l.now())
	l.dirty = false
	return slices.Clone(l.events), true
}

// MarkDirty forces the next Flushed to report the ledger, e.g. after a write
// failure.
func (l *Ledger) MarkDirty() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dirty = true
}

// Lookup is the geography hook: country code for an address, or ok=false.
// It is an interface rather than a func type so that a nil DB reads clearly
// at the call site.
type Lookup interface {
	Country(ip netip.Addr) (code string, ok bool)
}
