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
	"sync"
	"time"

	"banhammer/internal/model"
)

// DefaultMaxEvents is the hard cap on remembered ban events. It is a constant
// rather than a knob because the one reason to raise it — wanting a month of
// history on a host that bans more than 100k addresses a month — is better
// served by shipping the events somewhere designed for the volume.
const DefaultMaxEvents = 100_000

// Ledger is the bounded ban event log. The zero value is not usable; use
// NewLedger.
type Ledger struct {
	retention time.Duration
	maxEvents int
	now       func() time.Time

	mu     sync.Mutex
	events []model.BanEvent // oldest first
	dirty  bool
}

// Options configures a Ledger. Zero values take the defaults documented on
// each field.
type Options struct {
	// Retention is how long an event is kept. Default 30 days.
	Retention time.Duration
	// MaxEvents caps the ledger regardless of age. Default DefaultMaxEvents.
	MaxEvents int
	// Now defaults to time.Now; injected so pruning is testable.
	Now func() time.Time
}

// NewLedger builds an empty ledger.
func NewLedger(o Options) *Ledger {
	l := &Ledger{retention: o.Retention, maxEvents: o.MaxEvents, now: o.Now}
	if l.retention <= 0 {
		l.retention = 30 * 24 * time.Hour
	}
	if l.maxEvents <= 0 {
		l.maxEvents = DefaultMaxEvents
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
	if n := len(l.events); n > 0 && e.At.Before(l.events[n-1].At) {
		i, _ := slices.BinarySearchFunc(l.events, e, func(a, b model.BanEvent) int {
			return a.At.Compare(b.At)
		})
		l.events = slices.Insert(l.events, i, e)
	} else {
		l.events = append(l.events, e)
	}
	l.dirty = true
	l.pruneLocked(l.now())
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
			kept = append(kept, e)
		}
	}
	slices.SortStableFunc(kept, func(a, b model.BanEvent) int {
		return a.At.Compare(b.At)
	})
	l.events = kept
	l.pruneLocked(l.now())
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
