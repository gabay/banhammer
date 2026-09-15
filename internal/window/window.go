// Package window implements the sliding-window hit counter that decides when
// an address has misbehaved often enough to be banned.
//
// The design goal is a flat memory profile: the cost of tracking an address is
// O(threshold), never O(hits), so a million requests from one source cost the
// same as five. Each tracked address owns a ring buffer of exactly `threshold`
// uint32 second-offsets from a daemon epoch; the (threshold+1)-th timestamp is
// never interesting, so it is never stored. A hard `maxTracked` LRU cap bounds
// the map itself, which is what keeps a spoofed-source UDP flood from turning
// the daemon into the attack.
//
// # Concurrency
//
// A Tracker is NOT goroutine-safe, by design. The single aggregator goroutine
// owns one Tracker per monitor and is the only caller, so a mutex would buy
// nothing but cache-line traffic on the hottest path in the daemon. Do not add
// one; if you need concurrent access, give each goroutine its own Tracker.
//
// # Keys
//
// Addresses are used verbatim as map keys. The caller is expected to hand over
// already-normalised addresses (internal/rule does Unmap on extraction), since
// ::ffff:1.2.3.4 and 1.2.3.4 are different netip.Addr values and would
// therefore be counted separately.
package window

import (
	"net/netip"
	"time"
)

// sweepMin is the floor on how many stale entries a single Sweep may drop.
// Sweep is called from the aggregator goroutine, so the work it does is a
// pause in log processing; bounding it keeps that pause in the microseconds
// even when a flood has just expired en masse.
const sweepMin = 1024

// maxThreshold caps the ring size. The cap exists because the int argument is
// converted to uint32: 1<<32 would truncate to a zero-length ring and panic on
// the first hit, and 1<<32+7 would silently become 7. A million is already
// absurd (4 MB of ring per address) but it is finite and it cannot truncate.
const maxThreshold = 1 << 20

// maxWindowSecs is the largest representable window, ~136 years. Without the
// clamp a window of 2^32 s truncates to zero and the monitor can never ban
// anyone — a silent failure that is worse than a coarse one.
const maxWindowSecs = 1<<32 - 1

// nilIdx marks the end of the intrusive LRU and free lists.
const nilIdx = int32(-1)

// entry is one tracked address.
//
// Entries live in a slab (Tracker.ents) and are linked by index rather than by
// pointer: int32 links are half the size of pointers, cost the GC nothing to
// scan, and let the ring buffers share one flat backing array. The ip field is
// a second copy of the map key, needed to delete the map entry when this slot
// is evicted.
type entry struct {
	ip   netip.Addr // 24 B: the map key, for eviction
	last uint32     // tick of the most recent hit; also the LRU ordering key
	head uint32     // ring index of the oldest live tick
	n    uint32     // number of live ticks, always < threshold between calls
	prev int32      // LRU: towards the most recently used
	next int32      // LRU: towards the least recently used; also the free list
}

// Tracker counts hits per address inside a sliding time window.
//
// The zero value is not usable; call New.
type Tracker struct {
	threshold  uint32
	windowSecs uint32
	maxTracked int
	now        func() time.Time

	// cur is the current second-offset from the daemon epoch (the instant New
	// was called). It is accumulated forward from the elapsed time between
	// calls rather than recomputed from a stored epoch, which is what makes it
	// monotonic no matter what the injected clock does; see tick.
	lastSeen time.Time
	cur      uint32
	frac     time.Duration // sub-second remainder carried to the next tick

	index map[netip.Addr]int32
	ents  []entry  // slab; free slots are chained through entry.next
	ticks []uint32 // ring buffers, threshold words per slab slot
	free  int32    // head of the free-slot list
	mru   int32    // most recently used entry
	lru   int32    // least recently used entry
	live  int      // number of occupied slots == len(index)
}

// New returns a Tracker that fires once an address is seen threshold times
// within window.
//
// threshold and window are clamped rather than rejected — the contract has no
// error return, and a counter is not worth failing a daemon's startup over.
// The minimums are 1 hit and 1 second (ticks have one-second resolution, so a
// sub-second window behaves as one second); the maximums are maxThreshold and
// ~136 years, which exist to stop a wild config value from truncating to
// something meaningless. Clamping is silent, so config should range-check
// these too if it wants to tell the user.
//
// A maxTracked of zero or less means "no cap": the map then grows with the
// number of distinct addresses seen, which on an internet-facing source is an
// unbounded memory sink driven by the attacker. Combined with the fact that
// the slab is never shrunk, one flood then costs its high-water mark for the
// life of the process. Only do that for a source you trust.
//
// A nil now defaults to time.Now.
func New(threshold int, window time.Duration, maxTracked int, now func() time.Time) *Tracker {
	if threshold < 1 {
		threshold = 1
	} else if threshold > maxThreshold {
		threshold = maxThreshold
	}
	if now == nil {
		now = time.Now
	}
	secs := int64(window / time.Second)
	if secs < 1 {
		secs = 1
	} else if secs > maxWindowSecs {
		secs = maxWindowSecs
	}
	return &Tracker{
		threshold:  uint32(threshold),
		windowSecs: uint32(secs),
		maxTracked: maxTracked,
		now:        now,
		lastSeen:   now(),
		index:      make(map[netip.Addr]int32),
		free:       nilIdx,
		mru:        nilIdx,
		lru:        nilIdx,
	}
}

// Hit records one offense by ip and reports the current in-window count and
// whether the threshold was reached.
//
// On a trigger the counter is reset, so a persistent attacker fires once per
// threshold hits rather than on every subsequent line; the returned count is
// then exactly threshold. With threshold == 1 the very first hit triggers.
//
// The window is inclusive (PROJECT.md §4.4: age <= window counts, age > window
// has expired). That choice matters because ticks are floor-truncated to whole
// seconds, so two hits e seconds apart can land ceil(e) ticks apart: with an
// inclusive bound the guaranteed effective window is window-1s, with an
// exclusive one it would be window-2s — and at window == 1s an exclusive bound
// would mean two hits 20 ms apart fail to trigger a 1s/2-hit rule.
func (t *Tracker) Hit(ip netip.Addr) (count int, triggered bool) {
	tick := t.tick()

	i, ok := t.index[ip]
	if !ok {
		i = t.insert(ip, tick)
	} else if i != t.mru {
		t.unlink(i)
		t.pushFront(i)
	}

	e := &t.ents[i]
	e.last = tick

	ring := t.ticks[int(i)*int(t.threshold):][:t.threshold]

	// Expire from the old end first. Subtraction is deliberately done in
	// wrapping uint32 arithmetic: ticks are monotonic, so tick-ring[head] is
	// the true age in seconds for any age below 2^32 s (~136 years), which
	// means the epoch wrap needs no special case at all.
	for e.n > 0 && tick-ring[e.head] > t.windowSecs {
		e.head++
		if e.head == t.threshold {
			e.head = 0
		}
		e.n--
	}

	// n < threshold is an invariant between calls (we reset on trigger), so
	// there is always room and the write can never clobber a live tick.
	pos := e.head + e.n
	if pos >= t.threshold {
		pos -= t.threshold
	}
	ring[pos] = tick
	e.n++

	if e.n >= t.threshold {
		e.head, e.n = 0, 0
		return int(t.threshold), true
	}
	return int(e.n), false
}

// Sweep drops tracked addresses whose last hit has fallen out of the window
// (age > window, matching Hit).
//
// This deviates from PROJECT.md §4.4, which suggests scanning a bounded slice
// of the map: because every hit moves its entry to the front of the LRU list,
// the list is already ordered by last-hit tick, so Sweep walks the stale tail
// and stops at the first live entry. That is strictly cheaper — O(dropped)
// instead of O(sampled) — and needs no randomisation to be fair.
//
// The guarantee is deliberately partial: at most max(1024, Len()/8) entries go
// per call, and anything left over goes on the next call. Callers should
// therefore sweep periodically (PROJECT.md suggests every window/4) rather
// than assuming one call empties the backlog. Not sweeping at all is safe but
// wastes memory: stale ticks are also expired lazily on the next Hit for that
// address.
func (t *Tracker) Sweep() {
	tick := t.tick()
	budget := t.live / 8
	if budget < sweepMin {
		budget = sweepMin
	}
	for n := 0; n < budget; n++ {
		i := t.lru
		if i == nilIdx {
			return
		}
		if tick-t.ents[i].last <= t.windowSecs {
			return // the rest of the list is younger still
		}
		t.remove(i)
	}
}

// Len reports how many addresses are currently tracked. It never exceeds
// maxTracked.
func (t *Tracker) Len() int { return t.live }

// Forget discards any state for ip, as done when the address gets banned and
// its hits stop being interesting.
func (t *Tracker) Forget(ip netip.Addr) {
	if i, ok := t.index[ip]; ok {
		t.remove(i)
	}
}

// tick returns the current second-offset from the daemon epoch.
//
// Ticks must never go backwards: every age in this package is an unsigned
// difference, and a tick that moved back would make stored ticks look ~136
// years old and would break the LRU list's ordering. So instead of recomputing
// the offset from a stored epoch, we accumulate the *forward* time elapsed
// since the previous call.
//
// That makes two awkward cases free. A clock stepping backwards (an NTP step
// on a wall-clock source; time.Now's monotonic reading makes it unreachable in
// production) contributes nothing and time simply resumes from the new
// instant, so no counter is frozen or wedged. A forward jump so large that
// time.Duration saturates (>292 years) still only ever adds.
//
// The uint32 itself wraps every ~136 years, which is harmless: ages are
// computed with wrapping subtraction, so they stay correct across the wrap.
func (t *Tracker) tick() uint32 {
	now := t.now()
	d := now.Sub(t.lastSeen)
	t.lastSeen = now
	if d <= 0 {
		return t.cur
	}
	// Split the delta so the sub-second remainder can be carried without
	// overflowing: both terms below are < 1 s.
	secs := d / time.Second
	t.frac += d % time.Second
	if t.frac >= time.Second {
		t.frac -= time.Second
		secs++
	}
	t.cur += uint32(secs)
	return t.cur
}

// insert allocates a slot for ip, evicting the least recently used address
// first if the tracker is at its cap.
func (t *Tracker) insert(ip netip.Addr, tick uint32) int32 {
	if t.maxTracked > 0 && t.live >= t.maxTracked && t.lru != nilIdx {
		t.remove(t.lru) // O(1): no scan of the map to find a victim
	}

	i := t.alloc()

	e := &t.ents[i]
	e.ip, e.last, e.head, e.n = ip, tick, 0, 0
	t.index[ip] = i
	t.live++
	t.pushFront(i)
	return i
}

// alloc returns a free slab slot, growing the slab if there is none.
//
// Growth is deliberately not plain append: append doubles, and at the default
// cap of 100k addresses a 2x over-commit on the entry slab is tens of
// megabytes of untouched memory — the opposite of this package's point. 1/8
// growth is still geometric (so inserts stay amortised O(1)) but wastes at
// most 12.5%, and it never overshoots maxTracked.
//
// The trade is not free: growing by 1/8 instead of 2x copies the slab ~8x more
// often, which shows up as transient garbage on the cold-insert path. Steady
// state is what matters for a daemon that runs for months, and above
// maxTracked the growth stops entirely.
func (t *Tracker) alloc() int32 {
	if i := t.free; i != nilIdx {
		t.free = t.ents[i].next
		return i
	}

	i := int32(len(t.ents))
	if len(t.ents) == cap(t.ents) {
		n := len(t.ents) + len(t.ents)/8
		if floor := len(t.ents) + 16; n < floor {
			n = floor
		}
		if t.maxTracked > 0 && n > t.maxTracked {
			n = t.maxTracked
		}
		ents := make([]entry, len(t.ents), n)
		copy(ents, t.ents)
		t.ents = ents
		ticks := make([]uint32, len(t.ticks), n*int(t.threshold))
		copy(ticks, t.ticks)
		t.ticks = ticks
	}
	t.ents = t.ents[:i+1]
	t.ticks = t.ticks[:(int(i)+1)*int(t.threshold)]
	return i
}

// remove unlinks slot i, drops its map key and returns the slot to the free
// list. The ring buffer is left as-is; n == 0 makes its contents unreachable.
//
// The slab itself is never shrunk, so the tracker keeps its high-water mark
// (bounded by maxTracked) for the life of the daemon. That is the point: after
// a flood, re-tracking costs no allocation at all.
func (t *Tracker) remove(i int32) {
	delete(t.index, t.ents[i].ip)
	t.unlink(i)
	t.ents[i] = entry{next: t.free}
	t.free = i
	t.live--
}

func (t *Tracker) pushFront(i int32) {
	t.ents[i].prev = nilIdx
	t.ents[i].next = t.mru
	if t.mru != nilIdx {
		t.ents[t.mru].prev = i
	}
	t.mru = i
	if t.lru == nilIdx {
		t.lru = i
	}
}

func (t *Tracker) unlink(i int32) {
	e := &t.ents[i]
	if e.prev != nilIdx {
		t.ents[e.prev].next = e.next
	} else {
		t.mru = e.next
	}
	if e.next != nilIdx {
		t.ents[e.next].prev = e.prev
	} else {
		t.lru = e.prev
	}
	e.prev, e.next = nilIdx, nilIdx
}
