package window

import (
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"
)

// fakeClock is a manually driven clock: no test in this package sleeps.
type fakeClock struct{ t time.Time }

var epochBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newClock() *fakeClock { return &fakeClock{t: epochBase} }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func ip(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err) // test helper only
	}
	return a
}

// step is one scripted call in a hit-sequence table test.
type step struct {
	advance   time.Duration
	ip        string
	wantCount int
	wantTrig  bool
}

func TestHitSequences(t *testing.T) {
	t.Parallel()

	const a, b = "10.0.0.1", "10.0.0.2"

	tests := []struct {
		name      string
		threshold int
		window    time.Duration
		steps     []step
	}{
		{
			name:      "threshold one triggers immediately",
			threshold: 1,
			window:    10 * time.Minute,
			steps: []step{
				{0, a, 1, true},
				{time.Second, a, 1, true},
				{time.Hour, a, 1, true},
			},
		},
		{
			name:      "counts up then triggers and resets",
			threshold: 3,
			window:    time.Minute,
			steps: []step{
				{0, a, 1, false},
				{time.Second, a, 2, false},
				{time.Second, a, 3, true},
				// Reset: the next hit starts a fresh count even though
				// four hits are inside the window.
				{time.Second, a, 1, false},
				{time.Second, a, 2, false},
				{time.Second, a, 3, true},
			},
		},
		{
			name:      "hits spread wider than the window never trigger",
			threshold: 3,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{11 * time.Second, a, 1, false},
				{11 * time.Second, a, 1, false},
				{11 * time.Second, a, 1, false},
			},
		},
		{
			// Inclusive boundary, both sides. Ticks are floor-truncated to
			// seconds, so this is the worst case a user can observe.
			name:      "boundary: exactly window old still counts",
			threshold: 2,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{10 * time.Second, a, 2, true},
			},
		},
		{
			name:      "boundary: one second past the window has expired",
			threshold: 2,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{11 * time.Second, a, 1, false},
			},
		},
		{
			name:      "boundary: one second inside the window still counts",
			threshold: 2,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{9 * time.Second, a, 2, true},
			},
		},
		{
			// The case that decided the boundary: hits 20 ms apart must
			// trigger a 1s/2-hit rule even when they straddle a tick edge.
			name:      "boundary: hits 20ms apart trigger a one-second rule",
			threshold: 2,
			window:    time.Second,
			steps: []step{
				{990 * time.Millisecond, a, 1, false}, // tick 0
				{20 * time.Millisecond, a, 2, true},   // tick 1
			},
		},
		{
			name:      "oldest expiring keeps the newer hits",
			threshold: 3,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{4 * time.Second, a, 2, false},
				{4 * time.Second, a, 3, true},
				{0, a, 1, false},               // t=8
				{4 * time.Second, a, 2, false}, // t=12
				{4 * time.Second, a, 3, true},  // t=16, oldest (8) still inside
			},
		},
		{
			// Expiry advances head without a trigger, so the next writes
			// wrap around the end of the ring.
			name:      "ring wraps when expiry advances head",
			threshold: 3,
			window:    10 * time.Second,
			steps: []step{
				{0, a, 1, false},
				{time.Second, a, 2, false},
				{11 * time.Second, a, 1, false}, // t=12, both earlier hits expire
				{time.Second, a, 2, false},      // t=13, write index wraps to 0
				{time.Second, a, 3, true},       // t=14
			},
		},
		{
			name:      "addresses are counted independently",
			threshold: 2,
			window:    time.Minute,
			steps: []step{
				{0, a, 1, false},
				{time.Second, b, 1, false},
				{time.Second, b, 2, true},
				{time.Second, a, 2, true},
			},
		},
		{
			name:      "sub-second window is clamped to one second",
			threshold: 2,
			window:    100 * time.Millisecond,
			steps: []step{
				{0, a, 1, false},
				{100 * time.Millisecond, a, 2, true}, // same tick
				{2 * time.Second, a, 1, false},
			},
		},
		{
			name:      "ipv6 is tracked like ipv4",
			threshold: 2,
			window:    time.Minute,
			steps: []step{
				{0, "2001:db8::1", 1, false},
				{time.Second, "2001:db8::2", 1, false},
				{time.Second, "2001:db8::1", 2, true},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newClock()
			tr := New(tc.threshold, tc.window, 1000, c.now)
			for i, s := range tc.steps {
				c.add(s.advance)
				count, trig := tr.Hit(ip(s.ip))
				if count != s.wantCount || trig != s.wantTrig {
					t.Fatalf("step %d (%s at +%s): Hit = (%d, %v), want (%d, %v)",
						i, s.ip, s.advance, count, trig, s.wantCount, s.wantTrig)
				}
			}
		})
	}
}

// TestNewClampsArguments drives the clamping through Hit rather than reading
// the internal fields: what matters is that a hostile or silly config cannot
// make the tracker panic, ban instantly, or never ban at all.
func TestNewClampsArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		threshold int
		window    time.Duration
		// hits are applied one second apart; the test asserts on which hit
		// (1-based) the tracker first triggers, or 0 for "never within hits".
		hits          int
		wantTriggerOn int
	}{
		{"zero threshold clamps to one", 0, time.Minute, 3, 1},
		{"negative threshold clamps to one", -3, time.Minute, 3, 1},
		{"zero window clamps to one second", 5, 0, 5, 0},
		{"negative window clamps to one second", 5, -time.Hour, 5, 0},
		{"normal", 3, 10 * time.Minute, 5, 3},
		{"window truncates to whole seconds", 2, 1500 * time.Millisecond, 2, 2},
		// The uint32 conversion used to truncate these: 1<<32 became a
		// zero-length ring and panicked on the first Hit, and 1<<32+7
		// silently became a threshold of 7.
		{"threshold 2^32 does not truncate to zero", 1 << 32, time.Hour, 20, 0},
		{"threshold 2^32+7 does not truncate to seven", 1<<32 + 7, time.Hour, 20, 0},
		// A window of 2^32 s used to truncate to zero, so nothing ever
		// triggered; clamped, it is simply a very long window.
		{"window 2^32 seconds does not truncate to zero", 2, 1 << 32 * time.Second, 2, 2},
		{"window beyond 2^32 seconds is clamped", 2, time.Duration(math.MaxInt64), 2, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newClock()
			tr := New(tc.threshold, tc.window, 10, c.now)
			a := ip("10.0.0.1")

			got := 0
			for i := 1; i <= tc.hits; i++ {
				if _, trig := tr.Hit(a); trig && got == 0 {
					got = i
				}
				c.add(time.Second)
			}
			if got != tc.wantTriggerOn {
				t.Errorf("first trigger on hit %d, want %d", got, tc.wantTriggerOn)
			}
		})
	}
}

func TestNewNilClock(t *testing.T) {
	t.Parallel()
	tr := New(2, time.Minute, 10, nil)
	if _, trig := tr.Hit(ip("10.0.0.1")); trig {
		t.Fatal("first of two hits triggered")
	}
	if _, trig := tr.Hit(ip("10.0.0.1")); !trig {
		t.Fatal("second hit did not trigger with the default clock")
	}
}

// TestMemoryIsBoundedByThreshold is the package's reason to exist: a flood from
// a single address must not grow its footprint.
func TestMemoryIsBoundedByThreshold(t *testing.T) {
	t.Parallel()

	const threshold = 5
	c := newClock()
	tr := New(threshold, time.Hour, 1000, c.now)
	addr := ip("198.51.100.7")

	for i := 0; i < 1_000_000; i++ {
		tr.Hit(addr)
	}

	if got := tr.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
	if got := len(tr.ents); got != 1 {
		t.Fatalf("slab holds %d entries, want 1", got)
	}
	if got := len(tr.ticks); got != threshold {
		t.Fatalf("ring storage is %d words, want %d", got, threshold)
	}
	if got := tr.ents[0].n; got >= threshold {
		t.Fatalf("live tick count %d must stay below threshold between calls", got)
	}
}

func TestHitDoesNotAllocateOnWarmPath(t *testing.T) {
	// Not parallel: AllocsPerRun wants a quiet GOMAXPROCS.
	c := newClock()
	tr := New(5, time.Hour, 1000, c.now)
	addr := ip("203.0.113.9")
	tr.Hit(addr)

	if got := testing.AllocsPerRun(1000, func() { tr.Hit(addr) }); got != 0 {
		t.Fatalf("Hit allocates %v objects per call on the warm path, want 0", got)
	}
}

func TestMaxTrackedCapsTheMap(t *testing.T) {
	t.Parallel()

	const maxTracked = 100
	const total = 10_000

	c := newClock()
	tr := New(5, time.Hour, maxTracked, c.now)

	for i := 0; i < total; i++ {
		tr.Hit(ip(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)))
		if got := tr.Len(); got > maxTracked {
			t.Fatalf("after %d distinct addresses Len() = %d, want <= %d", i+1, got, maxTracked)
		}
	}

	if got := tr.Len(); got != maxTracked {
		t.Fatalf("Len() = %d, want %d", got, maxTracked)
	}
	// The slab must be reused, not grown, once the cap is reached.
	if got := len(tr.ents); got != maxTracked {
		t.Fatalf("slab grew to %d entries, want %d", got, maxTracked)
	}

	// The most recently active addresses are the survivors.
	for i := total - maxTracked; i < total; i++ {
		a := ip(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
		if _, ok := tr.index[a]; !ok {
			t.Fatalf("%v was evicted but is among the %d most recent", a, maxTracked)
		}
	}
}

func TestMaxTrackedEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(5, time.Hour, 3, c.now)
	a, b, d := ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")

	tr.Hit(a)
	c.add(time.Second)
	tr.Hit(b)
	c.add(time.Second)
	tr.Hit(d)
	c.add(time.Second)
	tr.Hit(a) // a is now the most recently used, b the least

	e := ip("10.0.0.4")
	c.add(time.Second)
	tr.Hit(e)

	if _, ok := tr.index[b]; ok {
		t.Error("least recently used address survived eviction")
	}
	for _, want := range []netip.Addr{a, d, e} {
		if _, ok := tr.index[want]; !ok {
			t.Errorf("%v was evicted, want retained", want)
		}
	}
	if got := tr.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}
}

func TestMaxTrackedUnlimited(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(5, time.Hour, 0, c.now)
	for i := 0; i < 500; i++ {
		tr.Hit(ip(fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff)))
	}
	if got := tr.Len(); got != 500 {
		t.Fatalf("Len() = %d, want 500 with maxTracked disabled", got)
	}
}

// TestSlabGrowthIsBounded pins the memory claim: the slab over-commits by at
// most 1/8 and never exceeds the cap, so the per-IP cost stays near budget.
func TestSlabGrowthIsBounded(t *testing.T) {
	t.Parallel()

	const maxTracked, threshold = 5000, 4
	c := newClock()
	tr := New(threshold, time.Hour, maxTracked, c.now)

	for i := 0; i < maxTracked*2; i++ {
		tr.Hit(ip(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)))
		n := len(tr.ents)
		if cap(tr.ents) > maxTracked {
			t.Fatalf("slab cap %d exceeds maxTracked %d", cap(tr.ents), maxTracked)
		}
		if limit := n + n/8 + 16; cap(tr.ents) > limit {
			t.Fatalf("slab cap %d over-commits past %d for %d entries", cap(tr.ents), limit, n)
		}
		if cap(tr.ticks) != cap(tr.ents)*threshold {
			t.Fatalf("tick storage cap %d, want %d", cap(tr.ticks), cap(tr.ents)*threshold)
		}
	}
}

// TestEvictionLosesHistory documents the cost of the LRU cap: an evicted
// address starts counting from scratch.
func TestEvictionLosesHistory(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(3, time.Hour, 1, c.now)
	a, b := ip("10.0.0.1"), ip("10.0.0.2")

	tr.Hit(a)
	tr.Hit(a)
	tr.Hit(b) // evicts a
	if count, _ := tr.Hit(a); count != 1 {
		t.Fatalf("count after eviction = %d, want 1", count)
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(5, 10*time.Second, 1000, c.now)
	a, b := ip("10.0.0.1"), ip("10.0.0.2")

	tr.Hit(a)
	c.add(5 * time.Second)
	tr.Hit(b)

	// a is exactly 10s old, which is still in window, so nothing goes.
	c.add(5 * time.Second)
	tr.Sweep()
	if got := tr.Len(); got != 2 {
		t.Fatalf("Len() = %d after sweeping at the boundary, want 2", got)
	}

	// One second later a is 11s old: stale. b is 6s old: live.
	c.add(time.Second)
	tr.Sweep()
	if got := tr.Len(); got != 1 {
		t.Fatalf("Len() = %d after sweep, want 1", got)
	}
	if _, ok := tr.index[a]; ok {
		t.Error("stale entry survived Sweep")
	}
	if _, ok := tr.index[b]; !ok {
		t.Error("live entry was swept")
	}

	c.add(time.Hour)
	tr.Sweep()
	if got := tr.Len(); got != 0 {
		t.Fatalf("Len() = %d after sweeping everything, want 0", got)
	}

	tr.Sweep() // empty tracker must not misbehave
	if got := tr.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

// TestSweepStopsAtTheFirstLiveEntry covers the interleaved case: stale and
// live addresses mixed, where the LRU ordering is what lets Sweep stop early.
func TestSweepStopsAtTheFirstLiveEntry(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(5, 10*time.Second, 100, c.now)

	// Ten addresses one second apart, then re-touch the even ones so they
	// are interleaved with the odd ones in age order.
	for i := 0; i < 10; i++ {
		tr.Hit(ip(fmt.Sprintf("10.0.0.%d", i)))
		c.add(time.Second)
	}
	for i := 0; i < 10; i += 2 {
		tr.Hit(ip(fmt.Sprintf("10.0.0.%d", i)))
		c.add(time.Second)
	}

	// Now at t=15: odd entries were last hit at t=1,3,5,7,9 (ages 14..6) and
	// even ones at t=10..14 (ages 5..1). Window is 10s, so only the odd
	// entries older than 10s go.
	tr.Sweep()

	for i := 0; i < 10; i++ {
		a := ip(fmt.Sprintf("10.0.0.%d", i))
		_, kept := tr.index[a]
		wantKept := i%2 == 0 || i >= 5
		if kept != wantKept {
			t.Errorf("10.0.0.%d kept = %v, want %v", i, kept, wantKept)
		}
	}
}

// TestSweepIsBounded pins the documented partial-sweep guarantee with literal
// numbers, so that changing either sweepMin or the Len()/8 divisor fails here.
func TestSweepIsBounded(t *testing.T) {
	t.Parallel()

	const total = 20_000
	c := newClock()
	tr := New(5, 10*time.Second, 0, c.now)
	for i := 0; i < total; i++ {
		tr.Hit(ip(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)))
	}
	c.add(time.Hour) // everything is stale

	// 20000/8 = 2500, comfortably above the 1024 floor.
	tr.Sweep()
	if got := tr.Len(); got != 17_500 {
		t.Fatalf("first Sweep left Len() = %d, want 17500 (a 2500 budget)", got)
	}
	// 17500/8 = 2187 (integer division).
	tr.Sweep()
	if got := tr.Len(); got != 15_313 {
		t.Fatalf("second Sweep left Len() = %d, want 15313 (a 2187 budget)", got)
	}

	// Drain, and check the floor takes over once Len()/8 drops below 1024.
	floorSeen := false
	for calls := 3; tr.Len() > 0; calls++ {
		before := tr.Len()
		tr.Sweep()
		dropped := before - tr.Len()
		switch {
		case before < 8*1024:
			floorSeen = true
			if want := min(1024, before); dropped != want {
				t.Fatalf("call %d dropped %d of %d entries, want the %d floor", calls, dropped, before, want)
			}
		case dropped != before/8:
			t.Fatalf("call %d dropped %d of %d entries, want %d", calls, dropped, before, before/8)
		}
		if calls > 40 {
			t.Fatalf("draining %d entries took more than 40 calls", total)
		}
	}
	if !floorSeen {
		t.Fatal("the sweepMin floor was never exercised")
	}
}

// TestSweepKeepsSlabReusable guards against the free list being corrupted by
// sweeps: freed slots must come back for new addresses.
func TestSweepKeepsSlabReusable(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(2, 10*time.Second, 0, c.now)
	for round := 0; round < 5; round++ {
		for i := 0; i < 20; i++ {
			tr.Hit(ip(fmt.Sprintf("10.0.%d.%d", round, i)))
		}
		c.add(time.Minute)
		tr.Sweep()
		if got := tr.Len(); got != 0 {
			t.Fatalf("round %d: Len() = %d, want 0", round, got)
		}
	}
	if got := len(tr.ents); got != 20 {
		t.Fatalf("slab grew to %d entries across 5 rounds of 20, want 20", got)
	}
	// And the reused slots still count correctly.
	a := ip("10.0.9.9")
	if count, trig := tr.Hit(a); count != 1 || trig {
		t.Fatalf("Hit on a reused slot = (%d, %v), want (1, false)", count, trig)
	}
	if count, trig := tr.Hit(a); count != 2 || !trig {
		t.Fatalf("second Hit on a reused slot = (%d, %v), want (2, true)", count, trig)
	}
}

func TestForget(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(3, time.Hour, 10, c.now)
	a, b := ip("10.0.0.1"), ip("10.0.0.2")

	tr.Hit(a)
	tr.Hit(a)
	tr.Hit(b)

	tr.Forget(a)
	if got := tr.Len(); got != 1 {
		t.Fatalf("Len() = %d after Forget, want 1", got)
	}
	if count, _ := tr.Hit(a); count != 1 {
		t.Fatalf("count after Forget = %d, want 1", count)
	}
	tr.Forget(ip("192.0.2.1")) // unknown address is a no-op
	if got := tr.Len(); got != 2 {
		t.Fatalf("Len() = %d after forgetting an unknown address, want 2", got)
	}
}

// TestClockJumpsBackwards covers an NTP step on a wall clock (time.Now's
// monotonic reading makes this impossible in production, but callers may
// inject anything). Everything here is asserted through the public API: the
// internal tick is deliberately not read, since reading it advances it.
func TestClockJumpsBackwards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jump time.Duration
	}{
		{"one second", -time.Second},
		{"one hour", -time.Hour},
		{"ten years", -10 * 365 * 24 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newClock()
			tr := New(3, time.Minute, 10, c.now)
			a := ip("10.0.0.1")

			c.add(30 * time.Second)
			if count, _ := tr.Hit(a); count != 1 {
				t.Fatalf("count = %d, want 1", count)
			}

			// The hit before the step must still be inside the window: if
			// the age underflowed it would look ~136 years old and the
			// count would restart at 1.
			c.add(tc.jump)
			count, trig := tr.Hit(a)
			if trig {
				t.Fatalf("threshold 3 triggered after 2 hits")
			}
			if count != 2 {
				t.Fatalf("count after the backwards step = %d, want 2", count)
			}

			// Not wedged: the counter still triggers, and still expires.
			c.add(time.Second)
			if count, trig := tr.Hit(a); !trig || count != 3 {
				t.Fatalf("Hit = (%d, %v), want (3, true)", count, trig)
			}
			c.add(time.Hour)
			if count, trig := tr.Hit(a); trig || count != 1 {
				t.Fatalf("Hit after the window elapsed = (%d, %v), want (1, false)", count, trig)
			}
			c.add(time.Hour)
			tr.Sweep()
			if got := tr.Len(); got != 0 {
				t.Fatalf("Len() = %d, entry wedged past the window", got)
			}
		})
	}
}

// TestClockJumpsForward is the other half: a large forward step must expire
// history rather than break it. The last case exceeds time.Duration's ~292
// year range, where a tick computed as now.Sub(epoch) would saturate and wrap
// backwards.
func TestClockJumpsForward(t *testing.T) {
	t.Parallel()

	const century = 100 * 365 * 24 * time.Hour

	tests := []struct {
		name  string
		jumps []time.Duration
	}{
		{"one hour", []time.Duration{time.Hour}},
		{"one year", []time.Duration{365 * 24 * time.Hour}},
		{"a century", []time.Duration{century}},
		{"beyond the duration range", []time.Duration{century, century, century}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newClock()
			tr := New(2, time.Minute, 10, c.now)
			a, b := ip("10.0.0.1"), ip("10.0.0.2")

			tr.Hit(a)
			for _, d := range tc.jumps {
				c.add(d)
			}

			if count, trig := tr.Hit(a); count != 1 || trig {
				t.Fatalf("Hit after the jump = (%d, %v), want (1, false)", count, trig)
			}
			// And the tracker is still usable afterwards.
			c.add(time.Second)
			if count, trig := tr.Hit(a); count != 2 || !trig {
				t.Fatalf("Hit = (%d, %v), want (2, true)", count, trig)
			}
			tr.Hit(b)
			c.add(time.Hour)
			tr.Sweep()
			if got := tr.Len(); got != 0 {
				t.Fatalf("Len() = %d after sweeping post-jump entries, want 0", got)
			}
		})
	}
}

// TestEpochWrap exercises the ~136-year uint32 rollover. Ages are computed
// with wrapping subtraction, so a window that straddles the wrap is still
// measured correctly.
func TestEpochWrap(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(2, time.Minute, 10, c.now)
	a := ip("10.0.0.1")

	// Park the clock two seconds short of 2^32 seconds after the epoch.
	c.add(time.Duration(int64(1<<32-2)) * time.Second)
	if count, trig := tr.Hit(a); count != 1 || trig {
		t.Fatalf("Hit = (%d, %v), want (1, false)", count, trig)
	}
	if tr.cur != 1<<32-2 {
		t.Fatalf("tick = %d, want %d", tr.cur, uint32(1<<32-2))
	}

	c.add(3 * time.Second)
	if count, trig := tr.Hit(a); count != 2 || !trig {
		t.Fatalf("Hit across the wrap = (%d, %v), want (2, true)", count, trig)
	}
	if tr.cur != 1 {
		t.Fatalf("tick after wrap = %d, want 1", tr.cur)
	}

	// And an age that straddles the wrap but exceeds the window still expires.
	c.add(2 * time.Minute)
	if count, trig := tr.Hit(a); count != 1 || trig {
		t.Fatalf("Hit = (%d, %v), want (1, false)", count, trig)
	}
}

// TestSubSecondTicksAccumulate pins the sub-second remainder carried between
// calls: ten 100 ms steps must add up to one tick, not zero.
func TestSubSecondTicksAccumulate(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(2, time.Second, 10, c.now)
	a, b := ip("10.0.0.1"), ip("10.0.0.2")

	tr.Hit(a) // tick 0
	for i := 0; i < 10; i++ {
		c.add(100 * time.Millisecond)
		tr.Hit(b) // each call advances the clock by less than a tick
	}
	if tr.cur != 1 {
		t.Fatalf("tick = %d after 10x100ms, want 1", tr.cur)
	}
	// The first hit is now one tick old, which is inside a 1 s window.
	if count, trig := tr.Hit(a); count != 2 || !trig {
		t.Fatalf("Hit = (%d, %v), want (2, true)", count, trig)
	}

	for i := 0; i < 10; i++ {
		c.add(100 * time.Millisecond)
		tr.Hit(b)
	}
	if tr.cur != 2 {
		t.Fatalf("tick = %d after another 10x100ms, want 2", tr.cur)
	}
}

// TestRingWrap walks a ring buffer past its capacity many times to make sure
// head/n bookkeeping stays consistent.
func TestRingWrap(t *testing.T) {
	t.Parallel()

	const threshold = 4
	c := newClock()
	tr := New(threshold, 10*time.Second, 10, c.now)
	a := ip("10.0.0.1")

	for i := 1; i <= 200; i++ {
		c.add(time.Second)
		count, trig := tr.Hit(a)
		// One hit per second with a 10s window: every 4th hit triggers.
		wantCount := i % threshold
		if wantCount == 0 {
			wantCount = threshold
		}
		if count != wantCount || trig != (i%threshold == 0) {
			t.Fatalf("hit %d: (%d, %v), want (%d, %v)", i, count, trig, wantCount, i%threshold == 0)
		}
		if tr.ents[0].n >= threshold {
			t.Fatalf("hit %d: n = %d, must stay below threshold", i, tr.ents[0].n)
		}
		if tr.ents[0].head >= threshold {
			t.Fatalf("hit %d: head = %d out of range", i, tr.ents[0].head)
		}
	}
}

// TestLRUListIntegrity cross-checks the intrusive list against the map after a
// mixed workload; a broken link would silently leak or double-free slots.
//
// Phase one deliberately uses a working set *smaller* than maxTracked. That is
// the only way the relink-on-hit path runs while checkList is watching, and
// relink order is what Sweep's early stop depends on: with a larger set every
// hit is a miss, and dropping the LRU ordering key entirely goes unnoticed.
func TestLRUListIntegrity(t *testing.T) {
	t.Parallel()

	const maxTracked = 50

	phases := []struct {
		name string
		keys int // distinct addresses touched round-robin
	}{
		{"working set fits under the cap", 20},
		{"working set overflows the cap", 200},
	}

	for _, ph := range phases {
		t.Run(ph.name, func(t *testing.T) {
			t.Parallel()

			c := newClock()
			tr := New(3, 30*time.Second, maxTracked, c.now)
			for i := 0; i < 500; i++ {
				c.add(time.Second)
				tr.Hit(ip(fmt.Sprintf("10.0.%d.%d", i%ph.keys/256, i%ph.keys%256)))
				if i%17 == 0 {
					tr.Forget(ip(fmt.Sprintf("10.0.%d.%d", i%ph.keys/256, i%ph.keys%256)))
				}
				if i%29 == 0 {
					tr.Sweep()
				}
				checkList(t, tr)
			}
		})
	}
}

// TestLRUOrderFollowsLastHit is the narrow version of the above: re-hitting the
// oldest entry must move it to the front, which is precisely the property
// Sweep's early stop relies on.
func TestLRUOrderFollowsLastHit(t *testing.T) {
	t.Parallel()

	c := newClock()
	tr := New(5, time.Hour, 10, c.now)
	a, b, d := ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")

	tr.Hit(a)
	c.add(time.Second)
	tr.Hit(b)
	c.add(time.Second)
	tr.Hit(d)
	c.add(time.Second)
	tr.Hit(a) // a becomes the most recent, b the least

	if got := tr.ents[tr.mru].ip; got != a {
		t.Errorf("front of the LRU list is %v, want %v", got, a)
	}
	if got := tr.ents[tr.lru].ip; got != b {
		t.Errorf("tail of the LRU list is %v, want %v", got, b)
	}
	checkList(t, tr)

	// And the ordering key itself must have moved with it: Sweep drops the
	// tail up to the first live entry, so a must survive a sweep that takes b.
	tr2 := New(5, 10*time.Second, 10, c.now)
	tr2.Hit(a) // tick 0
	c.add(5 * time.Second)
	tr2.Hit(b) // tick 5
	c.add(5 * time.Second)
	tr2.Hit(a) // tick 10: refreshes a's last-hit tick
	c.add(6 * time.Second)

	tr2.Sweep() // tick 16: b is 11s old (stale), a is 6s old (live)
	if got := tr2.Len(); got != 1 {
		t.Fatalf("Len() = %d after sweep, want 1", got)
	}
	if _, ok := tr2.index[b]; ok {
		t.Error("stale entry survived Sweep")
	}
	if _, ok := tr2.index[a]; !ok {
		t.Error("recently re-hit entry was swept: its last-hit tick did not move")
	}
}

// checkList verifies that the LRU list contains exactly the live entries, in
// non-increasing last-hit order, and is consistent in both directions.
func checkList(t *testing.T, tr *Tracker) {
	t.Helper()

	seen := 0
	prev := nilIdx
	var lastTick uint32
	for i := tr.mru; i != nilIdx; i = tr.ents[i].next {
		if tr.ents[i].prev != prev {
			t.Fatalf("entry %d: prev = %d, want %d", i, tr.ents[i].prev, prev)
		}
		if j, ok := tr.index[tr.ents[i].ip]; !ok || j != i {
			t.Fatalf("entry %d (%v) is linked but not indexed", i, tr.ents[i].ip)
		}
		if seen > 0 && tr.ents[i].last > lastTick {
			t.Fatalf("entry %d breaks LRU ordering: last %d after %d", i, tr.ents[i].last, lastTick)
		}
		lastTick = tr.ents[i].last
		prev = i
		seen++
		if seen > len(tr.ents) {
			t.Fatal("cycle in the LRU list")
		}
	}
	if prev != tr.lru {
		t.Fatalf("tail = %d, want %d", tr.lru, prev)
	}
	if seen != tr.live || seen != len(tr.index) {
		t.Fatalf("list has %d entries, live = %d, index = %d", seen, tr.live, len(tr.index))
	}
}
