package window

import (
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

type aclock struct{ t time.Time }

func (c *aclock) now() time.Time      { return c.t }
func (c *aclock) add(d time.Duration) { c.t = c.t.Add(d) }

var aBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newAClock() *aclock { return &aclock{t: aBase} }

func addr4(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

func fullInvariants(t *testing.T, tr *Tracker, ctx string) {
	t.Helper()
	seen := map[int32]bool{}
	var prev int32 = nilIdx
	var lastTick uint32
	n := 0
	for i := tr.mru; i != nilIdx; i = tr.ents[i].next {
		if seen[i] {
			t.Fatalf("%s: cycle in LRU at slot %d", ctx, i)
		}
		seen[i] = true
		if tr.ents[i].prev != prev {
			t.Fatalf("%s: slot %d prev=%d want %d", ctx, i, tr.ents[i].prev, prev)
		}
		if j, ok := tr.index[tr.ents[i].ip]; !ok || j != i {
			t.Fatalf("%s: slot %d (%v) linked but index says %d/%v", ctx, i, tr.ents[i].ip, j, ok)
		}
		if n > 0 && tr.ents[i].last > lastTick {
			t.Fatalf("%s: LRU ORDER BROKEN at slot %d: last=%d after %d", ctx, i, tr.ents[i].last, lastTick)
		}
		lastTick = tr.ents[i].last
		prev = i
		n++
		if n > len(tr.ents)+1 {
			t.Fatalf("%s: runaway list", ctx)
		}
	}
	if prev != tr.lru {
		t.Fatalf("%s: tail=%d want %d", ctx, tr.lru, prev)
	}
	if n != tr.live || n != len(tr.index) {
		t.Fatalf("%s: list=%d live=%d index=%d", ctx, n, tr.live, len(tr.index))
	}
	freeSeen := map[int32]bool{}
	nf := 0
	for i := tr.free; i != nilIdx; i = tr.ents[i].next {
		if freeSeen[i] {
			t.Fatalf("%s: cycle in free list at %d", ctx, i)
		}
		if seen[i] {
			t.Fatalf("%s: slot %d is BOTH live and free", ctx, i)
		}
		freeSeen[i] = true
		nf++
		if nf > len(tr.ents)+1 {
			t.Fatalf("%s: runaway free list", ctx)
		}
	}
	if n+nf != len(tr.ents) {
		t.Fatalf("%s: slot accounting: live=%d free=%d slab=%d", ctx, n, nf, len(tr.ents))
	}
	if len(tr.ticks) != len(tr.ents)*int(tr.threshold) {
		t.Fatalf("%s: ticks len=%d want %d", ctx, len(tr.ticks), len(tr.ents)*int(tr.threshold))
	}
}

// ===== B1: inclusive boundary =====

func TestAudit_BoundaryInclusiveBothSides(t *testing.T) {
	for _, age := range []time.Duration{9, 10, 11} {
		c := newAClock()
		tr := New(2, 10*time.Second, 10, c.now)
		a := addr4(1)
		tr.Hit(a)
		c.add(age * time.Second)
		count, trig := tr.Hit(a)
		want := age <= 10
		if trig != want {
			t.Errorf("age=%ds: trig=%v count=%d, want trig=%v", age, trig, count, want)
		}
	}
}

func TestAudit_OriginalRepros(t *testing.T) {
	cases := []struct {
		window, offset, gap time.Duration
	}{
		{time.Second, 990 * time.Millisecond, 20 * time.Millisecond},
		{10 * time.Second, 900 * time.Millisecond, 9200 * time.Millisecond},
	}
	for _, tc := range cases {
		c := newAClock()
		tr := New(2, tc.window, 10, c.now)
		c.add(tc.offset)
		a := addr4(1)
		tr.Hit(a)
		c.add(tc.gap)
		if count, trig := tr.Hit(a); !trig {
			t.Errorf("window=%v gap=%v: (%d,%v), want trigger", tc.window, tc.gap, count, trig)
		}
	}
}

// TestAudit_HitSweepAgree: for every window and every age, Hit's notion of
// "still live" must match Sweep's. A disagreement either sweeps an entry Hit
// still counts, or keeps one Hit has already discarded.
func TestAudit_HitSweepAgree(t *testing.T) {
	for w := 1; w <= 5; w++ {
		for age := 0; age <= w+2; age++ {
			// Hit's view: does the old tick still count?
			c1 := newAClock()
			h := New(2, time.Duration(w)*time.Second, 10, c1.now)
			a := addr4(1)
			h.Hit(a)
			c1.add(time.Duration(age) * time.Second)
			_, hitLive := h.Hit(a) // triggers iff the old tick is still in window

			// Sweep's view: is the entry kept?
			c2 := newAClock()
			s := New(2, time.Duration(w)*time.Second, 10, c2.now)
			s.Hit(a)
			c2.add(time.Duration(age) * time.Second)
			s.Sweep()
			_, sweepLive := s.index[a]

			if hitLive != sweepLive {
				t.Errorf("window=%ds age=%ds: Hit says live=%v but Sweep says live=%v",
					w, age, hitLive, sweepLive)
			}
			if want := age <= w; hitLive != want {
				t.Errorf("window=%ds age=%ds: Hit live=%v, want %v (inclusive)", w, age, hitLive, want)
			}
		}
	}
}

// ===== B2: clamps =====

func TestAudit_NoPanicOnHugeThreshold(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PANIC: %v", r)
		}
	}()
	for _, th := range []int{1 << 32, 1<<32 + 7, 1<<32 + 1, 1 << 40, 1<<62 + 3, -1, 0, 1} {
		tr := New(th, time.Hour, 4, nil)
		trig := 0
		for i := 0; i < 50; i++ {
			if _, tg := tr.Hit(addr4(i % 3)); tg {
				trig++
			}
		}
		t.Logf("threshold %d -> internal %d, %d triggers in 50 hits", th, tr.threshold, trig)
		if th > 1<<20 && trig > 0 {
			t.Errorf("threshold %d truncated: triggered %d times", th, trig)
		}
	}
}

func TestAudit_WindowClamp(t *testing.T) {
	for _, w := range []time.Duration{
		time.Duration(1<<32) * time.Second,
		time.Duration(1<<33) * time.Second,
		1<<62 - 1,
	} {
		c := newAClock()
		tr := New(2, w, 10, c.now)
		a := addr4(1)
		tr.Hit(a)
		c.add(24 * time.Hour)
		if _, trig := tr.Hit(a); !trig {
			t.Errorf("window=%v (windowSecs=%d): a day-old hit expired; banning disabled", w, tr.windowSecs)
		}
	}
}

// ===== the rewritten tick() =====

// TestAudit_TickNeverDriftsForwardOnly: for a forward-only clock the tick must
// equal floor(elapsed) exactly, no matter how the elapsed time is chopped up.
func TestAudit_TickNeverDriftsForwardOnly(t *testing.T) {
	for _, seed := range []int64{1, 9, 77} {
		rng := rand.New(rand.NewSource(seed))
		c := newAClock()
		tr := New(2, time.Hour, 10, c.now)
		var total time.Duration
		for i := 0; i < 20000; i++ {
			d := time.Duration(rng.Intn(3_000_000_000)) // 0..3s, ns resolution
			c.add(d)
			total += d
			got := tr.tick()
			want := uint32(total / time.Second)
			if got != want {
				t.Fatalf("seed %d step %d: tick=%d want %d (total=%v, frac=%v)",
					seed, i, got, want, total, tr.frac)
			}
		}
	}
}

func TestAudit_TickSubSecondCarry(t *testing.T) {
	cases := []struct {
		name  string
		step  time.Duration
		n     int
		wantT uint32
	}{
		{"10x100ms", 100 * time.Millisecond, 10, 1},
		{"1000x1ms", time.Millisecond, 1000, 1},
		{"1000000x1us", time.Microsecond, 1_000_000, 1},
		{"3x700ms", 700 * time.Millisecond, 3, 2},
		{"7x700ms", 700 * time.Millisecond, 7, 4},
		{"100x999ms", 999 * time.Millisecond, 100, 99},
		{"9x100ms (no carry yet)", 100 * time.Millisecond, 9, 0},
		{"1x1ns", time.Nanosecond, 1, 0},
	}
	for _, tc := range cases {
		c := newAClock()
		tr := New(2, time.Hour, 10, c.now)
		for i := 0; i < tc.n; i++ {
			c.add(tc.step)
			tr.tick()
		}
		if got := tr.tick(); got != tc.wantT {
			t.Errorf("%s: tick=%d want %d (frac=%v)", tc.name, got, tc.wantT, tr.frac)
		}
		if tr.frac < 0 || tr.frac >= time.Second {
			t.Errorf("%s: frac=%v out of [0,1s)", tc.name, tr.frac)
		}
	}
}

// TestAudit_TickCallFrequencyIndependent: sparse and frequent callers must see
// the same tick for the same wall time. Accumulate-since-last-call could
// plausibly differ from recompute-from-epoch here.
func TestAudit_TickCallFrequencyIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	steps := make([]time.Duration, 500)
	for i := range steps {
		steps[i] = time.Duration(rng.Intn(1_500_000_000))
	}

	cDense := newAClock()
	dense := New(2, time.Hour, 10, cDense.now)
	cSparse := newAClock()
	sparse := New(2, time.Hour, 10, cSparse.now)

	for i, d := range steps {
		cDense.add(d)
		dense.tick()
		cSparse.add(d)
		if i%37 == 0 { // only occasionally
			sparse.tick()
		}
	}
	if d, s := dense.tick(), sparse.tick(); d != s {
		t.Errorf("dense caller sees tick %d, sparse caller sees %d for the same wall time", d, s)
	}
}

// TestAudit_TickIdleThenHit: hours of idleness then a single call.
func TestAudit_TickIdleThenHit(t *testing.T) {
	c := newAClock()
	tr := New(3, 10*time.Minute, 10, c.now)
	a := addr4(1)
	tr.Hit(a)
	tr.Hit(a) // count 2
	c.add(6 * time.Hour)
	if count, trig := tr.Hit(a); count != 1 || trig {
		t.Errorf("after 6h idle: (%d,%v), want (1,false)", count, trig)
	}
	if got, want := tr.tick(), uint32(6*3600); got != want {
		t.Errorf("tick=%d after 6h idle, want %d", got, want)
	}
	c.add(time.Hour)
	tr.Sweep()
	if tr.Len() != 0 {
		t.Errorf("Len=%d after idling past the window", tr.Len())
	}
}

// TestAudit_TickJitter: tiny backwards-then-forwards oscillation must not
// stall the tick or make it go backwards, and must not drift without bound.
func TestAudit_TickJitter(t *testing.T) {
	c := newAClock()
	tr := New(2, time.Hour, 10, c.now)
	prev := tr.tick()
	for i := 0; i < 100_000; i++ {
		c.add(-50 * time.Millisecond)
		got := tr.tick()
		if got < prev {
			t.Fatalf("iter %d: tick went backwards %d -> %d", i, prev, got)
		}
		prev = got
		c.add(60 * time.Millisecond) // net +10ms per iteration
		got = tr.tick()
		if got < prev {
			t.Fatalf("iter %d: tick went backwards %d -> %d", i, prev, got)
		}
		prev = got
	}
	realElapsed := c.t.Sub(aBase)
	t.Logf("wall elapsed %v, tick %d s (drift = %+d s from wall)",
		realElapsed, prev, int64(prev)-int64(realElapsed/time.Second))
	if prev == 0 {
		t.Error("tick stalled permanently under jitter")
	}
}

func TestAudit_TickMonotonicUnderPathologies(t *testing.T) {
	c := newAClock()
	tr := New(2, time.Minute, 10, c.now)
	rng := rand.New(rand.NewSource(3))
	prev := tr.tick()
	for i := 0; i < 50_000; i++ {
		switch rng.Intn(6) {
		case 0:
			c.add(-time.Duration(rng.Int63n(int64(100 * 365 * 24 * time.Hour))))
		case 1:
			c.add(time.Duration(rng.Int63n(int64(100 * 365 * 24 * time.Hour))))
		case 2:
			c.t = aBase // reset to the start
		default:
			c.add(time.Duration(rng.Intn(5_000_000_000)))
		}
		got := tr.tick()
		// Wrapping is legal; a decrease that is not a wrap is not.
		if got < prev && uint32(prev-got) < 1<<31 {
			t.Fatalf("iter %d: tick went backwards %d -> %d", i, prev, got)
		}
		prev = got
	}
}

// TestAudit_TickWrapWithAccumulation crosses the uint32 rollover in
// sub-second steps, which the accumulating implementation must handle.
func TestAudit_TickWrapWithAccumulation(t *testing.T) {
	c := newAClock()
	tr := New(2, time.Minute, 10, c.now)
	a := addr4(1)
	c.add(time.Duration(int64(1<<32-2)) * time.Second)
	if got := tr.tick(); got != 1<<32-2 {
		t.Fatalf("tick=%d want %d", got, uint32(1<<32-2))
	}
	tr.Hit(a) // stored at 2^32-2
	for i := 0; i < 25; i++ {
		c.add(100 * time.Millisecond) // 2.5s total, crossing the wrap
		tr.tick()
	}
	if got := tr.tick(); got != 0 {
		t.Fatalf("tick after crossing the wrap = %d, want 0", got)
	}
	if count, trig := tr.Hit(a); count != 2 || !trig {
		t.Fatalf("Hit across the wrap = (%d,%v), want (2,true)", count, trig)
	}
	c.add(2 * time.Minute)
	if count, trig := tr.Hit(a); count != 1 || trig {
		t.Fatalf("Hit after the window = (%d,%v), want (1,false)", count, trig)
	}
}

// ===== structural re-verification =====

func TestAudit_SweepOrderFuzz(t *testing.T) {
	for _, seed := range []int64{1, 2, 3, 42, 1234567} {
		seed := seed
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			c := newAClock()
			maxTracked := 1 + rng.Intn(40)
			threshold := 1 + rng.Intn(5)
			tr := New(threshold, time.Duration(1+rng.Intn(30))*time.Second, maxTracked, c.now)
			for step := 0; step < 4000; step++ {
				switch rng.Intn(10) {
				case 0:
					tr.Forget(addr4(rng.Intn(60)))
				case 1:
					tr.Sweep()
				case 2:
					c.add(-time.Duration(rng.Intn(5000)) * time.Millisecond)
					tr.Hit(addr4(rng.Intn(60)))
				default:
					c.add(time.Duration(rng.Intn(3000)) * time.Millisecond)
					tr.Hit(addr4(rng.Intn(60)))
				}
				if tr.Len() > maxTracked {
					t.Fatalf("step %d: Len()=%d > maxTracked=%d", step, tr.Len(), maxTracked)
				}
				fullInvariants(t, tr, fmt.Sprintf("seed %d step %d", seed, step))
			}
			c.add(time.Hour)
			for i := 0; i < 100 && tr.Len() > 0; i++ {
				tr.Sweep()
			}
			if tr.Len() != 0 {
				t.Fatalf("Sweep leaked %d entries", tr.Len())
			}
		})
	}
}

func TestAudit_LRUScale(t *testing.T) {
	const maxTracked = 997
	const total = 200_000
	c := newAClock()
	tr := New(3, time.Hour, maxTracked, c.now)
	for i := 0; i < total; i++ {
		if i%100 == 0 {
			c.add(time.Second)
		}
		tr.Hit(addr4(i))
		if tr.Len() > maxTracked {
			t.Fatalf("i=%d Len()=%d > %d", i, tr.Len(), maxTracked)
		}
	}
	if tr.Len() != maxTracked || len(tr.ents) != maxTracked {
		t.Fatalf("Len=%d slab=%d want %d", tr.Len(), len(tr.ents), maxTracked)
	}
	for i := total - maxTracked; i < total; i++ {
		if _, ok := tr.index[addr4(i)]; !ok {
			t.Fatalf("recent addr %v evicted", addr4(i))
		}
	}
	fullInvariants(t, tr, "lru scale")
}

func TestAudit_NoHang(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		rng := rand.New(rand.NewSource(7))
		c := newAClock()
		tr := New(4, 20*time.Second, 64, c.now)
		for i := 0; i < 500_000; i++ {
			c.add(time.Duration(rng.Intn(2000)) * time.Millisecond)
			tr.Hit(addr4(rng.Intn(200)))
			if rng.Intn(11) == 0 {
				tr.Forget(addr4(rng.Intn(200)))
			}
			if rng.Intn(53) == 0 {
				tr.Sweep()
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("churn loop hung: likely a corrupt LRU/free link")
	}
}

func TestAudit_Allocs(t *testing.T) {
	c := newAClock()
	warm := New(5, 10*time.Minute, 1000, c.now)
	a := addr4(1)
	warm.Hit(a)
	if got := testing.AllocsPerRun(2000, func() { warm.Hit(a) }); got != 0 {
		t.Errorf("warm Hit allocates %v/op", got)
	}

	capped := New(5, 10*time.Minute, 512, c.now)
	for i := 0; i < 512; i++ {
		capped.Hit(addr4(i))
	}
	i := 1_000_000
	if got := testing.AllocsPerRun(2000, func() { i++; capped.Hit(addr4(i)) }); got != 0 {
		t.Errorf("cold-capped Hit allocates %v/op", got)
	}
	if got := testing.AllocsPerRun(500, func() { capped.Sweep() }); got != 0 {
		t.Errorf("Sweep allocates %v/op", got)
	}
	if got := testing.AllocsPerRun(500, func() { capped.Forget(a) }); got != 0 {
		t.Errorf("Forget allocates %v/op", got)
	}
}

func TestAudit_MemoryFlat(t *testing.T) {
	const threshold = 5
	c := newAClock()
	tr := New(threshold, time.Hour, 100_000, c.now)
	a := addr4(77)
	var m0, m1 runtime.MemStats
	tr.Hit(a)
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for i := 0; i < 1_000_000; i++ {
		if i%1000 == 0 {
			c.add(time.Second)
		}
		tr.Hit(a)
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(tr)
	t.Logf("heap delta over 1M hits on one IP: %d B; slab=%d ents, ticks=%d words",
		int64(m1.HeapAlloc)-int64(m0.HeapAlloc), len(tr.ents), len(tr.ticks))
	if len(tr.ents) != 1 || len(tr.ticks) != threshold || tr.Len() != 1 {
		t.Errorf("footprint grew with hit volume")
	}
}

func TestAudit_OddAddresses(t *testing.T) {
	c := newAClock()
	tr := New(2, time.Minute, 10, c.now)
	var zero netip.Addr
	if c1, _ := tr.Hit(zero); c1 != 1 {
		t.Errorf("zero Addr count=%d", c1)
	}
	if c2, trig := tr.Hit(zero); c2 != 2 || !trig {
		t.Errorf("zero Addr second hit = (%d,%v)", c2, trig)
	}
	tr.Hit(netip.MustParseAddr("1.2.3.4"))
	tr.Hit(netip.MustParseAddr("::ffff:1.2.3.4"))
	tr.Hit(netip.MustParseAddr("fe80::1%eth0"))
	tr.Hit(netip.MustParseAddr("fe80::1%eth1"))
	fullInvariants(t, tr, "odd addrs")
}

func TestAudit_TriggerResetExactCount(t *testing.T) {
	for _, threshold := range []int{1, 2, 3, 8, 255, 256, 1000} {
		c := newAClock()
		tr := New(threshold, time.Hour, 10, c.now)
		a := addr4(1)
		for i := 1; i <= threshold*3; i++ {
			count, trig := tr.Hit(a)
			wantTrig := i%threshold == 0
			wantCount := i % threshold
			if wantCount == 0 {
				wantCount = threshold
			}
			if trig != wantTrig || count != wantCount {
				t.Fatalf("threshold=%d hit %d: (%d,%v) want (%d,%v)", threshold, i, count, trig, wantCount, wantTrig)
			}
		}
	}
}

func TestAudit_SweepBudget(t *testing.T) {
	c := newAClock()
	tr := New(2, 10*time.Second, 0, c.now)
	for i := 0; i < 20000; i++ {
		tr.Hit(addr4(i))
	}
	c.add(time.Hour)
	before := tr.Len()
	tr.Sweep()
	if dropped := before - tr.Len(); dropped != 2500 {
		t.Errorf("dropped %d of 20000, want 2500", dropped)
	}
}
