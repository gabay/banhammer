package window

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// addrs builds n distinct IPv4 addresses without allocating during the
// benchmark loop itself.
func addrs(n int) []netip.Addr {
	out := make([]netip.Addr, n)
	var b [4]byte
	for i := range out {
		binary.BigEndian.PutUint32(b[:], 0x0a000000|uint32(i))
		out[i] = netip.AddrFrom4(b)
	}
	return out
}

// BenchmarkHitWarm is the dominant production path: an address already tracked,
// hit again. It must not allocate.
func BenchmarkHitWarm(b *testing.B) {
	c := newClock()
	tr := New(5, 10*time.Minute, 100_000, c.now)
	a := netip.MustParseAddr("198.51.100.1")
	tr.Hit(a)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Hit(a)
	}
}

// BenchmarkHitWarmSpread hits a working set large enough to miss cache, which
// is closer to a busy multi-source host than a single hot key.
func BenchmarkHitWarmSpread(b *testing.B) {
	const n = 10_000
	c := newClock()
	tr := New(5, 10*time.Minute, 100_000, c.now)
	as := addrs(n)
	for _, a := range as {
		tr.Hit(a)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Hit(as[i%n])
	}
}

// BenchmarkHitCold measures first-sight inserts, including slab growth.
func BenchmarkHitCold(b *testing.B) {
	as := addrs(b.N)
	c := newClock()
	tr := New(5, 10*time.Minute, 0, c.now)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Hit(as[i])
	}
}

// BenchmarkHitColdCapped is the DoS shape: every line is a new address and the
// LRU cap is saturated, so each insert also evicts.
func BenchmarkHitColdCapped(b *testing.B) {
	as := addrs(b.N)
	c := newClock()
	tr := New(5, 10*time.Minute, 1000, c.now)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Hit(as[i])
	}
}

// BenchmarkMemoryPerIP reports the steady-state heap cost of one tracked
// address, to be compared with the ~80 B/IP budget in PROJECT.md §4.4.
//
// The delta is computed in int64: HeapAlloc is a live-heap gauge, not a
// counter, so a GC that frees more than this run allocated makes the
// difference negative, and an unsigned subtraction would print ~1.8e19 B/IP.
func BenchmarkMemoryPerIP(b *testing.B) {
	const n = 100_000
	as := addrs(n)

	var total int64
	for i := 0; i < b.N; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		c := newClock()
		tr := New(5, 10*time.Minute, n, c.now)
		for _, a := range as {
			tr.Hit(a)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(tr)

		total += int64(after.HeapAlloc) - int64(before.HeapAlloc)
	}

	b.ReportMetric(float64(total)/float64(int64(b.N)*n), "B/IP")
	b.ReportMetric(0, "ns/op") // timing here is dominated by the two GCs
}
