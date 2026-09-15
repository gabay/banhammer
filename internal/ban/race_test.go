package ban

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

// TestConcurrentAccess models the real caller topology: Offend from the
// aggregator goroutine, Ban/Unban/Snapshot/Stats from the control socket, and
// Run draining expiries — all at once, under -race.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{
		Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour,
		Factor: 2, OnRepeat: OnRepeatExtend,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- m.Run(ctx) }()

	const iterations = 400
	var wg sync.WaitGroup

	// Aggregator: a small address space so offenses collide and extend.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range iterations {
			m.Offend("sshd", netip.AddrFrom4([4]byte{10, 0, 0, byte(i % 16)}), i%7+1)
		}
	}()

	// Control socket: snapshots must never observe torn state.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			for _, b := range m.Snapshot() {
				if !b.IP.IsValid() || b.Until.Before(b.At) {
					t.Errorf("torn ban observed: %+v", b)
					return
				}
			}
			_ = m.Stats()
		}
	}()

	// Control socket: manual bans and unbans over an overlapping range.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range iterations {
			ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i % 24)})
			if err := m.Ban(ip, "manual", time.Duration(i%5+1)*time.Minute); err != nil {
				t.Errorf("Ban: %v", err)
				return
			}
			if err := m.Unban(ip); err != nil && !errors.Is(err, ErrNotBanned) {
				t.Errorf("Unban: %v", err)
				return
			}
		}
	}()

	// Time marches on underneath all of it.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			advance(clk, m, 2*time.Second)
		}
	}()

	// A concurrent restore, as a reload might do.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			_ = m.Restore([]model.Ban{{
				IP:      netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}),
				Monitor: "sshd",
				At:      clk.Now(),
				Until:   clk.Now().Add(time.Duration(i) * time.Minute),
				Offense: 1,
			}})
		}
	}()

	wg.Wait()
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// Internal invariant: every ban has exactly one heap entry and vice versa.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sched.Len() != len(m.bans) {
		t.Errorf("heap has %d entries for %d bans", m.sched.Len(), len(m.bans))
	}
	if len(m.sched.index) != m.sched.Len() {
		t.Errorf("heap index has %d entries for %d items", len(m.sched.index), m.sched.Len())
	}
	for ip, b := range m.bans {
		e, ok := m.sched.index[ip]
		if !ok {
			t.Errorf("ban %v has no scheduled unban", ip)
			continue
		}
		if !e.until.Equal(b.Until) {
			t.Errorf("ban %v scheduled for %v, want %v", ip, e.until, b.Until)
		}
	}
}

// BenchmarkOffendExisting measures the hot path taken by a persistent attacker
// whose ban is already live (the common case during a flood). It uses an
// Info-level logger because that is the production default; at debug level the
// per-offense argument boxing adds a handful of allocations.
func BenchmarkOffendExisting(b *testing.B) {
	clk := newFakeClock()
	m := NewManager(Options{
		Now:      clk.Now,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		NewTimer: clk.NewTimer,
	})
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, FindHistory: 24 * time.Hour, Factor: 1})
	ip := netip.MustParseAddr("198.51.100.1")
	m.Offend("sshd", ip, 5)

	b.ReportAllocs()
	for range b.N {
		m.Offend("sshd", ip, 5)
	}
}
