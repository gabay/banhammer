package ban

import (
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

// epoch is an arbitrary fixed wall time; every test clock starts here so
// assertions can name absolute instants.
var epoch = time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

// fakeClock is a manually driven clock plus the timers it hands out. One mutex
// covers both so that Advance and a concurrent Now/Reset from the Run loop
// cannot observe a torn state.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock() *fakeClock { return &fakeClock{now: epoch} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer satisfies Options.NewTimer.
func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, ch: make(chan time.Time, 1), deadline: c.now.Add(d), active: true}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock and fires every timer that is now due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if t.active && !t.deadline.After(c.now) {
			t.active = false
			select {
			case t.ch <- c.now:
			default:
			}
		}
	}
}

// armed reports the wait most recently programmed into the single timer.
func (c *fakeClock) armed() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 {
		return 0, false
	}
	t := c.timers[len(c.timers)-1]
	return t.wait, true
}

type fakeTimer struct {
	clock    *fakeClock
	ch       chan time.Time
	deadline time.Time
	wait     time.Duration
	active   bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.wait = d
	t.deadline = t.clock.now.Add(d)
	t.active = true
	select { // Go 1.23+ semantics: Reset discards a pending fire.
	case <-t.ch:
	default:
	}
	return was
}

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.active = false
	select {
	case <-t.ch:
	default:
	}
	return was
}

// advance moves the clock and then nudges the manager.
//
// The nudge is not papering over a bug: with a frozen clock there is an
// unavoidable interleaving where Run computes a wait from the pre-Advance
// "now" and arms the timer after Advance, so nothing would ever fire again.
// A real clock keeps moving and fires slightly late instead. Tests that must
// prove the timer itself is armed correctly assert on fakeClock.armed() or
// call expireAndSchedule directly, so this helper does not hide a regression.
func advance(c *fakeClock, m *Manager, d time.Duration) {
	c.Advance(d)
	m.signal()
}

// fakeEnforcer records firewall calls and republishes them on channels so a
// test can block on an event instead of sleeping.
type fakeEnforcer struct {
	mu      sync.Mutex
	bans    []model.Ban
	unbans  []model.Ban
	banCh   chan model.Ban
	unbanCh chan model.Ban
}

func newFakeEnforcer() *fakeEnforcer {
	return &fakeEnforcer{
		banCh:   make(chan model.Ban, 1<<14),
		unbanCh: make(chan model.Ban, 1<<14),
	}
}

func (f *fakeEnforcer) Ban(b model.Ban) {
	f.mu.Lock()
	f.bans = append(f.bans, b)
	f.mu.Unlock()
	select {
	case f.banCh <- b:
	default:
	}
}

func (f *fakeEnforcer) Unban(b model.Ban) {
	f.mu.Lock()
	f.unbans = append(f.unbans, b)
	f.mu.Unlock()
	select {
	case f.unbanCh <- b:
	default:
	}
}

func (f *fakeEnforcer) banned() []model.Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.Ban(nil), f.bans...)
}

func (f *fakeEnforcer) unbanned() []model.Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.Ban(nil), f.unbans...)
}

// waitUnban blocks for the next unban. The timeout is a test-failure backstop,
// never part of the logic under test.
func (f *fakeEnforcer) waitUnban(t *testing.T) model.Ban {
	t.Helper()
	select {
	case b := <-f.unbanCh:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an unban")
		return model.Ban{}
	}
}

type fakePersister struct {
	mu    sync.Mutex
	saves [][]model.Ban
	err   error
}

func (p *fakePersister) SaveBans(b []model.Ban) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves = append(p.saves, b)
	return p.err
}

func (p *fakePersister) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.saves)
}

func (p *fakePersister) last() []model.Ban {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.saves) == 0 {
		return nil
	}
	return p.saves[len(p.saves)-1]
}

func (p *fakePersister) setErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newTestManager wires a manager to a fake clock, enforcer and persister, with
// no allowlist and no local exemptions unless the caller overrides them.
func newTestManager(t *testing.T, mutate func(*Options)) (*Manager, *fakeClock, *fakeEnforcer, *fakePersister) {
	t.Helper()
	clk := newFakeClock()
	fe := newFakeEnforcer()
	fp := &fakePersister{}
	o := Options{
		Enforcer:   fe,
		Persister:  fp,
		Now:        clk.Now,
		Log:        discardLogger(),
		NewTimer:   clk.NewTimer,
		Interfaces: func() ([]netip.Prefix, error) { return nil, nil },
	}
	if mutate != nil {
		mutate(&o)
	}
	return NewManager(o), clk, fe, fp
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func prefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}
