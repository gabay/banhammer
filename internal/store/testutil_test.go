package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

// fakeClock is a manually driven clock so debounce logic is tested without
// any real sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeTimer records a scheduled callback that only runs when a test fires it.
type fakeTimer struct {
	sched   *fakeScheduler
	delay   time.Duration
	fn      func()
	stopped bool
	fired   bool
}

func (t *fakeTimer) Stop() bool {
	t.sched.mu.Lock()
	defer t.sched.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	return true
}

type fakeScheduler struct {
	mu      sync.Mutex
	timers  []*fakeTimer
	stopped int
}

func (s *fakeScheduler) AfterFunc(d time.Duration, f func()) Stopper {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &fakeTimer{sched: s, delay: d, fn: f}
	s.timers = append(s.timers, t)
	return t
}

// fireAll runs every scheduled-but-not-yet-run callback, in order. Callbacks
// may schedule new timers; those are left for the next fireAll.
func (s *fakeScheduler) fireAll() int {
	s.mu.Lock()
	due := make([]*fakeTimer, 0, len(s.timers))
	for _, t := range s.timers {
		if !t.stopped && !t.fired {
			t.fired = true
			due = append(due, t)
		}
	}
	s.mu.Unlock()
	for _, t := range due {
		t.fn() // outside the lock: the callback takes the store's mutex
	}
	return len(due)
}

// lastDelay returns the delay of the most recently scheduled timer.
func (s *fakeScheduler) lastDelay(t *testing.T) time.Duration {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.timers) == 0 {
		t.Fatal("no timer was scheduled")
	}
	return s.timers[len(s.timers)-1].delay
}

func (s *fakeScheduler) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.timers)
}

// writeRecorder wraps the Store's atomic-write seam so tests can count writes
// and inject I/O failures such as a full disk.
type writeRecorder struct {
	mu     sync.Mutex
	inner  func(dir, base string, data []byte) error
	writes []recordedWrite
	fail   error
}

type recordedWrite struct {
	base string
	data []byte
}

func (w *writeRecorder) write(dir, base string, data []byte) error {
	w.mu.Lock()
	w.writes = append(w.writes, recordedWrite{base: base, data: append([]byte(nil), data...)})
	failure := w.fail
	w.mu.Unlock()
	if failure != nil {
		return failure
	}
	return w.inner(dir, base, data)
}

func (w *writeRecorder) setFail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fail = err
}

func (w *writeRecorder) countFor(base string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, r := range w.writes {
		if r.base == base {
			n++
		}
	}
	return n
}

// discardLogger keeps test output clean while still exercising the logging
// paths (corruption reports are logged at Error level).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// logCapture records what the store logged. Several of the store's contracts
// are about log *volume* — one line per corrupt file, not per bad entry; one
// warning per checkpoint clash, not one every five seconds — and those can
// only be asserted by looking at the records.
type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) logger() *slog.Logger { return slog.New(c) }

// withMessage returns every record whose message is exactly msg.
func (c *logCapture) withMessage(msg string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range c.records {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

func (c *logCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = nil
}

// attr returns the value logged under key, or nil.
func attr(r slog.Record, key string) any {
	var found any
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found = a.Value.Any()
			return false
		}
		return true
	})
	return found
}

// newTestStore opens a store on dir with a fake clock and scheduler, and
// returns it along with the write recorder. Tests that need different
// behaviour (a longer interval, a real timer, a capturing logger) pass an
// override instead of hand-rolling their own OpenWith.
func newTestStore(t *testing.T, dir string, override ...func(*Options)) (*Store, *fakeClock, *fakeScheduler, *writeRecorder) {
	t.Helper()
	clk := newFakeClock()
	sched := &fakeScheduler{}
	o := Options{
		Log:       discardLogger(),
		Now:       clk.Now,
		AfterFunc: sched.AfterFunc,
	}
	for _, f := range override {
		f(&o)
	}
	s, err := OpenWith(dir, o)
	if err != nil {
		t.Fatalf("OpenWith(%q): %v", dir, err)
	}
	rec := &writeRecorder{inner: s.writeFile}
	s.writeFile = rec.write
	t.Cleanup(func() {
		// Clear any injected failure so a test that exercised a full disk
		// still closes cleanly and releases the lock.
		rec.setFail(nil)
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return s, clk, sched, rec
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func sampleBans(t *testing.T) []model.Ban {
	t.Helper()
	at := time.Date(2024, 2, 29, 23, 59, 58, 123456789, time.FixedZone("IST", 2*3600))
	return []model.Ban{
		{IP: mustAddr(t, "1.2.3.4"), Monitor: "sshd", At: at, Until: at.Add(time.Hour), Count: 5, Offense: 1},
		{IP: mustAddr(t, "2001:db8::dead:beef"), Monitor: "nginx", At: at.UTC(), Until: at.UTC().Add(48 * time.Hour), Count: 12, Offense: 3},
		{IP: mustAddr(t, "::ffff:10.0.0.9"), Monitor: "postfix", At: at, Until: at.Add(time.Minute), Count: 1, Offense: 1},
	}
}

func assertBansEqual(t *testing.T, got, want []model.Ban) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d bans, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.IP != w.IP || g.Monitor != w.Monitor || g.Count != w.Count || g.Offense != w.Offense {
			t.Errorf("ban %d = %+v, want %+v", i, g, w)
		}
		assertTimeEqual(t, fmt.Sprintf("ban %d At", i), g.At, w.At)
		assertTimeEqual(t, fmt.Sprintf("ban %d Until", i), g.Until, w.Until)
	}
}

func assertTimeEqual(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
	if got.Format(time.RFC3339Nano) != want.Format(time.RFC3339Nano) {
		t.Errorf("%s zone offset lost: %s vs %s", what,
			got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// assertQuarantined checks the evidence was preserved, not deleted.
func assertQuarantined(t *testing.T, dir, base, want string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, base)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s still present after quarantine (err=%v)", base, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, base+CorruptSuffix))
	if err != nil {
		t.Fatalf("corrupt file not preserved: %v", err)
	}
	if string(got) != want {
		t.Errorf("quarantined content = %q, want the original %q", got, want)
	}
}
