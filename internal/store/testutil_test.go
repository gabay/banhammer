package store

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
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

// newTestStore opens a store on dir with a fake clock and scheduler, and
// returns it along with the write recorder.
func newTestStore(t *testing.T, dir string) (*Store, *fakeClock, *fakeScheduler, *writeRecorder) {
	t.Helper()
	clk := newFakeClock()
	sched := &fakeScheduler{}
	s, err := OpenWith(dir, Options{
		Log:       discardLogger(),
		Now:       clk.Now,
		AfterFunc: sched.AfterFunc,
	})
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
