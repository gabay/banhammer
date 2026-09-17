package source

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

// waitTimeout bounds every "the event should have arrived by now" wait. It is
// only ever paid on failure.
const waitTimeout = 5 * time.Second

// quietFor is how long a test waits to assert that nothing else arrives. Kept
// small deliberately: these add up.
const quietFor = 150 * time.Millisecond

// countingHandler records log records so tests can assert on warn-once
// behaviour without scraping text output.
type countingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many records at level contain substr in their message.
func (h *countingHandler) count(level slog.Level, substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.Level == level && strings.Contains(r.Message, substr) {
			n++
		}
	}
	return n
}

func testLogger() (*slog.Logger, *countingHandler) {
	h := &countingHandler{}
	return slog.New(h), h
}

// harness runs a Source and collects its events.
type harness struct {
	t      *testing.T
	events chan model.Event
	errc   chan error
	cancel context.CancelFunc
}

// start runs s until the test ends, failing the test if Run reports an error
// or does not return after cancellation.
func start(t *testing.T, s Source) *harness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{
		t:      t,
		events: make(chan model.Event, 4096),
		errc:   make(chan error, 1),
		cancel: cancel,
	}
	go func() { h.errc <- s.Run(ctx, h.events) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.errc:
			if err != nil {
				t.Errorf("Run returned %v, want nil on cancellation", err)
			}
		case <-time.After(waitTimeout):
			t.Error("Run did not return after cancellation")
		}
	})
	return h
}

// lines waits for exactly n events and returns them as strings.
func (h *harness) lines(n int) []string {
	h.t.Helper()
	got := make([]string, 0, n)
	deadline := time.After(waitTimeout)
	for len(got) < n {
		select {
		case ev := <-h.events:
			got = append(got, string(ev.Raw))
		case err := <-h.errc:
			h.t.Fatalf("Run exited early with %v after %d/%d lines: %q", err, len(got), n, got)
		case <-deadline:
			h.t.Fatalf("timed out after %d/%d lines: %q", len(got), n, got)
		}
	}
	return got
}

// expectQuiet asserts nothing more arrives for a short while.
func (h *harness) expectQuiet() {
	h.t.Helper()
	select {
	case ev := <-h.events:
		h.t.Fatalf("unexpected extra event %q", ev.Raw)
	case <-time.After(quietFor):
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// waitFor polls cond until it holds, failing with what after waitTimeout.
//
// Tests use it instead of sleeping "long enough": a sleep tuned on a quiet
// laptop is both slower than it needs to be and flaky on a loaded CI machine,
// and it encodes an assumption about timing rather than about behaviour.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// sourceGoroutines counts the goroutines that belong to this package: ones
// whose stack mentions a source frame, plus fsnotify's, which our tailers
// start and stop.
//
// runtime.NumGoroutine() is process-global, so comparing it before and after
// makes a leak assertion fail whenever anything else in the binary happens to
// be running — the testing package's own bookkeeping, a lingering http
// transport, or (mostly) a neighbouring t.Parallel test. Leak tests here do
// not call t.Parallel either; the filter is belt and braces, because a false
// "goroutine leak" failure is the kind of flake that gets a test deleted
// rather than fixed.
func sourceGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, "banhammer/internal/source") || strings.Contains(stack, "fsnotify") {
			n++
		}
	}
	return n
}

// assertNoLeak compares the package's goroutine count before and after,
// retrying because runtime bookkeeping (and fsnotify's own teardown) lags by a
// few scheduler ticks.
func assertNoLeak(t *testing.T, before int) {
	t.Helper()
	var after int
	for range 100 {
		after = sourceGoroutines()
		if after <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	buf = buf[:runtime.Stack(buf, true)]
	t.Errorf("goroutine leak: %d source goroutines before, %d after\n%s", before, after, buf)
}
