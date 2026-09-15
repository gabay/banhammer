package action

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"banhammer/internal/model"
)

// fakeBackend records operations and lets a test script failures. It also
// notices if the Executor ever calls it from two goroutines at once, which
// would be a correctness bug: iptables is not concurrency-safe.
type fakeBackend struct {
	mu     sync.Mutex
	ops    []string
	calls  int
	inUse  bool
	raced  bool
	handle func(n int, kind opKind, ctx context.Context) error

	done chan struct{} // one send per completed operation
}

func newFakeBackend(buf int) *fakeBackend {
	return &fakeBackend{done: make(chan struct{}, buf)}
}

func (f *fakeBackend) Name() string                { return "fake" }
func (f *fakeBackend) Start(context.Context) error { return nil }
func (f *fakeBackend) Stop(context.Context) error  { return nil }
func (f *fakeBackend) Ban(ctx context.Context, b model.Ban) error {
	return f.op(ctx, opBan, b)
}
func (f *fakeBackend) Unban(ctx context.Context, b model.Ban) error {
	return f.op(ctx, opUnban, b)
}

func (f *fakeBackend) op(ctx context.Context, kind opKind, b model.Ban) error {
	f.mu.Lock()
	if f.inUse {
		f.raced = true
	}
	f.inUse = true
	f.calls++
	n := f.calls
	f.ops = append(f.ops, kind.String()+" "+b.IP.String())
	h := f.handle
	f.mu.Unlock()

	var err error
	if h != nil {
		err = h(n, kind, ctx)
	}

	f.mu.Lock()
	f.inUse = false
	f.mu.Unlock()
	select {
	case f.done <- struct{}{}:
	default:
	}
	return err
}

func (f *fakeBackend) snapshot() (ops []string, calls int, raced bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...), f.calls, f.raced
}

// waitOps blocks until n operations have completed, failing the test rather
// than hanging forever if the executor wedges.
func (f *fakeBackend) waitOps(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-f.done:
		case <-deadline:
			_, calls, _ := f.snapshot()
			t.Fatalf("timed out waiting for %d operations; saw %d", n, calls)
		}
	}
}

// recordingSleep replaces the backoff sleep so retries cost no wall time.
func recordingSleep(d *[]time.Duration, mu *sync.Mutex) func(context.Context, time.Duration) bool {
	return func(ctx context.Context, wait time.Duration) bool {
		mu.Lock()
		*d = append(*d, wait)
		mu.Unlock()
		return ctx.Err() == nil
	}
}

func testOpts(sleep func(context.Context, time.Duration) bool) ExecutorOptions {
	return ExecutorOptions{
		QueueSize: 16,
		Attempts:  3,
		Backoff:   10 * time.Millisecond,
		OpTimeout: time.Second,
		Drain:     time.Second,
		Sleep:     sleep,
	}
}

// runExecutor starts e.Run and returns a stop function that cancels it and
// waits for the goroutine to exit, so a leak shows up as a test timeout.
func runExecutor(t *testing.T, e *Executor) (context.CancelFunc, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Run(ctx) }()
	stop := func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("Run returned %v, want nil on cancellation", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Run did not return after cancellation (goroutine leak)")
		}
	}
	return cancel, stop
}

func TestExecutorRetries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		failUntil   int // fail attempts strictly below this attempt number
		wantApplied uint64
		wantFailed  uint64
		wantCalls   int
		wantBackoff []time.Duration
	}{
		{
			name:        "succeeds first time",
			failUntil:   0,
			wantApplied: 1,
			wantCalls:   1,
		},
		{
			name:        "fails twice then succeeds",
			failUntil:   3,
			wantApplied: 1,
			wantCalls:   3,
			wantBackoff: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
		},
		{
			name:       "always fails, gives up after three attempts",
			failUntil:  99,
			wantFailed: 1,
			wantCalls:  3,
			// Backoff doubles, and there is no sleep after the final attempt.
			wantBackoff: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu      sync.Mutex
				slept   []time.Duration
				backend = newFakeBackend(8)
			)
			backend.handle = func(n int, _ opKind, _ context.Context) error {
				if n < tc.failUntil {
					return errors.New("iptables: Resource temporarily unavailable")
				}
				return nil
			}
			e := NewExecutorWithOptions(backend, testOpts(recordingSleep(&slept, &mu)), discardLogger())
			_, stop := runExecutor(t, e)

			e.Ban(testBan(t, "203.0.113.7"))
			backend.waitOps(t, tc.wantCalls)
			stop()

			_, calls, raced := backend.snapshot()
			if calls != tc.wantCalls {
				t.Fatalf("backend called %d times, want %d", calls, tc.wantCalls)
			}
			if raced {
				t.Fatal("backend was called concurrently")
			}
			st := e.Stats()
			if st.Applied != tc.wantApplied || st.Failed != tc.wantFailed {
				t.Fatalf("Stats = %+v, want applied=%d failed=%d", st, tc.wantApplied, tc.wantFailed)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(slept) != len(tc.wantBackoff) {
				t.Fatalf("backoff waits = %v, want %v", slept, tc.wantBackoff)
			}
			for i := range slept {
				if slept[i] != tc.wantBackoff[i] {
					t.Fatalf("backoff waits = %v, want %v", slept, tc.wantBackoff)
				}
			}
		})
	}
}

func TestExecutorFailureDoesNotStallTheNextOperation(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var slept []time.Duration
	backend := newFakeBackend(16)
	backend.handle = func(_ int, _ opKind, _ context.Context) error {
		// The first IP always fails; the second must still get through.
		return nil
	}
	bad := testBan(t, "203.0.113.7")
	good := testBan(t, "198.51.100.2")
	backend.handle = func(n int, _ opKind, _ context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if n <= 3 {
			return errors.New("permanent failure")
		}
		return nil
	}

	e := NewExecutorWithOptions(backend, testOpts(recordingSleep(&slept, &mu)), discardLogger())
	_, stop := runExecutor(t, e)
	e.Ban(bad)
	e.Ban(good)
	backend.waitOps(t, 4) // 3 failed attempts + 1 success
	stop()

	ops, _, _ := backend.snapshot()
	want := []string{
		"ban 203.0.113.7", "ban 203.0.113.7", "ban 203.0.113.7", "ban 198.51.100.2",
	}
	if len(ops) != len(want) {
		t.Fatalf("ops = %v, want %v", ops, want)
	}
	for i := range ops {
		if ops[i] != want[i] {
			t.Fatalf("ops = %v, want %v", ops, want)
		}
	}
	if st := e.Stats(); st.Applied != 1 || st.Failed != 1 {
		t.Fatalf("Stats = %+v, want applied=1 failed=1", st)
	}
}

func TestExecutorPerOperationTimeout(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(8)
	backend.handle = func(_ int, _ opKind, ctx context.Context) error {
		// A wedged firewall command: it only ever returns because the
		// executor's deadline kills it.
		<-ctx.Done()
		return ctx.Err()
	}
	opts := testOpts(func(context.Context, time.Duration) bool { return true })
	opts.Attempts = 2
	opts.OpTimeout = 5 * time.Millisecond
	e := NewExecutorWithOptions(backend, opts, discardLogger())
	_, stop := runExecutor(t, e)

	start := time.Now()
	e.Ban(testBan(t, "203.0.113.7"))
	backend.waitOps(t, 2)
	stop()

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout handling took %v, want well under 1s", elapsed)
	}
	if st := e.Stats(); st.Failed != 1 || st.Applied != 0 {
		t.Fatalf("Stats = %+v, want failed=1", st)
	}
}

func TestExecutorQueueFullDropsInsteadOfBlocking(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(1)
	opts := testOpts(nil)
	opts.QueueSize = 2
	e := NewExecutorWithOptions(backend, opts, discardLogger())

	// Nothing is draining the queue, so the third enqueue onwards must be
	// dropped rather than block the caller (which is the log pipeline).
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			e.Ban(testBan(t, "203.0.113.7"))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Ban blocked on a full queue")
	}

	st := e.Stats()
	if st.Queued != 2 {
		t.Fatalf("Queued = %d, want 2", st.Queued)
	}
	if st.Dropped != 8 {
		t.Fatalf("Dropped = %d, want 8", st.Dropped)
	}
}

func TestExecutorDrainsOnShutdown(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(16)
	release := make(chan struct{})
	var held atomic.Bool
	backend.handle = func(n int, _ opKind, _ context.Context) error {
		if n == 1 && held.CompareAndSwap(false, true) {
			<-release // hold the executor so the queue builds up behind us
		}
		return nil
	}
	e := NewExecutorWithOptions(backend, testOpts(nil), discardLogger())
	cancel, stop := runExecutor(t, e)

	for i := 0; i < 4; i++ {
		e.Ban(testBan(t, "203.0.113.7"))
	}
	// Wait until the first op is actually in flight before cancelling.
	for i := 0; i < 1000 && !held.Load(); i++ {
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(release)
	stop()

	if st := e.Stats(); st.Applied != 4 {
		t.Fatalf("Stats = %+v, want all 4 operations applied during drain", st)
	}
	if st := e.Stats(); st.Queued != 0 {
		t.Fatalf("queue not drained: %+v", st)
	}
}

func TestExecutorRejectsEnqueueAfterShutdown(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(4)
	e := NewExecutorWithOptions(backend, testOpts(nil), discardLogger())
	_, stop := runExecutor(t, e)
	stop()

	e.Ban(testBan(t, "203.0.113.7"))
	if st := e.Stats(); st.Dropped != 1 || st.Queued != 0 {
		t.Fatalf("Stats = %+v, want the late ban dropped", st)
	}
	if _, calls, _ := backend.snapshot(); calls != 0 {
		t.Fatalf("backend called %d times after shutdown, want 0", calls)
	}
}

func TestExecutorRunTwiceIsAnError(t *testing.T) {
	t.Parallel()
	e := NewExecutorWithOptions(newFakeBackend(1), testOpts(nil), discardLogger())
	_, stop := runExecutor(t, e)
	stop()
	if err := e.Run(context.Background()); err == nil {
		t.Fatal("second Run should fail rather than start a second drainer")
	}
}

func TestExecutorSerialisesConcurrentProducers(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend(256)
	opts := testOpts(nil)
	opts.QueueSize = 256 // drops are covered elsewhere; here nothing may be lost
	e := NewExecutorWithOptions(backend, opts, discardLogger())
	_, stop := runExecutor(t, e)

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Ban(testBan(t, "203.0.113.7"))
			e.Unban(testBan(t, "2001:db8::1"))
		}()
	}
	wg.Wait()
	backend.waitOps(t, 2*n)
	stop()

	_, calls, raced := backend.snapshot()
	if raced {
		t.Fatal("backend saw concurrent calls; firewall mutations must be serialised")
	}
	if calls != 2*n {
		t.Fatalf("backend called %d times, want %d", calls, 2*n)
	}
	if st := e.Stats(); st.Applied != 2*n {
		t.Fatalf("Stats = %+v, want applied=%d", st, 2*n)
	}
}

func TestExecutorNilLoggerIsTolerated(t *testing.T) {
	t.Parallel()
	if e := NewExecutor(newFakeBackend(1), nil); e == nil || e.log == nil {
		t.Fatal("NewExecutor must tolerate a nil logger")
	}
}

func TestSleepCtx(t *testing.T) {
	t.Parallel()
	// The default backoff sleep: short waits complete, and a cancelled context
	// cuts the wait short so shutdown is not delayed by a retry timer.
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Fatal("sleepCtx should report completion")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx should report cancellation")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled sleep took %v", elapsed)
	}
}
