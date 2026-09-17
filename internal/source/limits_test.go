package source

import (
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()
	// A fake clock: the point of the injectable now is that proving "the
	// second message is suppressed for a minute" must not take a minute.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		// offsets are the times, relative to base, at which allow is called.
		offsets []time.Duration
		every   time.Duration
		// wantAllowed is one entry per call.
		wantAllowed []bool
		// wantSuppressed is the suppressed count reported by each *allowed*
		// call, in order.
		wantSuppressed []uint64
	}{
		{
			name:           "first call always passes",
			offsets:        []time.Duration{0},
			every:          time.Minute,
			wantAllowed:    []bool{true},
			wantSuppressed: []uint64{0},
		},
		{
			name:           "burst collapses to one, and the count is reported next time",
			offsets:        []time.Duration{0, time.Second, 2 * time.Second, 90 * time.Second},
			every:          time.Minute,
			wantAllowed:    []bool{true, false, false, true},
			wantSuppressed: []uint64{0, 2},
		},
		{
			name:           "exactly at the interval is allowed",
			offsets:        []time.Duration{0, time.Minute},
			every:          time.Minute,
			wantAllowed:    []bool{true, true},
			wantSuppressed: []uint64{0, 0},
		},
		{
			name:           "one tick short is not",
			offsets:        []time.Duration{0, time.Minute - time.Nanosecond},
			every:          time.Minute,
			wantAllowed:    []bool{true, false},
			wantSuppressed: []uint64{0},
		},
		{
			name:           "zero interval falls back to the default",
			offsets:        []time.Duration{0, defaultWarnInterval - time.Second, defaultWarnInterval},
			wantAllowed:    []bool{true, false, true},
			wantSuppressed: []uint64{0, 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var now time.Time
			r := rateLimiter{every: tc.every, now: func() time.Time { return now }}

			var gotAllowed []bool
			var gotSuppressed []uint64
			for _, off := range tc.offsets {
				now = base.Add(off)
				ok, suppressed := r.allow()
				gotAllowed = append(gotAllowed, ok)
				if ok {
					gotSuppressed = append(gotSuppressed, suppressed)
				}
			}
			for i, want := range tc.wantAllowed {
				if gotAllowed[i] != want {
					t.Errorf("call %d allowed = %v, want %v (all: %v)", i, gotAllowed[i], want, gotAllowed)
				}
			}
			if len(gotSuppressed) != len(tc.wantSuppressed) {
				t.Fatalf("suppressed counts = %v, want %v", gotSuppressed, tc.wantSuppressed)
			}
			for i, want := range tc.wantSuppressed {
				if gotSuppressed[i] != want {
					t.Errorf("allowed call %d reported %d suppressed, want %d", i, gotSuppressed[i], want)
				}
			}
		})
	}
}

// The limiter is shared between a listener's connection goroutines and a
// tail's per-file goroutines, so it has to hold up under -race.
func TestRateLimiterConcurrent(t *testing.T) {
	t.Parallel()
	r := rateLimiter{every: time.Hour}
	var wg sync.WaitGroup
	allowed := make([]int, 8)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if ok, _ := r.allow(); ok {
					allowed[g]++
				}
			}
		}()
	}
	wg.Wait()
	total := 0
	for _, n := range allowed {
		total += n
	}
	if total != 1 {
		t.Errorf("allowed %d of 8000 calls within one interval, want exactly 1", total)
	}
}

// A repeating error must produce one warning, not one per occurrence: this is
// the PROJECT.md §4.9 requirement the sources lean on.
func TestRateLimiterWarnSuppressesAndCounts(t *testing.T) {
	t.Parallel()
	log, h := testLogger()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := rateLimiter{every: time.Minute, now: func() time.Time { return now }}

	for range 100 {
		r.warn(log, "disk on fire", "err", "EIO")
	}
	if n := h.count(slog.LevelWarn, "disk on fire"); n != 1 {
		t.Fatalf("warnings = %d, want 1", n)
	}

	now = now.Add(time.Minute)
	r.warn(log, "disk on fire", "err", "EIO")
	if n := h.count(slog.LevelWarn, "disk on fire"); n != 2 {
		t.Fatalf("warnings after the interval = %d, want 2", n)
	}
	if got := attrOf(t, h, 1, "suppressed"); got != uint64(99) {
		t.Errorf("suppressed = %v (%T), want uint64(99)", got, got)
	}
}

// attrOf returns the value of the named attribute on the i'th recorded log
// line, so tests can assert on structure rather than on formatted text.
func attrOf(t *testing.T, h *countingHandler, i int, key string) any {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if i >= len(h.records) {
		t.Fatalf("record %d requested, only %d recorded", i, len(h.records))
	}
	var out any
	h.records[i].Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			out = a.Value.Any()
			return false
		}
		return true
	})
	if out == nil {
		t.Fatalf("record %d has no %q attribute", i, key)
	}
	return out
}

func TestNextAcceptDelay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "first failure starts small", in: 0, want: acceptRetryMin},
		{name: "negative is treated as unset", in: -time.Second, want: acceptRetryMin},
		{name: "doubles", in: 5 * time.Millisecond, want: 10 * time.Millisecond},
		{name: "keeps doubling", in: 320 * time.Millisecond, want: 640 * time.Millisecond},
		{name: "clamps at the ceiling", in: 640 * time.Millisecond, want: acceptRetryMax},
		{name: "stays at the ceiling", in: acceptRetryMax, want: acceptRetryMax},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := nextAcceptDelay(tc.in); got != tc.want {
				t.Errorf("nextAcceptDelay(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Reaching the ceiling must take a bounded number of failures: an EMFILE storm
// should settle into one retry a second, not creep towards it for minutes.
func TestNextAcceptDelayReachesCeilingQuickly(t *testing.T) {
	t.Parallel()
	d := time.Duration(0)
	for i := range 100 {
		d = nextAcceptDelay(d)
		if d == acceptRetryMax {
			if i > 10 {
				t.Errorf("took %d failures to reach %v", i+1, acceptRetryMax)
			}
			return
		}
	}
	t.Fatalf("never reached %v, stuck at %v", acceptRetryMax, d)
}
