package ban

import (
	"math"
	"testing"
	"time"
)

func TestPolicyNormalized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Policy
		want Policy
	}{
		{
			name: "zero policy gets defaults",
			in:   Policy{},
			want: Policy{Bantime: defaultBantime, BantimeMax: defaultBantimeMax, FindHistory: defaultFindHistory, Factor: 1, OnRepeat: OnRepeatIgnore},
		},
		{
			name: "factor below one is clamped to flat",
			in:   Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 0.5, OnRepeat: OnRepeatExtend},
			want: Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 1, OnRepeat: OnRepeatExtend},
		},
		{
			name: "NaN factor is clamped",
			in:   Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: math.NaN()},
			want: Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 1, OnRepeat: OnRepeatIgnore},
		},
		{
			name: "max below bantime is raised",
			in:   Policy{Bantime: 10 * time.Hour, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 2},
			want: Policy{Bantime: 10 * time.Hour, BantimeMax: 10 * time.Hour, FindHistory: time.Hour, Factor: 2, OnRepeat: OnRepeatIgnore},
		},
		{
			name: "unknown on_repeat falls back to ignore",
			in:   Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 1, OnRepeat: "nonsense"},
			want: Policy{Bantime: time.Minute, BantimeMax: time.Hour, FindHistory: time.Hour, Factor: 1, OnRepeat: OnRepeatIgnore},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.normalized(); got != tt.want {
				t.Errorf("normalized() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPolicyDurationFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		p       Policy
		offense int
		want    time.Duration
	}{
		{name: "flat first", p: Policy{Bantime: time.Hour, Factor: 1}, offense: 1, want: time.Hour},
		{name: "flat tenth", p: Policy{Bantime: time.Hour, Factor: 1}, offense: 10, want: time.Hour},
		{name: "escalating first is exactly bantime", p: Policy{Bantime: time.Hour, Factor: 2}, offense: 1, want: time.Hour},
		{name: "escalating second", p: Policy{Bantime: time.Hour, Factor: 2}, offense: 2, want: 2 * time.Hour},
		{name: "escalating third", p: Policy{Bantime: time.Hour, Factor: 2}, offense: 3, want: 4 * time.Hour},
		{name: "clamped at max", p: Policy{Bantime: time.Hour, Factor: 2, BantimeMax: 10 * time.Hour}, offense: 5, want: 10 * time.Hour},
		{name: "non-integer factor", p: Policy{Bantime: 10 * time.Minute, Factor: 1.5}, offense: 3, want: 22*time.Minute + 30*time.Second},
		// Offense 0 should never happen, but must not produce a negative or
		// zero-length ban if it does.
		{name: "offense zero behaves like first", p: Policy{Bantime: time.Hour, Factor: 2}, offense: 0, want: time.Hour},
		{name: "negative offense behaves like first", p: Policy{Bantime: time.Hour, Factor: 2}, offense: -5, want: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.normalized().durationFor(tt.offense); got != tt.want {
				t.Errorf("durationFor(%d) = %v, want %v", tt.offense, got, tt.want)
			}
		})
	}
}

// TestPolicyDurationForIsMonotonicAndClamped walks a doubling policy far past
// the point where Bantime*2^(n-1) overflows float64 and then time.Duration.
func TestPolicyDurationForIsMonotonicAndClamped(t *testing.T) {
	t.Parallel()
	cases := []Policy{
		{Bantime: time.Hour, Factor: 2, BantimeMax: 168 * time.Hour},
		{Bantime: time.Second, Factor: 2, BantimeMax: time.Duration(math.MaxInt64)},
		{Bantime: time.Hour, Factor: 1e300, BantimeMax: 168 * time.Hour},
		{Bantime: time.Duration(math.MaxInt64), Factor: 2, BantimeMax: time.Duration(math.MaxInt64)},
	}
	for i, p := range cases {
		p := p.normalized()
		prev := time.Duration(0)
		for n := 1; n <= 100; n++ {
			got := p.durationFor(n)
			if got <= 0 {
				t.Fatalf("case %d offense %d: duration %v is not positive (overflow?)", i, n, got)
			}
			if got < prev {
				t.Fatalf("case %d offense %d: duration %v decreased from %v", i, n, got, prev)
			}
			if got > p.BantimeMax {
				t.Fatalf("case %d offense %d: duration %v exceeds max %v", i, n, got, p.BantimeMax)
			}
			prev = got
		}
		if last := p.durationFor(100); last != p.BantimeMax && p.Factor > 1 {
			t.Errorf("case %d: offense 100 = %v, want the clamp %v", i, last, p.BantimeMax)
		}
	}
}
