package ban

import "time"

// Timer is the slice of *time.Timer the unban scheduler needs. It exists purely
// as a test seam: the manager arms exactly one of these, so injecting a fake
// makes expiry tests deterministic and instant instead of sleeping.
//
// Implementations must follow Go 1.23+ *time.Timer semantics: Stop and Reset
// guarantee that no value sent before the call is still pending on C.
type Timer interface {
	// C is the channel on which the timer fires.
	C() <-chan time.Time
	// Reset re-arms the timer for d from now, discarding any pending fire.
	Reset(d time.Duration) bool
	// Stop disarms the timer, discarding any pending fire.
	Stop() bool
}

// realTimer adapts *time.Timer to Timer.
type realTimer struct{ t *time.Timer }

// NewRealTimer is the default Options.NewTimer: a plain *time.Timer.
func NewRealTimer(d time.Duration) Timer { return realTimer{t: time.NewTimer(d)} }

func (r realTimer) C() <-chan time.Time        { return r.t.C }
func (r realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }
func (r realTimer) Stop() bool                 { return r.t.Stop() }
