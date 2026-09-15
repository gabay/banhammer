package ban

import (
	"math"
	"time"
)

// OnRepeat values for Policy.OnRepeat.
const (
	// OnRepeatIgnore leaves an existing ban untouched when the IP re-offends.
	OnRepeatIgnore = "ignore"
	// OnRepeatExtend pushes an existing ban's Until out to the new deadline.
	OnRepeatExtend = "extend"
)

// Defaults applied to a zero/implausible Policy. config.Load normally fills
// these in; the manager repeats them defensively because a zero Bantime would
// produce bans that expire the instant they are created.
const (
	defaultBantime     = time.Hour
	defaultBantimeMax  = 168 * time.Hour
	defaultFindHistory = 24 * time.Hour
)

// Policy is the per-monitor ban arithmetic: how long a first ban lasts, how it
// escalates for repeat offenders, and what a re-offense does to a live ban.
type Policy struct {
	Bantime, BantimeMax, FindHistory time.Duration
	Factor                           float64
	OnRepeat                         string // ignore|extend
}

// normalized fills in defaults and rejects values that would make the
// arithmetic nonsense (Factor < 1 would shorten bans for repeat offenders).
func (p Policy) normalized() Policy {
	if p.Bantime <= 0 {
		p.Bantime = defaultBantime
	}
	if p.BantimeMax <= 0 {
		p.BantimeMax = defaultBantimeMax
	}
	if p.BantimeMax < p.Bantime {
		p.BantimeMax = p.Bantime
	}
	if p.FindHistory <= 0 {
		p.FindHistory = defaultFindHistory
	}
	if !(p.Factor >= 1) { // also catches NaN
		p.Factor = 1
	}
	if p.OnRepeat != OnRepeatExtend {
		p.OnRepeat = OnRepeatIgnore
	}
	return p
}

// durationFor returns the ban length for the nth offense within FindHistory:
// min(Bantime * Factor^(n-1), BantimeMax).
//
// p must already be normalized. The float path is skipped entirely for the
// common Factor == 1 case, and any overflow to +Inf clamps to BantimeMax
// rather than wrapping into a negative (instantly expiring) duration.
func (p Policy) durationFor(offense int) time.Duration {
	if offense <= 1 || p.Factor == 1 {
		return min(p.Bantime, p.BantimeMax)
	}
	f := math.Pow(p.Factor, float64(offense-1))
	if math.IsNaN(f) || f <= 0 {
		return p.Bantime
	}
	ns := float64(p.Bantime) * f
	// Compare in float space: ns may be +Inf, and converting an out-of-range
	// float64 to time.Duration is implementation-defined.
	if math.IsInf(ns, 1) || ns >= float64(p.BantimeMax) {
		return p.BantimeMax
	}
	return time.Duration(ns)
}
