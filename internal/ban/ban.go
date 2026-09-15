// Package ban is Banhammer's decision core: it decides who gets banned, for
// how long, and when they come back.
//
// # Responsibilities
//
//   - the allowlist, checked before anything else, so an operator cannot be
//     locked out of their own box;
//   - escalation and repeat handling (offense history within FindHistory);
//   - a single min-heap of pending unbans driven by a single timer;
//   - handing enforcement to an Enforcer (the firewall executor) and state to a
//     Persister (the on-disk store).
//
// # Concurrency model
//
// One mutex guards all mutable state (the ban map, the unban heap, offense
// history and the policy table). Offend arrives from the aggregator goroutine
// while Ban/Unban/UnbanAll/Snapshot arrive from the control socket and Run's
// expiry loop mutates from its own goroutine; a mutex is simpler than an
// internal command channel and avoids a second queue whose depth would need
// tuning. Enforcer calls are made *while holding* the lock, so the order of
// firewall operations always matches the order of state changes — an Enforcer
// must therefore be non-blocking (action.Executor enqueues) and must never call
// back into the Manager. Persister calls are made *outside* the lock, guarded
// by a sequence number so a slow write can never clobber newer state.
//
// # Ordering guarantees (and non-guarantees)
//
// Bans sharing the same Until are unbanned in unspecified order, and Snapshot
// only reflects a consistent point in time — it is not linearised against an
// in-flight Enforcer call. Nothing guarantees that a firewall rule is actually
// installed by the time Offend returns; enforcement is asynchronous by design.
package ban

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"banhammer/internal/model"
)

// Errors returned by the manual control-plane operations.
var (
	// ErrAllowlisted is returned by Ban for an address the allowlist protects.
	ErrAllowlisted = errors.New("ban: address is allowlisted")
	// ErrNotBanned is returned by Unban for an address that is not banned.
	ErrNotBanned = errors.New("ban: address is not banned")
	// ErrInvalidAddr is returned for an address that is not a valid IP.
	ErrInvalidAddr = errors.New("ban: invalid address")
	// ErrRunning is returned by a second concurrent call to Run.
	ErrRunning = errors.New("ban: manager is already running")
)

// Enforcer applies decisions to the firewall. It is satisfied by
// *action.Executor, whose Ban/Unban are non-blocking enqueues; implementations
// must not block and must not call back into the Manager.
type Enforcer interface {
	Ban(model.Ban)
	Unban(model.Ban)
}

// Persister writes the authoritative ban set to disk. It is satisfied by
// *store.Store, which makes the write atomic and debounces it.
type Persister interface {
	SaveBans([]model.Ban) error
}

// Options configures a Manager. Only Enforcer and Persister are really
// optional (a nil one is treated as a no-op, which is what `banhammer test`
// wants); everything else has a working default.
type Options struct {
	// Allowlist is the set of never-ban prefixes. Bare addresses should
	// already have been widened to /32 or /128 by config.Load.
	Allowlist []netip.Prefix
	// AllowLocal additionally exempts loopback and this host's own interface
	// addresses.
	AllowLocal bool
	Enforcer   Enforcer
	Persister  Persister
	// Now defaults to time.Now. Injected so expiry is testable.
	Now func() time.Time
	Log *slog.Logger

	// Interfaces lists this host's addresses for AllowLocal. Defaults to
	// LocalInterfacePrefixes; injected so tests do not depend on the machine's
	// NICs. Whatever it returns is used verbatim (masked), so returning a
	// subnet exempts that whole subnet.
	// NOT in docs/CONTRACTS.md — see the package report.
	Interfaces InterfaceLister
	// NewTimer builds the single scheduler timer. Defaults to NewRealTimer;
	// injected so expiry tests run instantly. NOT in docs/CONTRACTS.md.
	NewTimer func(time.Duration) Timer
}

// Stats are lifetime counters, exposed for the metrics endpoint and for
// `banhammer status`. Not part of docs/CONTRACTS.md.
type Stats struct {
	Active          int    // bans currently enforced
	Banned          uint64 // new bans issued
	Extended        uint64 // existing bans pushed out
	Unbanned        uint64 // manual or restore-driven unbans
	Expired         uint64 // unbans driven by the scheduler
	Allowlisted     uint64 // offenses dropped by the allowlist
	PersistFailures uint64
}

// historyKey scopes offense history per monitor, because Policy (and therefore
// FindHistory) is per monitor: mixing jails would make "the nth offense within
// FindHistory" ambiguous when two monitors disagree on the window.
type historyKey struct {
	ip      netip.Addr
	monitor string
}

// historySweepEvery bounds offense-history memory: a full prune of stale
// entries runs once every N offenses, amortising to O(1) per offense while
// guaranteeing that an IP which never returns is eventually forgotten.
const historySweepEvery = 1024

// maxOffenseHistory caps the offenses remembered per (IP, monitor). With any
// Factor > 1 the ban length is pinned at BantimeMax long before this, so the
// cap costs nothing in accuracy and bounds memory even with a find_history of
// weeks. Offense numbers therefore saturate at maxOffenseHistory + 1.
const maxOffenseHistory = 128

// idleWait is what the single timer is armed for when nothing is scheduled.
// The wake channel interrupts it as soon as a ban is added, so the value only
// bounds how long a (bug-induced) missed wakeup could go unnoticed.
const idleWait = time.Hour

// Manager owns the ban state machine. Create it with NewManager and run its
// expiry loop with Run.
type Manager struct {
	now       func() time.Time
	log       *slog.Logger
	enforcer  Enforcer
	persister Persister
	newTimer  func(time.Duration) Timer

	// Immutable after NewManager, hence lock-free in Allowed.
	allow      []netip.Prefix
	allowLocal bool

	wake    chan struct{} // nudges Run to re-arm its timer
	running atomic.Bool

	mu       sync.Mutex
	policies map[string]Policy
	bans     map[netip.Addr]model.Ban
	sched    *banHeap
	history  map[historyKey][]time.Time
	offenses int    // offenses since the last history sweep
	seq      uint64 // monotonic state version, for persistence ordering

	// persistMu serialises writes; persisted is the highest seq written, so a
	// snapshot that lost the race is dropped instead of overwriting newer state.
	persistMu sync.Mutex
	persisted uint64

	counters struct {
		banned, extended, unbanned, expired, allowlisted, persistFailures atomic.Uint64
	}
}

// NewManager builds a Manager. It resolves the host's own addresses once, at
// construction: interface churn during a daemon's lifetime is rare, and a
// lookup on the Offend hot path is not.
func NewManager(o Options) *Manager {
	m := &Manager{
		now:        o.Now,
		log:        o.Log,
		enforcer:   o.Enforcer,
		persister:  o.Persister,
		newTimer:   o.NewTimer,
		allowLocal: o.AllowLocal,
		wake:       make(chan struct{}, 1),
		policies:   make(map[string]Policy),
		bans:       make(map[netip.Addr]model.Ban),
		sched:      newBanHeap(),
		history:    make(map[historyKey][]time.Time),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.newTimer == nil {
		m.newTimer = NewRealTimer
	}

	allow, bad := normalizePrefixes(o.Allowlist)
	for _, p := range bad {
		m.log.Warn("ignoring unusable allowlist entry", "prefix", p.String())
	}
	if o.AllowLocal {
		lister := o.Interfaces
		if lister == nil {
			lister = LocalInterfacePrefixes
		}
		local, err := lister()
		if err != nil {
			// Not fatal: explicit allowlist entries and loopback still apply.
			m.log.Error("cannot enumerate local interfaces; allow_local covers loopback only", "err", err)
		}
		norm, bad := normalizePrefixes(local)
		for _, p := range bad {
			m.log.Warn("ignoring unusable local interface prefix", "prefix", p.String())
		}
		allow = append(allow, norm...)
	}
	m.allow = slices.Clip(allow)
	return m
}

// SetPolicy installs the policy for a monitor. The empty monitor name sets the
// fallback used for monitors with no policy of their own (an offense reported
// by a monitor that was removed by a reload, say). Safe to call at any time,
// including from a config reload while the daemon is running.
func (m *Manager) SetPolicy(monitor string, p Policy) {
	p = p.normalized()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[monitor] = p
}

// policyLocked resolves the policy for a monitor. m.mu must be held.
func (m *Manager) policyLocked(monitor string) Policy {
	if p, ok := m.policies[monitor]; ok {
		return p
	}
	if p, ok := m.policies[""]; ok {
		return p
	}
	return Policy{}.normalized()
}

// Offend records that monitor saw ip cross its threshold with count hits, and
// bans or extends accordingly. It is the aggregator's entry point and never
// returns an error: an allowlisted address is a silent no-op and a persistence
// failure is logged and counted, because neither should stop the pipeline.
//
// The offense counter that drives escalation counts *bans*, not threshold
// crossings: while a ban is live, further crossings for the same IP change
// nothing (under OnRepeat "ignore"), so counting them would let a flood
// fast-forward an attacker to BantimeMax and would grow history without bound.
func (m *Manager) Offend(monitor string, ip netip.Addr, count int) {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		m.log.Warn("ignoring offense for invalid address", "monitor", monitor)
		return
	}
	if m.Allowed(ip) {
		m.counters.allowlisted.Add(1)
		m.log.Debug("offense ignored: address is allowlisted", "ip", ip, "monitor", monitor, "count", count)
		return
	}

	m.mu.Lock()
	now := m.now()
	p := m.policyLocked(monitor)
	key := historyKey{ip: ip, monitor: monitor}
	hist := m.pruneOffensesLocked(key, now, p.FindHistory)
	offense := len(hist) + 1 // prospective; committed only if we act
	d := p.durationFor(offense)
	until := now.Add(d)

	existing, banned := m.bans[ip]
	switch {
	case banned && !existing.Expired(now):
		if p.OnRepeat != OnRepeatExtend {
			m.mu.Unlock()
			// Enabled-guarded: this is the branch a sustained flood hits over
			// and over, and boxing the arguments allocates even when the
			// handler would drop the record.
			if m.log.Enabled(context.Background(), slog.LevelDebug) {
				m.log.Debug("repeat offense ignored: ban already active",
					"ip", ip, "monitor", monitor, "until", existing.Until)
			}
			return
		}
		if !until.After(existing.Until) {
			// Escalation has not yet outgrown the live ban; shortening it
			// would hand the attacker time back.
			m.mu.Unlock()
			m.log.Debug("repeat offense: computed ban is not longer than the active one",
				"ip", ip, "monitor", monitor, "until", existing.Until)
			return
		}
		prev := existing.Until
		existing.Until = until
		existing.Count = count
		existing.Offense = offense
		existing.Monitor = monitor
		m.bans[ip] = existing
		m.sched.schedule(ip, until)
		m.commitOffenseLocked(key, hist, now)
		m.counters.extended.Add(1)
		snap, seq := m.stateLocked()
		m.mu.Unlock()
		// Deliberately not re-enforced: the firewall entry already exists and
		// re-issuing Ban would append a duplicate iptables rule.
		m.log.Info("ban extended", "ip", ip, "monitor", monitor, "was", prev, "until", until, "offense", offense)
		m.signal()
		m.persist(seq, snap)
	default:
		b := model.Ban{IP: ip, Monitor: monitor, At: now, Until: until, Count: count, Offense: offense}
		if banned {
			// Expired but still in the map: Run is not draining (shutdown, or
			// no Run at all). Replace it rather than leaking the old entry.
			m.log.Debug("replacing expired ban still in state", "ip", ip, "until", existing.Until)
		}
		m.applyLocked(b)
		m.commitOffenseLocked(key, hist, now)
		snap, seq := m.stateLocked()
		m.mu.Unlock()
		m.counters.banned.Add(1)
		m.log.Info("banned", "ip", ip, "monitor", monitor, "count", count,
			"offense", offense, "bantime", d, "until", until)
		m.signal()
		m.persist(seq, snap)
	}
}

// Ban bans ip manually, for d (or the monitor's configured Bantime if d <= 0).
// Unlike Offend it reports an allowlisted address as an error: an operator
// typing `banhammer ban` deserves to be told why nothing happened. It never
// shortens a live ban — use Unban then Ban for that.
func (m *Manager) Ban(ip netip.Addr, monitor string, d time.Duration) error {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidAddr, ip.String())
	}
	if m.Allowed(ip) {
		return fmt.Errorf("%w: %s", ErrAllowlisted, ip)
	}

	m.mu.Lock()
	now := m.now()
	p := m.policyLocked(monitor)
	if d <= 0 {
		d = p.Bantime
	}
	until := now.Add(d)
	b := model.Ban{IP: ip, Monitor: monitor, At: now, Until: until, Count: 0, Offense: 1}
	if existing, ok := m.bans[ip]; ok && !existing.Expired(now) {
		b = existing
		b.Monitor = monitor
		b.Offense = existing.Offense
		if until.After(existing.Until) {
			b.Until = until
			m.counters.extended.Add(1)
		}
	} else {
		m.counters.banned.Add(1)
	}
	m.applyLocked(b)
	snap, seq := m.stateLocked()
	m.mu.Unlock()

	m.log.Info("banned manually", "ip", ip, "monitor", monitor, "until", b.Until)
	m.signal()
	return m.persist(seq, snap)
}

// applyLocked installs b (new or replacing) and enforces it. m.mu must be held.
func (m *Manager) applyLocked(b model.Ban) {
	m.bans[b.IP] = b
	m.sched.schedule(b.IP, b.Until)
	if m.enforcer != nil {
		m.enforcer.Ban(b)
	}
}

// Unban lifts the ban on ip. Offense history is deliberately kept, so an
// operator unbanning a repeat offender does not reset their escalation.
func (m *Manager) Unban(ip netip.Addr) error {
	ip = ip.Unmap().WithZone("")
	m.mu.Lock()
	b, ok := m.bans[ip]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotBanned, ip)
	}
	m.dropLocked(b)
	snap, seq := m.stateLocked()
	m.mu.Unlock()

	m.counters.unbanned.Add(1)
	m.log.Info("unbanned", "ip", ip, "monitor", b.Monitor)
	m.signal()
	return m.persist(seq, snap)
}

// UnbanAll lifts every active ban. Used by `banhammer unban --all` and by
// shutdown when flush_on_exit is set.
func (m *Manager) UnbanAll() error {
	m.mu.Lock()
	n := len(m.bans)
	for _, b := range m.bans {
		m.dropLocked(b)
	}
	snap, seq := m.stateLocked()
	m.mu.Unlock()

	m.counters.unbanned.Add(uint64(n))
	m.log.Info("unbanned all", "count", n)
	m.signal()
	return m.persist(seq, snap)
}

// dropLocked removes b from state and tells the firewall. m.mu must be held.
// Safe to call while ranging over m.bans (deleting the current key is legal).
func (m *Manager) dropLocked(b model.Ban) {
	delete(m.bans, b.IP)
	m.sched.remove(b.IP)
	if m.enforcer != nil {
		m.enforcer.Unban(b)
	}
}

// Restore re-applies bans loaded from disk. It runs on every start, so it must
// tolerate whatever an older (or crashed) run left behind: expired bans,
// duplicate IPs, allowlisted IPs, and bans whose monitor no longer exists in
// the config. It is idempotent — calling it twice, or with bans already held,
// converges on the same state, and a record that changes nothing is not
// re-pushed to the firewall (with iptables, a second -I would stack a
// duplicate rule that a single -D would not clear).
//
// A ban for an unknown monitor is still enforced: the firewall rule is real
// regardless of config churn, and dropping it would silently release an
// attacker because someone renamed a jail.
func (m *Manager) Restore(bans []model.Ban) error {
	m.mu.Lock()
	now := m.now()
	var live, expired, dupes, exempt int

	for _, b := range bans {
		b.IP = b.IP.Unmap().WithZone("")
		if !b.IP.IsValid() {
			m.log.Warn("dropping restored ban with invalid address", "monitor", b.Monitor)
			continue
		}
		if m.Allowed(b.IP) {
			// The allowlist may have grown since this ban was written; clear
			// the (possibly still-installed) firewall rule.
			exempt++
			if m.enforcer != nil {
				m.enforcer.Unban(b)
			}
			m.log.Warn("dropping restored ban for allowlisted address", "ip", b.IP, "monitor", b.Monitor)
			continue
		}
		if b.Until.IsZero() || b.Expired(now) {
			expired++
			if m.enforcer != nil {
				m.enforcer.Unban(b)
			}
			m.log.Debug("restored ban already expired; unbanning", "ip", b.IP, "until", b.Until)
			continue
		}
		if _, known := m.policies[b.Monitor]; !known && len(m.policies) > 0 {
			m.log.Warn("restored ban references an unknown monitor; still enforcing",
				"ip", b.IP, "monitor", b.Monitor)
		}
		if prev, ok := m.bans[b.IP]; ok {
			dupes++
			// Keep the longest term: whichever record is the most recent
			// truth, releasing early is the worse failure.
			if !b.Until.After(prev.Until) {
				continue
			}
		}
		if b.Offense < 1 {
			b.Offense = 1
		}
		live++
		m.applyLocked(b)
	}

	snap, seq := m.stateLocked()
	m.mu.Unlock()

	m.log.Info("restored bans", "live", live, "expired", expired,
		"duplicates", dupes, "allowlisted", exempt, "input", len(bans))
	m.signal()
	return m.persist(seq, snap)
}

// Run drives expiry until ctx is cancelled, at which point it returns nil.
//
// It owns the *only* timer in the package: one heap head, one armed timer,
// re-armed after every wakeup. Ten thousand bans expiring in the same second
// cost one wakeup, one batch of Enforcer calls and one persist, not ten
// thousand of each.
func (m *Manager) Run(ctx context.Context) error {
	if !m.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	defer m.running.Store(false)

	t := m.newTimer(idleWait)
	defer t.Stop()

	for {
		wait := m.expireAndSchedule()
		t.Reset(wait)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C():
		case <-m.wake:
		}
	}
}

// expireAndSchedule unbans everything due, persists once if anything changed,
// and returns how long to wait for the next expiry.
func (m *Manager) expireAndSchedule() time.Duration {
	m.mu.Lock()
	now := m.now()
	var n int
	for {
		e, ok := m.sched.peek()
		if !ok || e.until.After(now) {
			break
		}
		m.sched.popHead()
		b, ok := m.bans[e.ip]
		if !ok {
			continue // already unbanned; nothing to do
		}
		if b.Until.After(now) {
			// Defensive: an entry that lost sync with the ban record. Re-arm
			// it rather than releasing the address early.
			m.sched.schedule(b.IP, b.Until)
			continue
		}
		delete(m.bans, b.IP)
		if m.enforcer != nil {
			m.enforcer.Unban(b)
		}
		n++
		m.log.Debug("ban expired", "ip", b.IP, "monitor", b.Monitor, "until", b.Until)
	}

	wait := idleWait
	if e, ok := m.sched.peek(); ok {
		// Arm exactly at the head, however far out it is; idleWait is only the
		// sentinel for "nothing scheduled".
		wait = max(e.until.Sub(now), 0)
	}
	var snap []model.Ban
	var seq uint64
	if n > 0 {
		snap, seq = m.stateLocked()
	}
	m.mu.Unlock()

	if n > 0 {
		m.counters.expired.Add(uint64(n))
		m.log.Info("bans expired", "count", n)
		// One write for the whole batch.
		if err := m.persist(seq, snap); err != nil {
			m.log.Debug("persist after expiry failed", "err", err)
		}
	}
	return wait
}

// signal nudges Run to recompute its timer. Non-blocking: a pending nudge is
// as good as a new one.
func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Snapshot returns the active bans, sorted by expiry then address. The slice
// and its elements are copies: model.Ban contains no reference types, so the
// caller cannot reach into manager state through it.
func (m *Manager) Snapshot() []model.Ban {
	m.mu.Lock()
	out := m.snapshotLocked()
	m.mu.Unlock()
	return out
}

func (m *Manager) snapshotLocked() []model.Ban {
	out := make([]model.Ban, 0, len(m.bans))
	for _, b := range m.bans {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b model.Ban) int {
		if c := a.Until.Compare(b.Until); c != 0 {
			return c
		}
		return a.IP.Compare(b.IP)
	})
	return out
}

// stateLocked returns the snapshot to persist plus its version. m.mu must be held.
func (m *Manager) stateLocked() ([]model.Ban, uint64) {
	m.seq++
	return m.snapshotLocked(), m.seq
}

// Stats reports lifetime counters and the current number of active bans.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	active := len(m.bans)
	m.mu.Unlock()
	return Stats{
		Active:          active,
		Banned:          m.counters.banned.Load(),
		Extended:        m.counters.extended.Load(),
		Unbanned:        m.counters.unbanned.Load(),
		Expired:         m.counters.expired.Load(),
		Allowlisted:     m.counters.allowlisted.Load(),
		PersistFailures: m.counters.persistFailures.Load(),
	}
}

// persist writes snap if it is newer than what has already been written.
// A failure is logged and counted but never unwinds an enforced ban: the
// firewall is the source of truth for safety, the file only for restarts.
func (m *Manager) persist(seq uint64, snap []model.Ban) error {
	if m.persister == nil {
		return nil
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if seq <= m.persisted {
		return nil // a newer snapshot already went out
	}
	m.persisted = seq
	if err := m.persister.SaveBans(snap); err != nil {
		m.counters.persistFailures.Add(1)
		m.log.Error("saving ban state failed; bans remain enforced", "err", err, "bans", len(snap))
		return fmt.Errorf("saving ban state: %w", err)
	}
	return nil
}

// pruneOffensesLocked drops k's offenses older than find and returns what is
// left, oldest first. It also drives the periodic full sweep, which is counted
// per call (not per committed offense) so that pruning keeps up with traffic.
// m.mu must be held.
func (m *Manager) pruneOffensesLocked(k historyKey, now time.Time, find time.Duration) []time.Time {
	m.offenses++
	if m.offenses >= historySweepEvery {
		m.offenses = 0
		m.sweepHistoryLocked(now)
	}
	h, ok := m.history[k]
	if !ok {
		return nil
	}
	// History is append-ordered, so the survivors are a suffix: find the first
	// one inside the window and reslice, rather than filtering element by
	// element.
	cutoff := now.Add(-find)
	i := 0
	for i < len(h) && !h[i].After(cutoff) {
		i++
	}
	switch {
	case i == len(h):
		delete(m.history, k) // nothing left in the window
		return nil
	case i > 0:
		h = append(h[:0], h[i:]...)
		m.history[k] = h
	}
	return h
}

// commitOffenseLocked records an offense at now. hist must be the slice
// pruneOffensesLocked just returned for k. m.mu must be held.
func (m *Manager) commitOffenseLocked(k historyKey, hist []time.Time, now time.Time) {
	if len(hist) >= maxOffenseHistory {
		// Drop the oldest. An offender this prolific is already pinned at
		// BantimeMax, so the exact count no longer changes any decision, and
		// the cap is what keeps memory bounded for a months-long find_history.
		n := copy(hist, hist[len(hist)-maxOffenseHistory+1:])
		hist = hist[:n]
	}
	m.history[k] = append(hist, now)
}

// sweepHistoryLocked drops history that no policy could still count, so an
// attacker who never returns does not pin memory forever. m.mu must be held.
func (m *Manager) sweepHistoryLocked(now time.Time) {
	before := len(m.history)
	for k, h := range m.history {
		find := m.policyLocked(k.monitor).FindHistory
		cutoff := now.Add(-find)
		i := 0
		for i < len(h) && !h[i].After(cutoff) {
			i++
		}
		switch {
		case i == len(h):
			delete(m.history, k)
		case i > 0:
			m.history[k] = append(h[:0], h[i:]...)
		}
	}
	if dropped := before - len(m.history); dropped > 0 {
		m.log.Debug("pruned offense history", "dropped", dropped, "remaining", len(m.history))
	}
}
