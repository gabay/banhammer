package ban

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"banhammer/internal/model"
)

func TestOffendFirstOffenseIsExactlyBantime(t *testing.T) {
	t.Parallel()
	m, clk, fe, fp := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, BantimeMax: 24 * time.Hour, FindHistory: 24 * time.Hour, Factor: 1})

	ip := addr(t, "198.51.100.7")
	m.Offend("sshd", ip, 5, "")

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot = %v, want 1 ban", snap)
	}
	got := snap[0]
	want := model.Ban{IP: ip, Monitor: "sshd", At: clk.Now(), Until: clk.Now().Add(time.Hour), Count: 5, Offense: 1}
	if got != want {
		t.Errorf("ban = %+v, want %+v", got, want)
	}
	if b := fe.banned(); len(b) != 1 || b[0] != want {
		t.Errorf("enforcer bans = %+v, want exactly the ban", b)
	}
	if fp.calls() != 1 {
		t.Errorf("persister calls = %d, want 1", fp.calls())
	}
}

func TestOffendNormalizesV4In6(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: time.Hour})

	m.Offend("sshd", addr(t, "::ffff:198.51.100.7"), 5, "")
	m.Offend("sshd", addr(t, "198.51.100.7"), 5, "") // same key, must not double-ban

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot = %v, want a single ban keyed on the unmapped address", snap)
	}
	if !snap[0].IP.Is4() {
		t.Errorf("stored IP = %v, want the unmapped v4 form", snap[0].IP)
	}
}

func TestOffendInvalidAddrIsIgnored(t *testing.T) {
	t.Parallel()
	m, _, fe, fp := newTestManager(t, nil)
	m.Offend("sshd", netip.Addr{}, 5, "")
	if len(fe.banned()) != 0 || fp.calls() != 0 || len(m.Snapshot()) != 0 {
		t.Error("an invalid address must not produce a ban")
	}
}

func TestOffendRepeatHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		onRepeat  string
		factor    float64
		wantUntil time.Duration // from epoch
		wantBans  int           // enforcer Ban calls
		wantSaves int
	}{
		{name: "ignore leaves the live ban alone", onRepeat: OnRepeatIgnore, factor: 2, wantUntil: time.Hour, wantBans: 1, wantSaves: 1},
		{name: "extend pushes until out", onRepeat: OnRepeatExtend, factor: 2, wantUntil: 2 * time.Hour, wantBans: 1, wantSaves: 2},
		// With no escalation there is nothing to extend to: the recomputed
		// deadline is not later than the live one, so the ban is untouched.
		{name: "extend with flat bantime is a no-op", onRepeat: OnRepeatExtend, factor: 1, wantUntil: time.Hour, wantBans: 1, wantSaves: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, clk, fe, fp := newTestManager(t, nil)
			m.SetPolicy("sshd", Policy{
				Bantime: time.Hour, BantimeMax: 24 * time.Hour, FindHistory: 24 * time.Hour,
				Factor: tt.factor, OnRepeat: tt.onRepeat,
			})
			ip := addr(t, "198.51.100.8")
			m.Offend("sshd", ip, 5, "")
			m.Offend("sshd", ip, 9, "")

			snap := m.Snapshot()
			if len(snap) != 1 {
				t.Fatalf("snapshot = %v, want 1 ban", snap)
			}
			if want := epoch.Add(tt.wantUntil); !snap[0].Until.Equal(want) {
				t.Errorf("Until = %v, want %v", snap[0].Until, want)
			}
			if got := len(fe.banned()); got != tt.wantBans {
				t.Errorf("enforcer Ban calls = %d, want %d (an extension must not re-install the rule)", got, tt.wantBans)
			}
			if got := fp.calls(); got != tt.wantSaves {
				t.Errorf("persister calls = %d, want %d", got, tt.wantSaves)
			}
			if len(fe.unbanned()) != 0 {
				t.Error("a repeat offense must never unban")
			}
			_ = clk
		})
	}
}

// TestOffendEscalationAcrossExpiries checks the offense counter survives the
// ban itself: an attacker who comes back after the term gets a longer one.
func TestOffendEscalationAcrossExpiries(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, BantimeMax: 8 * time.Hour, FindHistory: 24 * time.Hour, Factor: 2})
	ip := addr(t, "198.51.100.9")

	want := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 8 * time.Hour}
	for i, w := range want {
		m.Offend("sshd", ip, 5, "")
		snap := m.Snapshot()
		if len(snap) != 1 {
			t.Fatalf("offense %d: snapshot = %v, want 1 ban", i+1, snap)
		}
		if got := snap[0].Until.Sub(clk.Now()); got != w {
			t.Errorf("offense %d: bantime = %v, want %v", i+1, got, w)
		}
		if snap[0].Offense != i+1 {
			t.Errorf("offense %d: Offense field = %d", i+1, snap[0].Offense)
		}
		// Let the ban run out before the next offense.
		clk.Advance(w)
		m.expireAndSchedule()
		if n := len(m.Snapshot()); n != 0 {
			t.Fatalf("offense %d: %d bans still active after expiry", i+1, n)
		}
	}
}

func TestOffendHistoryPrunedByFindHistory(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, BantimeMax: 24 * time.Hour, FindHistory: 4 * time.Hour, Factor: 2})
	ip := addr(t, "198.51.100.10")

	m.Offend("sshd", ip, 5, "")
	clk.Advance(time.Hour)
	m.expireAndSchedule()
	m.Offend("sshd", ip, 5, "") // second offense inside find_history: 2h
	if got := m.Snapshot()[0].Until.Sub(clk.Now()); got != 2*time.Hour {
		t.Fatalf("second offense bantime = %v, want 2h", got)
	}

	// Walk past find_history with no further offenses; the slate is wiped.
	clk.Advance(5 * time.Hour)
	m.expireAndSchedule()
	m.Offend("sshd", ip, 5, "")
	if got := m.Snapshot()[0].Until.Sub(clk.Now()); got != time.Hour {
		t.Errorf("bantime after find_history elapsed = %v, want a first-offense 1h", got)
	}
	if got := m.Snapshot()[0].Offense; got != 1 {
		t.Errorf("Offense = %d, want 1", got)
	}
}

func TestOffendHistoryIsPerMonitor(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	p := Policy{Bantime: time.Hour, BantimeMax: 24 * time.Hour, FindHistory: 24 * time.Hour, Factor: 2}
	m.SetPolicy("sshd", p)
	m.SetPolicy("nginx", p)
	ip := addr(t, "198.51.100.11")

	m.Offend("sshd", ip, 5, "")
	clk.Advance(time.Hour)
	m.expireAndSchedule()
	m.Offend("nginx", ip, 5, "")
	if got := m.Snapshot()[0].Offense; got != 1 {
		t.Errorf("offense under a different monitor = %d, want 1 (history is per monitor)", got)
	}
}

// TestIgnoredRepeatsDoNotEscalate: while a ban is live and OnRepeat is
// "ignore", further threshold crossings must not count as offenses — otherwise
// a flood fast-forwards the attacker to BantimeMax and inflates history.
func TestIgnoredRepeatsDoNotEscalate(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	key := historyKey{ip: addr(t, "198.51.100.12"), monitor: "sshd"}
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, BantimeMax: 100 * time.Hour, FindHistory: 24 * time.Hour, Factor: 2})

	for range 500 {
		m.Offend("sshd", key.ip, 5, "")
	}
	m.mu.Lock()
	n := len(m.history[key])
	m.mu.Unlock()
	if n != 1 {
		t.Errorf("history has %d entries after 500 ignored repeats, want 1", n)
	}

	clk.Advance(time.Hour)
	m.expireAndSchedule()
	m.Offend("sshd", key.ip, 5, "")
	if got := m.Snapshot()[0].Until.Sub(clk.Now()); got != 2*time.Hour {
		t.Errorf("bantime after the flood = %v, want a second-offense 2h", got)
	}
}

func TestOffenseHistoryIsCapped(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	key := historyKey{ip: addr(t, "198.51.100.13"), monitor: "sshd"}
	// Extend mode with a short clamp: every offense commits a history entry.
	m.SetPolicy("sshd", Policy{
		Bantime: time.Hour, BantimeMax: 2 * time.Hour, FindHistory: 1000 * time.Hour,
		Factor: 2, OnRepeat: OnRepeatExtend,
	})
	for range 4 * maxOffenseHistory {
		m.Offend("sshd", key.ip, 5, "")
		clk.Advance(time.Minute) // each offense pushes Until out, so each commits
	}
	m.mu.Lock()
	n := len(m.history[key])
	m.mu.Unlock()
	if n > maxOffenseHistory {
		t.Errorf("history holds %d entries, want at most %d", n, maxOffenseHistory)
	}
	if got := m.Snapshot()[0].Offense; got > maxOffenseHistory+1 {
		t.Errorf("Offense = %d, want it saturated at %d", got, maxOffenseHistory+1)
	}
}
func TestOffendSweepsHistory(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, func(o *Options) { o.Persister = nil })
	m.SetPolicy("sshd", Policy{Bantime: time.Second, BantimeMax: time.Minute, FindHistory: time.Minute, Factor: 1})

	// One offense each from many addresses, then let them all age out and
	// trigger the periodic sweep.
	for i := range historySweepEvery {
		ip := netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})
		m.Offend("sshd", ip, 5, "")
	}
	m.mu.Lock()
	before := len(m.history)
	m.mu.Unlock()
	if before == 0 {
		t.Fatal("no history recorded")
	}

	clk.Advance(2 * time.Minute)
	m.expireAndSchedule()
	// The next offense crosses the sweep counter and prunes the aged entries.
	for range historySweepEvery {
		m.Offend("sshd", addr(t, "203.1.1.1"), 5, "")
	}
	m.mu.Lock()
	after := len(m.history)
	m.mu.Unlock()
	if after >= before {
		t.Errorf("history size = %d after sweep, want well below %d", after, before)
	}
}

func TestManualBanUnban(t *testing.T) {
	t.Parallel()
	m, clk, fe, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: 30 * time.Minute})
	ip := addr(t, "198.51.100.20")

	if err := m.Ban(ip, "manual", 2*time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if got := m.Snapshot()[0].Until; !got.Equal(epoch.Add(2 * time.Hour)) {
		t.Errorf("Until = %v, want epoch+2h", got)
	}

	// d <= 0 falls back to the monitor's Bantime.
	other := addr(t, "198.51.100.21")
	if err := m.Ban(other, "sshd", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if got := m.Snapshot()[0].Until; !got.Equal(epoch.Add(30 * time.Minute)) {
		t.Errorf("Until = %v, want the policy bantime", got)
	}

	if err := m.Unban(ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if err := m.Unban(ip); !errors.Is(err, ErrNotBanned) {
		t.Errorf("second Unban = %v, want ErrNotBanned", err)
	}
	if u := fe.unbanned(); len(u) != 1 || u[0].IP != ip {
		t.Errorf("enforcer unbans = %+v, want one for %v", u, ip)
	}
	m.mu.Lock()
	schedLen := m.sched.Len()
	m.mu.Unlock()
	if schedLen != 1 {
		t.Errorf("heap holds %d entries after an unban, want 1", schedLen)
	}
	_ = clk
}

func TestManualBanNeverShortens(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	ip := addr(t, "198.51.100.22")
	if err := m.Ban(ip, "manual", 10*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.Ban(ip, "manual", time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := m.Snapshot()[0].Until; !got.Equal(epoch.Add(10 * time.Hour)) {
		t.Errorf("Until = %v, want the longer term to stand", got)
	}
}

func TestUnbanAll(t *testing.T) {
	t.Parallel()
	m, _, fe, fp := newTestManager(t, nil)
	for i := range 10 {
		if err := m.Ban(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "manual", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	saves := fp.calls()
	if err := m.UnbanAll(); err != nil {
		t.Fatalf("UnbanAll: %v", err)
	}
	if n := len(m.Snapshot()); n != 0 {
		t.Errorf("%d bans left after UnbanAll", n)
	}
	if n := len(fe.unbanned()); n != 10 {
		t.Errorf("enforcer unbans = %d, want 10", n)
	}
	if got := fp.calls() - saves; got != 1 {
		t.Errorf("UnbanAll wrote state %d times, want 1", got)
	}
	m.mu.Lock()
	schedLen := m.sched.Len()
	m.mu.Unlock()
	if schedLen != 0 {
		t.Errorf("heap holds %d entries after UnbanAll", schedLen)
	}
	// UnbanAll on an empty manager must be harmless.
	if err := m.UnbanAll(); err != nil {
		t.Errorf("UnbanAll on empty manager: %v", err)
	}
}

func TestSnapshotIsSortedAndCopied(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	for i, d := range []time.Duration{3 * time.Hour, time.Hour, 2 * time.Hour} {
		if err := m.Ban(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "manual", d); err != nil {
			t.Fatal(err)
		}
	}
	snap := m.Snapshot()
	for i := 1; i < len(snap); i++ {
		if snap[i].Until.Before(snap[i-1].Until) {
			t.Fatalf("snapshot not sorted by Until: %v", snap)
		}
	}
	// Mutating the copy must not be visible internally.
	snap[0].Monitor = "tampered"
	snap[0].Until = epoch
	if got := m.Snapshot()[0]; got.Monitor == "tampered" || got.Until.Equal(epoch) {
		t.Error("Snapshot aliases internal state")
	}
}

func TestPersistFailureKeepsBanEnforced(t *testing.T) {
	t.Parallel()
	m, _, fe, fp := newTestManager(t, nil)
	fp.setErr(errors.New("disk on fire"))
	ip := addr(t, "198.51.100.30")

	err := m.Ban(ip, "manual", time.Hour)
	if err == nil {
		t.Error("Ban should report the persistence failure")
	}
	if len(m.Snapshot()) != 1 {
		t.Error("ban was rolled back by a persistence failure")
	}
	if len(fe.banned()) != 1 {
		t.Error("ban was not enforced")
	}
	if got := m.Stats().PersistFailures; got != 1 {
		t.Errorf("Stats().PersistFailures = %d, want 1", got)
	}

	// Offend must swallow the error entirely rather than stall the pipeline.
	m.SetPolicy("sshd", Policy{Bantime: time.Hour})
	m.Offend("sshd", addr(t, "198.51.100.31"), 5, "")
	if len(m.Snapshot()) != 2 {
		t.Error("Offend dropped a ban because persistence failed")
	}
	if got := m.Stats().PersistFailures; got != 2 {
		t.Errorf("Stats().PersistFailures = %d, want 2", got)
	}
}

// TestPersistSkipsStaleSnapshot proves the sequence guard: a snapshot that
// loses the race to a newer one is dropped, not written after it.
func TestPersistSkipsStaleSnapshot(t *testing.T) {
	t.Parallel()
	m, _, _, fp := newTestManager(t, nil)
	newer := []model.Ban{{Monitor: "newer"}}
	older := []model.Ban{{Monitor: "older"}}
	if err := m.persist(5, newer); err != nil {
		t.Fatal(err)
	}
	if err := m.persist(3, older); err != nil {
		t.Fatal(err)
	}
	if fp.calls() != 1 {
		t.Fatalf("persister calls = %d, want 1", fp.calls())
	}
	if fp.last()[0].Monitor != "newer" {
		t.Error("a stale snapshot overwrote newer state")
	}
}

func TestNilEnforcerAndPersister(t *testing.T) {
	t.Parallel()
	m := NewManager(Options{Now: newFakeClock().Now, Log: discardLogger()})
	if err := m.Ban(addr(t, "198.51.100.40"), "manual", time.Hour); err != nil {
		t.Fatalf("Ban with no enforcer/persister: %v", err)
	}
	if err := m.Unban(addr(t, "198.51.100.40")); err != nil {
		t.Fatalf("Unban with no enforcer/persister: %v", err)
	}
}

func TestRestore(t *testing.T) {
	t.Parallel()
	live := func(ip string, d time.Duration) model.Ban {
		return model.Ban{IP: netip.MustParseAddr(ip), Monitor: "sshd", At: epoch.Add(-time.Minute), Until: epoch.Add(d), Offense: 1}
	}

	m, clk, fe, fp := newTestManager(t, func(o *Options) {
		o.AllowLocal = true
		o.Allowlist = []netip.Prefix{prefix(t, "192.168.0.0/16")}
	})
	m.SetPolicy("sshd", Policy{Bantime: time.Hour})

	in := []model.Ban{
		live("198.51.100.1", time.Hour),
		live("198.51.100.2", -time.Minute),              // expired
		live("198.51.100.3", 0),                         // exactly now: expired
		{IP: netip.MustParseAddr("198.51.100.4")},       // zero Until
		live("198.51.100.1", 2*time.Hour),               // duplicate, longer
		live("198.51.100.1", time.Minute),               // duplicate, shorter
		live("192.168.1.1", time.Hour),                  // newly allowlisted
		live("127.0.0.1", time.Hour),                    // loopback
		{IP: netip.Addr{}, Until: epoch.Add(time.Hour)}, // invalid
		{IP: netip.MustParseAddr("::ffff:198.51.100.5"), Monitor: "gone", Until: epoch.Add(time.Hour)}, // unknown monitor, v4-in-v6
	}
	if err := m.Restore(in); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	snap := m.Snapshot()
	got := map[string]time.Time{}
	for _, b := range snap {
		got[b.IP.String()] = b.Until
	}
	want := map[string]time.Time{
		"198.51.100.1": epoch.Add(2 * time.Hour), // longest duplicate wins
		"198.51.100.5": epoch.Add(time.Hour),     // unknown monitor still enforced
	}
	if len(got) != len(want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	for ip, until := range want {
		if !got[ip].Equal(until) {
			t.Errorf("%s restored with Until %v, want %v", ip, got[ip], until)
		}
	}
	// Expired and allowlisted records are pushed to the firewall as unbans so
	// a stale rule from a previous run cannot survive.
	if n := len(fe.unbanned()); n != 5 {
		t.Errorf("enforcer unbans = %d, want 5 (3 expired + 2 allowlisted)", n)
	}
	if fp.calls() != 1 {
		t.Errorf("persister calls = %d, want 1 for the whole restore", fp.calls())
	}

	// Expiry must be scheduled, not just recorded.
	clk.Advance(61 * time.Minute)
	m.expireAndSchedule()
	if n := len(m.Snapshot()); n != 1 {
		t.Errorf("%d bans active after the 1h one expired, want 1", n)
	}
}

func TestRestoreIsIdempotent(t *testing.T) {
	t.Parallel()
	m, _, fe, _ := newTestManager(t, nil)
	in := []model.Ban{{IP: addr(t, "198.51.100.1"), Monitor: "sshd", At: epoch, Until: epoch.Add(time.Hour), Offense: 3}}

	for range 3 {
		if err := m.Restore(in); err != nil {
			t.Fatalf("Restore: %v", err)
		}
	}
	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot = %v, want 1 ban", snap)
	}
	if snap[0].Offense != 3 {
		t.Errorf("Offense = %d, want the persisted 3", snap[0].Offense)
	}
	// The first Restore installs the rule; the repeats change nothing and so
	// must not re-issue it (iptables -I would stack duplicate rules).
	if n := len(fe.banned()); n != 1 {
		t.Errorf("enforcer bans = %d, want 1 across three identical Restores", n)
	}
	m.mu.Lock()
	schedLen := m.sched.Len()
	m.mu.Unlock()
	if schedLen != 1 {
		t.Errorf("heap holds %d entries, want 1", schedLen)
	}
}

func TestRestoreOverExistingBanKeepsLongest(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	ip := addr(t, "198.51.100.1")
	if err := m.Ban(ip, "manual", 10*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore([]model.Ban{{IP: ip, Monitor: "sshd", Until: epoch.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if got := m.Snapshot()[0].Until; !got.Equal(epoch.Add(10 * time.Hour)) {
		t.Errorf("Until = %v, want the longer live ban to stand", got)
	}
}

// TestExpiryBatchIsOneWakeup is the thundering-herd guard: ten thousand bans
// with the same deadline cost one pass and one state write.
func TestExpiryBatchIsOneWakeup(t *testing.T) {
	t.Parallel()
	m, clk, fe, fp := newTestManager(t, nil)

	const n = 10000
	in := make([]model.Ban, 0, n)
	for i := range n {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		in = append(in, model.Ban{IP: ip, Monitor: "sshd", At: epoch, Until: epoch.Add(time.Hour), Offense: 1})
	}
	if err := m.Restore(in); err != nil {
		t.Fatal(err)
	}
	if got := len(m.Snapshot()); got != n {
		t.Fatalf("restored %d bans, want %d", got, n)
	}
	saves := fp.calls()

	clk.Advance(time.Hour)
	wait := m.expireAndSchedule()

	if got := len(m.Snapshot()); got != 0 {
		t.Errorf("%d bans left after the batch expired", got)
	}
	if got := len(fe.unbanned()); got != n {
		t.Errorf("enforcer unbans = %d, want %d", got, n)
	}
	if got := fp.calls() - saves; got != 1 {
		t.Errorf("state written %d times for the batch, want 1", got)
	}
	if wait != idleWait {
		t.Errorf("wait with an empty heap = %v, want the idle sentinel %v", wait, idleWait)
	}
	if got := m.Stats().Expired; got != n {
		t.Errorf("Stats().Expired = %d, want %d", got, n)
	}
}

// TestExpireAndScheduleArmsAtHead pins the single-timer behaviour: the wait
// returned is always the time to the earliest expiry.
func TestExpireAndScheduleArmsAtHead(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)

	if got := m.expireAndSchedule(); got != idleWait {
		t.Errorf("empty heap wait = %v, want %v", got, idleWait)
	}
	if err := m.Ban(addr(t, "198.51.100.1"), "manual", 3*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := m.expireAndSchedule(); got != 3*time.Hour {
		t.Errorf("wait = %v, want 3h", got)
	}
	// A later-arriving ban that expires sooner must pull the wait in.
	if err := m.Ban(addr(t, "198.51.100.2"), "manual", time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := m.expireAndSchedule(); got != time.Minute {
		t.Errorf("wait = %v, want the new earliest expiry of 1m", got)
	}
	clk.Advance(90 * time.Second)
	if got := m.expireAndSchedule(); got != 3*time.Hour-90*time.Second {
		t.Errorf("wait after the first expiry = %v, want the next head", got)
	}
	// A ban already in the past must not produce a negative wait (busy loop).
	m.mu.Lock()
	m.bans[addr(t, "198.51.100.3")] = model.Ban{IP: addr(t, "198.51.100.3"), Until: epoch}
	m.sched.schedule(addr(t, "198.51.100.3"), epoch)
	m.mu.Unlock()
	if got := m.expireAndSchedule(); got < 0 {
		t.Errorf("wait = %v, must never be negative", got)
	}
}

// TestExpireToleratesStaleHeapEntry covers the defensive path: if an entry
// ever loses sync with its ban record, the address is re-scheduled rather than
// released early.
func TestExpireToleratesStaleHeapEntry(t *testing.T) {
	t.Parallel()
	m, clk, fe, _ := newTestManager(t, nil)
	ip := addr(t, "198.51.100.50")
	if err := m.Ban(ip, "manual", 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.sched.index[ip].until = epoch // entry now claims an expiry in the past
	// Also plant an orphan entry with no ban record at all.
	m.sched.schedule(addr(t, "198.51.100.51"), epoch)
	m.mu.Unlock()

	clk.Advance(time.Minute)
	wait := m.expireAndSchedule()

	if len(fe.unbanned()) != 0 {
		t.Error("a stale entry released a live ban early")
	}
	if n := len(m.Snapshot()); n != 1 {
		t.Fatalf("%d bans active, want 1", n)
	}
	if want := epoch.Add(2 * time.Hour).Sub(clk.Now()); wait != want {
		t.Errorf("wait = %v, want %v (re-armed at the real deadline)", wait, want)
	}
}

func TestRunExpiresAndStops(t *testing.T) {
	t.Parallel()
	m, clk, fe, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, FindHistory: 24 * time.Hour, Factor: 1})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	ip := addr(t, "198.51.100.60")
	m.Offend("sshd", ip, 5, "")
	if _, ok := <-fe.banCh; !ok {
		t.Fatal("no ban enforced")
	}

	// Nothing should expire before the term is up.
	advance(clk, m, 59*time.Minute)
	select {
	case b := <-fe.unbanCh:
		t.Fatalf("premature unban of %v", b.IP)
	case <-time.After(20 * time.Millisecond):
	}

	advance(clk, m, 2*time.Minute)
	if got := fe.waitUnban(t); got.IP != ip {
		t.Errorf("unbanned %v, want %v", got.IP, ip)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRunRearmsWhenAnEarlierBanArrives(t *testing.T) {
	t.Parallel()
	m, clk, fe, _ := newTestManager(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()

	long := addr(t, "198.51.100.70")
	short := addr(t, "198.51.100.71")
	if err := m.Ban(long, "manual", 10*time.Hour); err != nil {
		t.Fatal(err)
	}
	<-fe.banCh
	if err := m.Ban(short, "manual", time.Minute); err != nil {
		t.Fatal(err)
	}
	<-fe.banCh

	advance(clk, m, 2*time.Minute)
	if got := fe.waitUnban(t); got.IP != short {
		t.Errorf("unbanned %v, want the earlier-expiring %v", got.IP, short)
	}
	if n := len(m.Snapshot()); n != 1 {
		t.Errorf("%d bans active, want the long one to remain", n)
	}
}

func TestRunRejectsASecondCall(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	// Wait for the first Run to claim the manager before contending with it.
	// Calling Run any earlier would *succeed* and then block forever, because
	// Run is the expiry loop itself and only returns on ctx.Done — the previous
	// version of this test retried in a loop and deadlocked for the full test
	// timeout whenever the scheduler ran the test goroutine first.
	for !m.running.Load() {
		runtime.Gosched()
	}

	if err := m.Run(ctx); !errors.Is(err, ErrRunning) {
		t.Fatalf("second Run = %v, want ErrRunning", err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("first Run = %v, want nil", err)
	}
}

func TestStats(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, func(o *Options) { o.AllowLocal = true })
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, FindHistory: 24 * time.Hour, Factor: 2, OnRepeat: OnRepeatExtend})

	m.Offend("sshd", addr(t, "127.0.0.1"), 5, "")
	m.Offend("sshd", addr(t, "198.51.100.80"), 5, "")
	m.Offend("sshd", addr(t, "198.51.100.80"), 5, "") // extends
	if err := m.Ban(addr(t, "198.51.100.81"), "manual", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := m.Unban(addr(t, "198.51.100.81")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(3 * time.Hour)
	m.expireAndSchedule()

	got := m.Stats()
	want := Stats{Active: 0, Banned: 2, Extended: 1, Unbanned: 1, Expired: 1, Allowlisted: 1}
	if got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

func TestSetPolicyFallback(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	m.SetPolicy("", Policy{Bantime: 15 * time.Minute, FindHistory: time.Hour, Factor: 1})

	m.Offend("monitor-that-was-removed", addr(t, "198.51.100.90"), 5, "")
	if got := m.Snapshot()[0].Until.Sub(clk.Now()); got != 15*time.Minute {
		t.Errorf("bantime = %v, want the fallback policy's 15m", got)
	}

	// With no policy at all, the package defaults apply.
	m2, clk2, _, _ := newTestManager(t, nil)
	m2.Offend("unknown", addr(t, "198.51.100.91"), 5, "")
	if got := m2.Snapshot()[0].Until.Sub(clk2.Now()); got != defaultBantime {
		t.Errorf("bantime = %v, want the default %v", got, defaultBantime)
	}
}

func TestZeroPolicyNeverProducesAnInstantBan(t *testing.T) {
	t.Parallel()
	m, clk, _, _ := newTestManager(t, nil)
	m.SetPolicy("sshd", Policy{}) // e.g. a config bug upstream
	m.Offend("sshd", addr(t, "198.51.100.92"), 5, "")
	b := m.Snapshot()[0]
	if !b.Until.After(clk.Now()) {
		t.Fatalf("ban expires at %v, which is not after now %v", b.Until, clk.Now())
	}
}

func ExampleManager_Allowed() {
	m := NewManager(Options{
		AllowLocal: true,
		Interfaces: func() ([]netip.Prefix, error) { return nil, nil },
	})
	fmt.Println(m.Allowed(netip.MustParseAddr("::ffff:127.0.0.1")))
	fmt.Println(m.Allowed(netip.MustParseAddr("198.51.100.1")))
	// Output:
	// true
	// false
}
