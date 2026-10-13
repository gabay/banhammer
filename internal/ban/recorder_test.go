package ban

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
)

type fakeRecorder struct {
	mu   sync.Mutex
	bans []model.Ban
}

func (r *fakeRecorder) Record(b model.Ban) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bans = append(r.bans, b)
}

func (r *fakeRecorder) recorded() []model.Ban {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.Ban(nil), r.bans...)
}

// TestRecorderHearsExactlyNewBans pins the Recorder contract: one call per
// new ban, whether automatic or manual, and none for an extension, a repeat
// that changes nothing, a restore, or an allowlisted address. The ledger
// behind the status page counts these calls, so over-reporting here would
// turn every restart into a fake attack wave on the chart.
func TestRecorderHearsExactlyNewBans(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	m, clk, _, _ := newTestManager(t, func(o *Options) {
		o.Recorder = rec
		o.Allowlist = []netip.Prefix{prefix(t, "10.0.0.0/8")}
	})
	m.SetPolicy("sshd", Policy{Bantime: time.Hour, OnRepeat: OnRepeatExtend, Factor: 2, BantimeMax: 24 * time.Hour, FindHistory: 24 * time.Hour})

	// 1. automatic ban
	m.Offend("sshd", addr(t, "203.0.113.1"), 5, "p")
	// 2. repeat while live: extension, not a new ban
	m.Offend("sshd", addr(t, "203.0.113.1"), 7, "p")
	// 3. allowlisted: nothing
	m.Offend("sshd", addr(t, "10.1.2.3"), 5, "p")
	// 4. manual ban of a fresh address
	if err := m.Ban(addr(t, "203.0.113.2"), "manual", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	// 5. manual re-ban of a live address: record update only
	if err := m.Ban(addr(t, "203.0.113.2"), "manual", 5*time.Hour); err != nil {
		t.Fatalf("Ban again: %v", err)
	}
	// 6. restore: never recorded
	if err := m.Restore([]model.Ban{{IP: addr(t, "203.0.113.3"), Monitor: "sshd", At: clk.Now(), Until: clk.Now().Add(time.Hour)}}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	got := rec.recorded()
	if len(got) != 2 {
		t.Fatalf("recorded %d bans, want 2: %+v", len(got), got)
	}
	if got[0].IP != addr(t, "203.0.113.1") || got[0].Monitor != "sshd" || got[0].Count != 5 || !got[0].At.Equal(clk.Now()) {
		t.Errorf("first record = %+v", got[0])
	}
	if got[1].IP != addr(t, "203.0.113.2") || got[1].Monitor != "manual" || got[1].Offense != 1 {
		t.Errorf("second record = %+v", got[1])
	}

	// 7. after expiry, the same address offending again is a new ban.
	clk.Advance(48 * time.Hour)
	m.expireAndSchedule()
	m.Offend("sshd", addr(t, "203.0.113.1"), 5, "p")
	if got := rec.recorded(); len(got) != 3 {
		t.Fatalf("after expiry recorded %d bans, want 3", len(got))
	}
}

// TestRecorderIsOptional guards the nil path: `banhammer test` builds a
// manager without one.
func TestRecorderIsOptional(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, nil)
	m.Offend("sshd", addr(t, "203.0.113.1"), 5, "p")
	if err := m.Ban(addr(t, "203.0.113.2"), "manual", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if got := m.Stats().Banned; got != 2 {
		t.Errorf("Banned = %d, want 2", got)
	}
}
