package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"banhammer/internal/model"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func sampleBans(t *testing.T) []model.Ban {
	t.Helper()
	at := time.Date(2024, 2, 29, 23, 59, 58, 123456789, time.FixedZone("IST", 2*3600))
	return []model.Ban{
		{IP: mustAddr(t, "1.2.3.4"), Monitor: "sshd", At: at, Until: at.Add(time.Hour), Count: 5, Offense: 1},
		{IP: mustAddr(t, "2001:db8::dead:beef"), Monitor: "nginx", At: at.UTC(), Until: at.UTC().Add(48 * time.Hour), Count: 12, Offense: 3},
		{IP: mustAddr(t, "::ffff:10.0.0.9"), Monitor: "postfix", At: at, Until: at.Add(time.Minute), Count: 1, Offense: 1},
	}
}

func TestOpenCreatesDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nested", "state")

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close() //nolint:errcheck // asserted below via explicit Close in other tests

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("state dir is not a directory")
	}
	// The exact bits depend on the test runner's umask; owner access is the
	// invariant that matters.
	if fi.Mode().Perm()&0o700 != 0o700 {
		t.Errorf("state dir mode = %v, want at least rwx for owner", fi.Mode().Perm())
	}
	if s.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", s.Dir(), dir)
	}
	if _, err := os.Stat(filepath.Join(dir, lockFileName)); err != nil {
		t.Errorf("lock file missing: %v", err)
	}
}

func TestOpenRejectsEmptyDir(t *testing.T) {
	t.Parallel()
	if _, err := Open(""); err == nil {
		t.Fatal("Open(\"\") succeeded, want error")
	}
}

func TestOpenExclusive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	first, err := Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	// flock is per open file description, so even the same process is denied.
	_, err = Open(dir)
	if err == nil {
		t.Fatal("second Open succeeded, want ErrLocked")
	}
	if !errors.Is(err, ErrLocked) {
		t.Errorf("second Open error = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not name the state directory %q", err, dir)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Closing must hand the directory back.
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close second: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
}

func TestOpenReadOnlyParent(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	base := t.TempDir()
	ro := filepath.Join(base, "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) }) // so TempDir cleanup can remove it

	t.Run("cannot create state dir", func(t *testing.T) {
		target := filepath.Join(ro, "state")
		_, err := Open(target)
		if err == nil {
			t.Fatal("Open succeeded on a read-only parent")
		}
		if !strings.Contains(err.Error(), target) || !errors.Is(err, os.ErrPermission) {
			t.Errorf("error = %v, want a permission error naming %q", err, target)
		}
	})

	t.Run("cannot take lock", func(t *testing.T) {
		_, err := Open(ro)
		if err == nil {
			t.Fatal("Open succeeded on a read-only state dir")
		}
		if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), lockFileName) {
			t.Errorf("error = %v, want a permission error about the lock file", err)
		}
	})
}

func TestLoadBansMissingFile(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())

	bans, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("LoadBans on a fresh dir = %v, want none", bans)
	}
}

func TestSaveLoadBansRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := sampleBans(t)

	s, _, _, _ := newTestStore(t, dir)
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close() //nolint:errcheck // nothing pending
	got, err := reopened.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
}

func assertBansEqual(t *testing.T, got, want []model.Ban) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d bans, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.IP != w.IP || g.Monitor != w.Monitor || g.Count != w.Count || g.Offense != w.Offense {
			t.Errorf("ban %d = %+v, want %+v", i, g, w)
		}
		assertTimeEqual(t, fmt.Sprintf("ban %d At", i), g.At, w.At)
		assertTimeEqual(t, fmt.Sprintf("ban %d Until", i), g.Until, w.Until)
	}
}

func assertTimeEqual(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
	if got.Format(time.RFC3339Nano) != want.Format(time.RFC3339Nano) {
		t.Errorf("%s zone offset lost: %s vs %s", what,
			got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

func TestSaveBansEmptySliceRoundTrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)

	if err := s.SaveBans(nil); err != nil {
		t.Fatalf("SaveBans(nil): %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, BansFile))
	if err != nil {
		t.Fatalf("read bans file: %v", err)
	}
	// "null" would be legal JSON but is a nuisance for anyone reading or
	// hand-editing the file.
	if !strings.Contains(string(data), `"bans": []`) {
		t.Errorf("empty state rendered as %s, want an empty array", data)
	}
	bans, err := s.LoadBans()
	if err != nil || len(bans) != 0 {
		t.Fatalf("LoadBans = %v, %v; want empty, nil", bans, err)
	}
}

func TestLoadBansSeesPendingWrite(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	want := sampleBans(t)

	// Nothing is on disk yet (the debounce timer has not fired), but a reader
	// must still observe the latest state.
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
}

func TestSaveBansCopiesInput(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())
	bans := sampleBans(t)

	if err := s.SaveBans(bans); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	bans[0].Monitor = "mutated-after-save"
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rec.countFor(BansFile); got != 1 {
		t.Fatalf("writes = %d, want 1", got)
	}
	persisted, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if persisted[0].Monitor != "sshd" {
		t.Errorf("caller mutation leaked into the store: %q", persisted[0].Monitor)
	}
}

func TestDebounceCoalescesAndFlushKeepsFinalState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, sched, rec := newTestStore(t, dir)

	for i := 1; i <= 3; i++ {
		b := []model.Ban{{
			IP:      mustAddr(t, fmt.Sprintf("10.0.0.%d", i)),
			Monitor: "sshd",
			At:      time.Unix(int64(i), 0).UTC(),
			Until:   time.Unix(int64(i)+60, 0).UTC(),
			Count:   i,
			Offense: 1,
		}}
		if err := s.SaveBans(b); err != nil {
			t.Fatalf("SaveBans #%d: %v", i, err)
		}
	}
	if got := rec.countFor(BansFile); got != 0 {
		t.Fatalf("writes before flush = %d, want 0 (debounced)", got)
	}
	if got := sched.count(); got != 1 {
		t.Fatalf("timers scheduled = %d, want 1 shared timer", got)
	}

	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rec.countFor(BansFile); got != 1 {
		t.Fatalf("writes after Flush = %d, want exactly 1", got)
	}
	// The cancelled timer must not produce a second, stale write.
	if fired := sched.fireAll(); fired != 0 {
		t.Errorf("timer fired %d times after Flush, want 0", fired)
	}
	if got := rec.countFor(BansFile); got != 1 {
		t.Errorf("writes = %d after stale timer, want 1", got)
	}

	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(got) != 1 || got[0].IP.String() != "10.0.0.3" {
		t.Errorf("persisted state = %+v, want only the final save", got)
	}
}

func TestDebounceRateLimit(t *testing.T) {
	t.Parallel()
	s, clk, sched, rec := newTestStore(t, t.TempDir())
	bans := sampleBans(t)

	// First save: nothing written recently, so the timer is armed for "now".
	if err := s.SaveBans(bans[:1]); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if d := sched.lastDelay(t); d != 0 {
		t.Errorf("first debounce delay = %v, want 0", d)
	}
	if n := sched.fireAll(); n != 1 {
		t.Fatalf("fired %d timers, want 1", n)
	}
	if got := rec.countFor(BansFile); got != 1 {
		t.Fatalf("writes = %d, want 1", got)
	}

	// Second save in the same instant must be deferred by a full interval.
	clk.Advance(200 * time.Millisecond)
	if err := s.SaveBans(bans[:2]); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if got := rec.countFor(BansFile); got != 1 {
		t.Fatalf("writes = %d, want the second save to be held back", got)
	}
	if d := sched.lastDelay(t); d != DefaultBanInterval-200*time.Millisecond {
		t.Errorf("debounce delay = %v, want %v", d, DefaultBanInterval-200*time.Millisecond)
	}

	clk.Advance(800 * time.Millisecond)
	sched.fireAll()
	if got := rec.countFor(BansFile); got != 2 {
		t.Fatalf("writes = %d, want 2", got)
	}
	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("persisted %d bans, want 2", len(got))
	}
}

func TestFlushWithoutPendingWritesNothing(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())

	for i := 0; i < 3; i++ {
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	if got := rec.countFor(BansFile); got != 0 {
		t.Errorf("writes = %d, want 0", got)
	}
}

func TestSaveBansWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, sched, rec := newTestStore(t, dir)
	rec.setFail(syscall.ENOSPC)

	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans should not fail synchronously: %v", err)
	}
	sched.fireAll() // the deferred write hits the full disk

	// The failure is reported to the next caller rather than swallowed...
	err := s.SaveBans(sampleBans(t)[:1])
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("SaveBans error = %v, want ENOSPC reported from the deferred write", err)
	}
	// ...and only once.
	if err := s.Flush(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("Flush error = %v, want the retry to fail too", err)
	}

	// The daemon keeps running: once the disk recovers, the latest state is
	// still there to be written.
	rec.setFail(nil)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}
	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("persisted %d bans, want the 1 held in memory across the failure", len(got))
	}
}

func TestSaveOffsetsFailurePropagates(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())
	rec.setFail(syscall.ENOSPC)

	err := s.SaveOffsets(map[string]model.Checkpoint{
		"/var/log/auth.log": {Path: "/var/log/auth.log", Dev: 1, Inode: 2, Offset: 3},
	})
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("SaveOffsets error = %v, want ENOSPC", err)
	}
	// A failed write must not change what Lookup reports; otherwise the
	// daemon would believe a checkpoint survived a restart when it did not.
	if _, ok := s.Lookup("/var/log/auth.log"); ok {
		t.Error("Lookup reports a checkpoint that was never persisted")
	}
}

func TestOffsetsRoundTripAndLookup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := map[string]model.Checkpoint{
		"/var/log/auth.log":  {Path: "/var/log/auth.log", Dev: 66306, Inode: 12345, Offset: 4096},
		"/var/log/nginx.log": {Path: "/var/log/nginx.log", Dev: 66306, Inode: 999, Offset: 0},
	}

	s, _, _, _ := newTestStore(t, dir)
	if err := s.SaveOffsets(want); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close() //nolint:errcheck // read-only use
	got, err := reopened.LoadOffsets()
	if err != nil {
		t.Fatalf("LoadOffsets: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("loaded %d offsets, want %d", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("offset %q = %+v, want %+v", k, got[k], w)
		}
	}

	// Lookup works right after Open, before any explicit LoadOffsets call.
	cp, ok := reopened.Lookup("/var/log/auth.log")
	if !ok {
		t.Fatal("Lookup(/var/log/auth.log) = not found")
	}
	if cp != want["/var/log/auth.log"] {
		t.Errorf("Lookup = %+v, want %+v", cp, want["/var/log/auth.log"])
	}
	if _, ok := reopened.Lookup("/var/log/nope.log"); ok {
		t.Error("Lookup of an unknown path reported found")
	}
	if cp, ok := reopened.Lookup("/var/log/nginx.log"); !ok || cp.Inode != 999 {
		t.Errorf("Lookup(/var/log/nginx.log) = %+v, %v; want the seeded checkpoint", cp, ok)
	}
	// Matching must be on the whole path, not on a suffix or basename.
	if _, ok := reopened.Lookup("auth.log"); ok {
		t.Error("Lookup matched a basename rather than the full path")
	}

}

func TestLoadOffsetsReturnsCopy(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	cp := model.Checkpoint{Path: "/a.log", Dev: 1, Inode: 2, Offset: 3}
	if err := s.SaveOffsets(map[string]model.Checkpoint{"/a.log": cp}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	got, err := s.LoadOffsets()
	if err != nil {
		t.Fatalf("LoadOffsets: %v", err)
	}
	delete(got, "/a.log")
	if _, ok := s.Lookup("/a.log"); !ok {
		t.Error("mutating the returned map affected the store")
	}
}

func TestLookupPathIndexedByCheckpointPath(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	// Key and path differ (a monitor-keyed map); Lookup must use the path.
	if err := s.SaveOffsets(map[string]model.Checkpoint{
		"sshd":   {Path: "/var/log/auth.log", Inode: 7, Offset: 12},
		"keyed":  {Inode: 8, Offset: 13},
		"nginx2": {Path: "/var/log/nginx.log", Inode: 9, Offset: 14},
	}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if cp, ok := s.Lookup("/var/log/auth.log"); !ok || cp.Inode != 7 {
		t.Errorf("Lookup by path = %+v, %v", cp, ok)
	}
	if _, ok := s.Lookup("sshd"); ok {
		t.Error("Lookup matched a map key whose checkpoint names a different path")
	}
	// An entry with no path falls back to its key, which is all we can do.
	if cp, ok := s.Lookup("keyed"); !ok || cp.Inode != 8 {
		t.Errorf("Lookup of pathless entry = %+v, %v", cp, ok)
	}
}

func TestCorruptStateFiles(t *testing.T) {
	t.Parallel()
	truncated := `{"version":1,"bans":[{"ip":"1.2.3.4","monitor":"ssh`

	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace", "   \n"},
		{"truncated mid json", truncated},
		{"random bytes", "\x00\xff\x11\xfeqp\x9c\x00garbage\x7f"},
		{"wrong shape", `[1,2,3]`},
		{"bare null", `null`},
		{"unknown version", `{"version":99,"bans":[]}`},
		{"html error page", "<html><body>503</body></html>"},
	}

	for _, tc := range tests {
		t.Run("bans/"+tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, BansFile)
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}

			s, _, _, _ := newTestStore(t, dir)
			bans, err := s.LoadBans()
			if err != nil {
				t.Fatalf("LoadBans on corrupt file must not fail: %v", err)
			}
			if len(bans) != 0 {
				t.Fatalf("LoadBans = %v, want empty state", bans)
			}
			assertQuarantined(t, dir, BansFile, tc.content)

			// The daemon carries on and can persist new state.
			if err := s.SaveBans(sampleBans(t)); err != nil {
				t.Fatalf("SaveBans after corruption: %v", err)
			}
			if err := s.Flush(); err != nil {
				t.Fatalf("Flush after corruption: %v", err)
			}
			if got, err := s.LoadBans(); err != nil || len(got) != 3 {
				t.Fatalf("LoadBans after recovery = %v, %v", got, err)
			}
		})

		t.Run("offsets/"+tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, OffsetsFile)
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}

			// Corruption is detected at Open; it must not stop the daemon.
			s, _, _, _ := newTestStore(t, dir)
			offsets, err := s.LoadOffsets()
			if err != nil {
				t.Fatalf("LoadOffsets on corrupt file must not fail: %v", err)
			}
			if len(offsets) != 0 {
				t.Fatalf("LoadOffsets = %v, want empty state", offsets)
			}
			if _, ok := s.Lookup("/var/log/auth.log"); ok {
				t.Error("Lookup found a checkpoint from a corrupt file")
			}
			assertQuarantined(t, dir, OffsetsFile, tc.content)

			if err := s.SaveOffsets(map[string]model.Checkpoint{
				"/x.log": {Path: "/x.log", Offset: 1},
			}); err != nil {
				t.Fatalf("SaveOffsets after corruption: %v", err)
			}
			if _, ok := s.Lookup("/x.log"); !ok {
				t.Error("store unusable after corruption recovery")
			}
		})
	}
}

// assertQuarantined checks the evidence was preserved, not deleted.
func assertQuarantined(t *testing.T, dir, base, want string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, base)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s still present after quarantine (err=%v)", base, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, base+CorruptSuffix))
	if err != nil {
		t.Fatalf("corrupt file not preserved: %v", err)
	}
	if string(got) != want {
		t.Errorf("quarantined content = %q, want the original %q", got, want)
	}
}

func TestQuarantineOverwritesPreviousCorruptFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, BansFile+CorruptSuffix), []byte("older"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, BansFile), []byte("newer garbage"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, _, _, _ := newTestStore(t, dir)
	if _, err := s.LoadBans(); err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertQuarantined(t, dir, BansFile, "newer garbage")
}

func TestQuarantineFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, BansFile), []byte("garbage"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, _, _, _ := newTestStore(t, dir) // takes the lock while the dir is still writable

	// Renaming the corrupt file aside will now fail. Losing the evidence must
	// still not take the daemon down.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) // let TempDir clean up

	bans, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans = %v, want a degraded but successful load", err)
	}
	if len(bans) != 0 {
		t.Errorf("LoadBans = %v, want empty state", bans)
	}
}

func TestLoadBansDropsInvalidEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `{"version":1,"bans":[
	  {"ip":"","monitor":"broken","at":"2024-01-01T00:00:00Z","until":"2024-01-01T01:00:00Z"},
	  {"ip":"9.9.9.9","monitor":"ok","at":"2024-01-01T00:00:00Z","until":"2024-01-01T01:00:00Z","count":2,"offense":1}
	]}`
	if err := os.WriteFile(filepath.Join(dir, BansFile), []byte(content), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, _, _, _ := newTestStore(t, dir)
	bans, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(bans) != 1 || bans[0].Monitor != "ok" {
		t.Fatalf("LoadBans = %+v, want only the valid entry", bans)
	}
	// One bad entry is not grounds for discarding the whole file.
	if _, err := os.Stat(filepath.Join(dir, BansFile+CorruptSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Error("file was quarantined for a single bad entry")
	}
}

func TestLoadBansUnreadableFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, BansFile)
	if err := os.WriteFile(path, []byte(`{"version":1,"bans":[]}`), 0o000); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, _, _, _ := newTestStore(t, dir)

	// Unreadable is not the same as corrupt: we must not quarantine a file we
	// cannot even read, and the caller deserves the error.
	if _, err := s.LoadBans(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("LoadBans error = %v, want a permission error", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("unreadable file was moved aside: %v", err)
	}
}

func TestOperationsAfterClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := s.LoadBans(); !errors.Is(err, ErrClosed) {
		t.Errorf("LoadBans = %v, want ErrClosed", err)
	}
	if err := s.SaveBans(nil); !errors.Is(err, ErrClosed) {
		t.Errorf("SaveBans = %v, want ErrClosed", err)
	}
	if _, err := s.LoadOffsets(); !errors.Is(err, ErrClosed) {
		t.Errorf("LoadOffsets = %v, want ErrClosed", err)
	}
	if err := s.SaveOffsets(nil); !errors.Is(err, ErrClosed) {
		t.Errorf("SaveOffsets = %v, want ErrClosed", err)
	}
	// A closed store no longer owns the directory: writing now could clobber
	// the state of whichever daemon took the lock next.
	if err := s.Flush(); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush = %v, want ErrClosed", err)
	}

	if _, ok := s.Lookup("/x"); ok {
		t.Error("Lookup after Close reported found")
	}
}

func TestCloseFlushesPendingBans(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	clk := newFakeClock()
	sched := &fakeScheduler{}
	s, err := OpenWith(dir, Options{Log: discardLogger(), Now: clk.Now, AfterFunc: sched.AfterFunc})
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	want := sampleBans(t)
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close() //nolint:errcheck // read-only use
	got, err := reopened.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
}

func TestSynchronousMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenWith(dir, Options{Log: discardLogger(), BanInterval: -1})
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close() //nolint:errcheck // nothing pending in synchronous mode
	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, BansFile)); err != nil {
		t.Fatalf("synchronous save did not hit the disk: %v", err)
	}
}

func TestStateFilesAreHumanReadable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	if err := s.SaveOffsets(map[string]model.Checkpoint{"/a.log": {Path: "/a.log", Offset: 7}}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, OffsetsFile))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasSuffix(string(data), "}\n") {
		t.Errorf("state file should be newline-terminated, got %q", data)
	}
	if !json.Valid(data) {
		t.Errorf("state file is not valid JSON: %s", data)
	}
	if !strings.Contains(string(data), "\n  \"version\": 1") {
		t.Errorf("state file is not indented: %s", data)
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	s, _, sched, _ := newTestStore(t, t.TempDir())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				ip := netip.AddrFrom4([4]byte{10, byte(i), byte(j), 1})
				if err := s.SaveBans([]model.Ban{{IP: ip, Monitor: "m", Count: j}}); err != nil {
					t.Errorf("SaveBans: %v", err)
					return
				}
				if err := s.SaveOffsets(map[string]model.Checkpoint{
					"/a.log": {Path: "/a.log", Offset: int64(j)},
				}); err != nil {
					t.Errorf("SaveOffsets: %v", err)
					return
				}
				s.Lookup("/a.log")
				sched.fireAll()
				if _, err := s.LoadBans(); err != nil {
					t.Errorf("LoadBans: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
