package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"banhammer/internal/model"
)

// --- Shutdown must never hand a state directory to another daemon while the
// newest bans exist only in this process's memory.

func TestCloseFailureKeepsLockAndIsSticky(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, _, _, rec := newTestStore(t, dir)
	want := sampleBans(t)

	rec.setFail(syscall.ENOSPC)
	if err := a.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}

	err := a.Close()
	if err == nil {
		t.Fatal("Close succeeded although the final write failed")
	}
	if !errors.Is(err, ErrNotPersisted) || !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("Close error = %v, want it to wrap both ErrNotPersisted and ENOSPC", err)
	}

	// The lock must still be held: another daemon starting now would write
	// over state that only exists in this process's memory.
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open while a failed-to-close store holds state = %v, want ErrLocked", err)
	}

	// Sticky: a second Close must not look like success.
	if err := a.Close(); !errors.Is(err, ErrNotPersisted) {
		t.Fatalf("second Close = %v, want the same failure", err)
	}

	// Disk recovers: now Close works, and only now is the directory released.
	rec.setFail(nil)
	if err := a.Close(); err != nil {
		t.Fatalf("Close after recovery: %v", err)
	}
	// And the store really is closed afterwards.
	if err := a.Flush(); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush after a successful Close = %v, want ErrClosed", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after the first store finally closed: %v", err)
	}
	defer b.Close() //nolint:errcheck // read-only use
	got, err := b.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
}

// TestClosedStoreCannotClobberAnotherDaemon is the concrete regression: a
// closed store must not write into a directory another process now owns.
func TestClosedStoreCannotClobberAnotherDaemon(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	a, _, _, _ := newTestStore(t, dir)
	if err := a.SaveBans(sampleBans(t)[:1]); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("second daemon Open: %v", err)
	}
	defer b.Close() //nolint:errcheck // read-only use
	bState := sampleBans(t)
	if err := b.SaveBans(bState); err != nil {
		t.Fatalf("b.SaveBans: %v", err)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("b.Flush: %v", err)
	}

	// The zombie store tries to flush. It must refuse, not overwrite.
	if err := a.Flush(); !errors.Is(err, ErrClosed) {
		t.Fatalf("zombie Flush = %v, want ErrClosed", err)
	}
	got, err := b.LoadBans()
	if err != nil {
		t.Fatalf("b.LoadBans: %v", err)
	}
	assertBansEqual(t, got, bState)
}

func TestCloseDoesNotReportAStaleFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, sched, rec := newTestStore(t, dir)
	want := sampleBans(t)

	rec.setFail(syscall.ENOSPC)
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	sched.fireAll() // the deferred write fails and is remembered

	rec.setFail(nil)
	// The state is about to become durable, so Close must report success:
	// the caller has to be able to tell "data lost" from "an old write
	// failed, everything is fine now".
	if err := s.Close(); err != nil {
		t.Fatalf("Close = %v, want nil once the state is durable", err)
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

func TestFlushDoesNotReportAStaleFailure(t *testing.T) {
	t.Parallel()
	s, _, sched, rec := newTestStore(t, t.TempDir())

	rec.setFail(syscall.ENOSPC)
	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	sched.fireAll()

	rec.setFail(nil)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush = %v, want nil once the write goes through", err)
	}
	// The cleared failure must not resurface on the next call either.
	if err := s.SaveBans(sampleBans(t)[:1]); err != nil {
		t.Fatalf("SaveBans after recovery = %v, want nil", err)
	}
}

// --- Bounded self-healing retries.

func TestDeferredWriteRetriesWithBackoff(t *testing.T) {
	t.Parallel()
	s, _, sched, rec := newTestStore(t, t.TempDir())
	want := sampleBans(t)

	rec.setFail(syscall.ENOSPC)
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}

	// Attempt 1 fails; a retry must be armed rather than leaving the state
	// stranded in memory until some future save that may never come.
	if n := sched.fireAll(); n != 1 {
		t.Fatalf("fired %d timers, want 1", n)
	}
	if got, want := sched.lastDelay(t), DefaultBanInterval; got != want {
		t.Errorf("first retry delay = %v, want %v", got, want)
	}
	if n := sched.fireAll(); n != 1 {
		t.Fatalf("no retry was scheduled after the first failure")
	}
	if got, want := sched.lastDelay(t), 2*DefaultBanInterval; got != want {
		t.Errorf("second retry delay = %v, want exponential backoff %v", got, want)
	}

	rec.setFail(nil)
	if n := sched.fireAll(); n != 1 {
		t.Fatalf("no third attempt was scheduled")
	}
	if got := rec.countFor(BansFile); got != 3 {
		t.Errorf("write attempts = %d, want 3 (two failures and the successful retry)", got)
	}
	// Success ends the chain.
	if n := sched.fireAll(); n != 0 {
		t.Errorf("%d timers still armed after a successful write, want 0", n)
	}
	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
}

func TestDeferredWriteRetriesAreCapped(t *testing.T) {
	t.Parallel()
	s, _, sched, rec := newTestStore(t, t.TempDir())
	rec.setFail(syscall.ENOSPC)

	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	fired := 0
	for i := 0; i < maxWriteRetries+5; i++ {
		fired += sched.fireAll()
	}
	if want := maxWriteRetries + 1; fired != want {
		t.Errorf("attempts = %d, want %d (the initial write plus %d retries)", fired, want, maxWriteRetries)
	}
	if got := rec.countFor(BansFile); got != maxWriteRetries+1 {
		t.Errorf("writes = %d, want %d", got, maxWriteRetries+1)
	}

	// Giving up must not wedge the store: the next save starts a fresh chain,
	// and the pending state was never dropped.
	rec.setFail(nil)
	if err := s.SaveBans(sampleBans(t)[:1]); !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("SaveBans = %v, want the remembered failure reported once", err)
	}
	if n := sched.fireAll(); n != 1 {
		t.Fatalf("a new save did not re-arm the timer")
	}
	if got, err := s.LoadBans(); err != nil || len(got) != 1 {
		t.Fatalf("LoadBans = %v, %v; want the state to have survived", got, err)
	}
}

func TestRetryBackoffIsCapped(t *testing.T) {
	t.Parallel()
	s, _, sched, rec := newTestStore(t, t.TempDir(), func(o *Options) {
		o.BanInterval = 20 * time.Second // 20s << 4 would be 320s without the cap
	})
	rec.setFail(syscall.ENOSPC)

	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	for i := 0; i < maxWriteRetries+1; i++ {
		sched.fireAll()
	}
	if d := sched.lastDelay(t); d > maxRetryDelay {
		t.Errorf("retry delay = %v, want at most %v", d, maxRetryDelay)
	}
}

// --- Two monitors watching one log file is a normal configuration, so Lookup
// must resolve the collision the same way every time.

func TestLookupCollisionPrefersTheFurthestOffset(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())

	const path = "/var/log/auth.log"
	offsets := map[string]model.Checkpoint{
		"sshd":        {Path: path, Dev: 1, Inode: 2, Offset: 1},
		"sshd-strict": {Path: path, Dev: 1, Inode: 2, Offset: 100000},
		"sshd-extra":  {Path: path, Dev: 1, Inode: 2, Offset: 500},
	}

	// Rebuild the index many times: map iteration order must not leak into
	// the answer. Re-reading a few lines is survivable; skipping them is not.
	for i := 0; i < 200; i++ {
		s.setOffsets(offsets)
		cp, ok := s.Lookup(path)
		if !ok {
			t.Fatalf("iteration %d: Lookup(%q) not found", i, path)
		}
		if cp.Offset != 100000 {
			t.Fatalf("iteration %d: Lookup = offset %d, want the largest (100000)", i, cp.Offset)
		}
	}
}

func TestLookupCollisionTieIsStable(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())

	const path = "/var/log/auth.log"
	offsets := map[string]model.Checkpoint{
		"aaa": {Path: path, Inode: 1, Offset: 42},
		"bbb": {Path: path, Inode: 2, Offset: 42},
		"ccc": {Path: path, Inode: 3, Offset: 42},
	}
	s.setOffsets(offsets)
	first, ok := s.Lookup(path)
	if !ok {
		t.Fatal("Lookup not found")
	}
	for i := 0; i < 200; i++ {
		s.setOffsets(offsets)
		got, _ := s.Lookup(path)
		if got != first {
			t.Fatalf("iteration %d: Lookup = %+v, want the stable %+v", i, got, first)
		}
	}
	// Sorted key order decides the tie, so the answer is also predictable.
	if first.Inode != 1 {
		t.Errorf("tie resolved to inode %d, want the first key in sorted order", first.Inode)
	}
}

func TestLookupPrefersExactKeyMatch(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	const path = "/var/log/auth.log"
	s.setOffsets(map[string]model.Checkpoint{
		// The daemon keys by path; that entry must win over an alias that
		// happens to name the same file with a bigger offset.
		path:    {Path: path, Inode: 7, Offset: 10},
		"alias": {Path: path, Inode: 7, Offset: 99},
	})
	cp, ok := s.Lookup(path)
	if !ok || cp.Offset != 10 {
		t.Errorf("Lookup = %+v, %v; want the entry stored under the path key", cp, ok)
	}
}

// --- Debris from a write that was interrupted by a crash must be cleaned up
// at Open, and only debris.

func TestOpenSweepsInterruptedWriteDebris(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	debris := []string{
		BansFile + tempPrefix + "123456",
		OffsetsFile + tempPrefix + "abcdef",
	}
	keep := []string{BansFile, OffsetsFile + CorruptSuffix, "notes.txt"}
	for _, name := range append(append([]string{}, debris...), keep...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"version":1,"bans":[]}`), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	s, _, _, _ := newTestStore(t, dir)
	_ = s // Open did the sweep

	for _, name := range debris {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the sweep (err=%v)", name, err)
		}
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed by the sweep: %v", name, err)
		}
	}
}

func TestRenameFailureDebrisIsSweptAtNextOpen(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)

	// An unwritable directory lets CreateTemp fail outright on most systems,
	// so simulate the harder case directly: a temp file whose rename never
	// happened.
	tmp := filepath.Join(dir, BansFile+tempPrefix+"999")
	if err := os.WriteFile(tmp, []byte("half a write"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close() //nolint:errcheck // read-only use
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("leftover temp file survived Open (err=%v)", err)
	}
}

// --- Values that parse but cannot be true (a ban that expires before it
// started, a negative file offset) are dropped or clamped at this boundary so
// downstream code never has to defend itself against them.

func TestLoadClampsHostileValues(t *testing.T) {
	t.Parallel()

	t.Run("ban expiring before it started is dropped", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		content := `{"version":1,"bans":[
		  {"ip":"1.1.1.1","monitor":"backwards","at":"2024-01-02T00:00:00Z","until":"2024-01-01T00:00:00Z"},
		  {"ip":"2.2.2.2","monitor":"instant","at":"2024-01-01T00:00:00Z","until":"2024-01-01T00:00:00Z"},
		  {"ip":"3.3.3.3","monitor":"ok","at":"2024-01-01T00:00:00Z","until":"2024-01-01T01:00:00Z"}
		]}`
		if err := os.WriteFile(filepath.Join(dir, BansFile), []byte(content), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		s, _, _, _ := newTestStore(t, dir)
		bans, err := s.LoadBans()
		if err != nil {
			t.Fatalf("LoadBans: %v", err)
		}
		// The zero-length ban is legal (already expired); the reversed one is not.
		if len(bans) != 2 {
			t.Fatalf("got %d bans (%v), want 2", len(bans), bans)
		}
		for _, b := range bans {
			if b.Monitor == "backwards" {
				t.Error("kept a ban whose Until precedes its At")
			}
		}
	})

	t.Run("negative offset is clamped", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		content := `{"version":1,"offsets":{
		  "/a.log":{"path":"/a.log","dev":1,"inode":2,"offset":-9223372036854775808},
		  "/b.log":{"path":"/b.log","dev":1,"inode":3,"offset":17}
		}}`
		if err := os.WriteFile(filepath.Join(dir, OffsetsFile), []byte(content), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		s, _, _, _ := newTestStore(t, dir)

		cp, ok := s.Lookup("/a.log")
		if !ok {
			t.Fatal("Lookup(/a.log) not found")
		}
		if cp.Offset != 0 {
			t.Errorf("offset = %d, want it clamped to 0", cp.Offset)
		}
		if cp, ok := s.Lookup("/b.log"); !ok || cp.Offset != 17 {
			t.Errorf("valid neighbour was disturbed: %+v, %v", cp, ok)
		}
		loaded, err := s.LoadOffsets()
		if err != nil {
			t.Fatalf("LoadOffsets: %v", err)
		}
		if loaded["/a.log"].Offset != 0 {
			t.Errorf("LoadOffsets offset = %d, want 0", loaded["/a.log"].Offset)
		}
	})
}

// --- A state file far larger than anything this daemon writes is garbage,
// and must be refused before it is read into memory.

func TestOversizedStateFileIsQuarantined(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	s.maxFileSize = 64 // keeps the test cheap; the production cap is 64 MiB

	big := `{"version":1,"bans":[]}` + strings.Repeat(" ", 1024)
	if err := os.WriteFile(filepath.Join(dir, BansFile), []byte(big), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	bans, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans on an oversized file must not fail: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("LoadBans = %v, want empty state", bans)
	}
	assertQuarantined(t, dir, BansFile, big)
}

// TestMaxStateFileSizeIsPinned guards the constant itself: the number is part
// of the daemon's memory bound, so a change to it should be a deliberate edit
// here and not a side effect of some other work.
func TestMaxStateFileSizeIsPinned(t *testing.T) {
	t.Parallel()
	if MaxStateFileSize != 64<<20 {
		t.Errorf("MaxStateFileSize = %d, want 64 MiB", MaxStateFileSize)
	}
}

// TestOversizedOffsetsFileIsQuarantinedAtOpen covers the path no LoadOffsets
// call can reach: offsets.json is read inside Open, so an unreadable one has
// to be quarantined there or the daemon never starts. The cap is injected
// rather than exceeded — a 64 MiB fixture would be absurd in a unit test.
func TestOversizedOffsetsFileIsQuarantinedAtOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := `{"version":1,"offsets":{"/a.log":{"path":"/a.log","offset":7}}}`
	if err := os.WriteFile(filepath.Join(dir, OffsetsFile), []byte(big), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s, _, _, _ := newTestStore(t, dir, func(o *Options) { o.maxFileSize = 16 })
	offsets, err := s.LoadOffsets()
	if err != nil {
		t.Fatalf("LoadOffsets: %v", err)
	}
	if len(offsets) != 0 {
		t.Errorf("offsets = %v, want empty state after quarantine", offsets)
	}
	if _, ok := s.Lookup("/a.log"); ok {
		t.Error("Lookup answered from a file that was too large to read")
	}
	assertQuarantined(t, dir, OffsetsFile, big)

	// The daemon carries on: a fresh save works and is what a restart sees.
	if err := s.SaveOffsets(map[string]model.Checkpoint{"/b.log": {Path: "/b.log", Offset: 1}}); err != nil {
		t.Fatalf("SaveOffsets after quarantine: %v", err)
	}
	if _, ok := s.Lookup("/b.log"); !ok {
		t.Error("store unusable after an oversized file was set aside")
	}
}

// TestLargeButUnderCapOffsetsFileIsRead is the other side of the cap: 1 MiB is
// nowhere near 64 MiB, so the file must be parsed, not set aside. It used to
// be named as if it asserted a quarantine and would have passed with the size
// logic deleted.
func TestLargeButUnderCapOffsetsFileIsRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Padding inside the JSON, so the file is genuinely large and genuinely
	// parseable.
	big := `{"version":1,"offsets":{"/a.log":{"path":"/a.log","offset":4096}}}` +
		strings.Repeat(" ", 1<<20)
	if err := os.WriteFile(filepath.Join(dir, OffsetsFile), []byte(big), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s, _, _, _ := newTestStore(t, dir)
	offsets, err := s.LoadOffsets()
	if err != nil {
		t.Fatalf("LoadOffsets: %v", err)
	}
	if len(offsets) != 1 || offsets["/a.log"].Offset != 4096 {
		t.Errorf("offsets = %+v, want the checkpoint from the file", offsets)
	}
	if cp, ok := s.Lookup("/a.log"); !ok || cp.Offset != 4096 {
		t.Errorf("Lookup = %+v, %v; want the checkpoint from the file", cp, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, OffsetsFile+CorruptSuffix)); err == nil {
		t.Error("a 1 MiB file was quarantined although it is far under the cap")
	}
}

func TestReadCappedRejectsGrowingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	s.maxFileSize = 8

	path := filepath.Join(dir, "grow.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 100)), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.readCapped(path); !errors.Is(err, errTooLarge) {
		t.Fatalf("readCapped = %v, want errTooLarge", err)
	}
	if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	data, err := s.readCapped(path)
	if err != nil {
		t.Fatalf("readCapped: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("readCapped = %q, want %q", data, "ok")
	}
}

// TestErrorsAreDistinguishable pins the sentinel contract the daemon's
// shutdown path depends on.
func TestErrorsAreDistinguishable(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())
	rec.setFail(fmt.Errorf("wrapped: %w", syscall.EROFS))

	if err := s.SaveOffsets(map[string]model.Checkpoint{"/a": {Path: "/a"}}); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("SaveOffsets error = %v, want ErrNotPersisted", err)
	} else if !errors.Is(err, syscall.EROFS) {
		t.Errorf("SaveOffsets error = %v, want the cause preserved", err)
	}
	if err := s.SaveBans(sampleBans(t)); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	err := s.Flush()
	if !errors.Is(err, ErrNotPersisted) || !errors.Is(err, syscall.EROFS) {
		t.Errorf("Flush error = %v, want ErrNotPersisted wrapping EROFS", err)
	}
	if errors.Is(err, ErrClosed) {
		t.Error("a write failure must not look like a closed store")
	}
}

// TestDirFsyncFailureIsNotCalledDataLoss pins the weaker sentinel. A rename
// that landed but could not be fsynced leaves the new state visible to the
// next reader; calling that "not persisted" would make the shutdown path
// refuse to release a directory whose contents are in fact correct.
func TestDirFsyncFailureIsNotCalledDataLoss(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())
	// What atomicWrite reports when only the directory fsync fails.
	rec.setFail(fmt.Errorf("durability of bans.json: %w: %w", ErrNotDurable, syscall.EIO))

	err := s.SaveOffsets(map[string]model.Checkpoint{"/a": {Path: "/a"}})
	if !errors.Is(err, ErrNotDurable) {
		t.Errorf("error = %v, want ErrNotDurable", err)
	}
	if errors.Is(err, ErrNotPersisted) {
		t.Errorf("error = %v, want it *not* to claim the state is only in memory", err)
	}
	if !errors.Is(err, syscall.EIO) {
		t.Errorf("error = %v, want the cause preserved", err)
	}
	// The two sentinels must stay distinguishable in both directions.
	if errors.Is(ErrNotDurable, ErrNotPersisted) || errors.Is(ErrNotPersisted, ErrNotDurable) {
		t.Error("ErrNotDurable and ErrNotPersisted are not distinguishable")
	}
}

// --- Repeated problems must be summarised, not repeated: PROJECT.md §4.9
// asks for rate-limited logging, and one bad file can hold 50k bad entries.

func TestDroppedBanEntriesAreReportedInOneLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	const badEntries = 500
	var b strings.Builder
	b.WriteString(`{"version":1,"bans":[`)
	for i := 0; i < badEntries; i++ {
		fmt.Fprintf(&b, `{"ip":"","monitor":"broken","at":"2024-01-01T00:00:00Z","until":"2024-01-01T01:00:00Z"},`)
	}
	b.WriteString(`{"ip":"8.8.8.8","monitor":"backwards","at":"2024-01-02T00:00:00Z","until":"2024-01-01T00:00:00Z"},`)
	b.WriteString(`{"ip":"9.9.9.9","monitor":"ok","at":"2024-01-01T00:00:00Z","until":"2024-01-01T01:00:00Z"}]}`)
	if err := os.WriteFile(filepath.Join(dir, BansFile), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	logs := &logCapture{}
	s, _, _, _ := newTestStore(t, dir, func(o *Options) { o.Log = logs.logger() })
	bans, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	if len(bans) != 1 || bans[0].Monitor != "ok" {
		t.Fatalf("LoadBans = %+v, want only the valid entry", bans)
	}

	records := logs.withMessage("dropped unusable ban entries")
	if len(records) != 1 {
		t.Fatalf("logged %d lines for %d unusable entries, want exactly 1", len(records), badEntries+1)
	}
	for _, tc := range []struct {
		key  string
		want any
	}{
		{"dropped", int64(badEntries + 1)},
		{"kept", int64(1)},
		{"invalid_address", int64(badEntries)},
		{"expires_before_start", int64(1)},
	} {
		if got := attr(records[0], tc.key); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.key, got, tc.want)
		}
	}
	// A count with no example is not actionable.
	if got, _ := attr(records[0], "example").(string); got == "" {
		t.Error("the summary carries no example of what was dropped")
	}
}

func TestCheckpointClashIsLoggedOncePerResolution(t *testing.T) {
	t.Parallel()
	const (
		path = "/var/log/auth.log"
		msg  = "several checkpoints name the same file; resuming from the furthest one"
	)
	logs := &logCapture{}
	s, _, _, _ := newTestStore(t, t.TempDir(), func(o *Options) { o.Log = logs.logger() })

	// Two monitors tailing one file, both advancing: the daemon saves this
	// every 5s for as long as it runs.
	for i := 1; i <= 5; i++ {
		if err := s.SaveOffsets(map[string]model.Checkpoint{
			"sshd":        {Path: path, Offset: int64(10 * i)},
			"sshd-strict": {Path: path, Offset: int64(1000 * i)},
		}); err != nil {
			t.Fatalf("SaveOffsets #%d: %v", i, err)
		}
	}
	records := logs.withMessage(msg)
	if len(records) != 1 {
		t.Fatalf("logged %d warnings for 5 saves of the same clash, want 1", len(records))
	}
	if got, want := attr(records[0], "kept_key"), "sshd-strict"; got != want {
		t.Errorf("kept_key = %v, want %v", got, want)
	}
	if got, want := attr(records[0], "kept_offset"), int64(1000); got != want {
		t.Errorf("kept_offset = %v, want %v", got, want)
	}
	if got, want := attr(records[0], "discarded_offset"), int64(10); got != want {
		t.Errorf("discarded_offset = %v, want %v", got, want)
	}
	// The old pair logged both numbers under one key, which left the reader
	// guessing which one was used.
	if got := attr(records[0], "offsets"); got != nil {
		t.Errorf("offsets = %v, want the two values under distinct keys", got)
	}

	// A different entry winning is news; the same one winning again is not.
	logs.reset()
	if err := s.SaveOffsets(map[string]model.Checkpoint{
		"sshd":        {Path: path, Offset: 99999},
		"sshd-strict": {Path: path, Offset: 5000},
	}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if n := len(logs.withMessage(msg)); n != 1 {
		t.Errorf("logged %d warnings when the winner changed, want 1", n)
	}
	if got, want := attr(logs.withMessage(msg)[0], "kept_key"), "sshd"; got != want {
		t.Errorf("kept_key = %v, want %v", got, want)
	}

	logs.reset()
	if err := s.SaveOffsets(map[string]model.Checkpoint{
		"sshd":        {Path: path, Offset: 100000},
		"sshd-strict": {Path: path, Offset: 5000},
	}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if n := len(logs.withMessage(msg)); n != 0 {
		t.Errorf("logged %d warnings for an unchanged resolution, want 0", n)
	}

	// A clash that goes away and comes back is worth hearing about again.
	logs.reset()
	if err := s.SaveOffsets(map[string]model.Checkpoint{
		"sshd": {Path: path, Offset: 100000},
	}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if n := len(logs.withMessage(msg)); n != 0 {
		t.Errorf("logged %d warnings with only one monitor left, want 0", n)
	}
	if err := s.SaveOffsets(map[string]model.Checkpoint{
		"sshd":        {Path: path, Offset: 100000},
		"sshd-strict": {Path: path, Offset: 200000},
	}); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	if n := len(logs.withMessage(msg)); n != 1 {
		t.Errorf("logged %d warnings when the clash returned, want 1", n)
	}
}
