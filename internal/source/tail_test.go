package source

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"strings"
	"testing"
	"time"

	"banhammer/internal/model"
)

// fakeLookup is a CheckpointLookup backed by a map.
type fakeLookup map[string]model.Checkpoint

func (f fakeLookup) Lookup(path string) (model.Checkpoint, bool) {
	cp, ok := f[path]
	return cp, ok
}

// newTestTail builds a tail with test-scale intervals. notify controls whether
// fsnotify is used; tests that need a deterministic wakeup turn it off and
// drive the tailer with nudge.
func newTestTail(t *testing.T, pattern, startAt string, cp CheckpointLookup, notify bool) (*tail, *countingHandler) {
	t.Helper()
	log, h := testLogger()
	s, err := NewTail("mon", pattern, startAt, cp, log)
	if err != nil {
		t.Fatalf("NewTail: %v", err)
	}
	tl := s.(*tail)
	tl.poll = 10 * time.Millisecond
	tl.rescan = 20 * time.Millisecond
	tl.useNotify = notify
	return tl, h
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

func inodeOf(t *testing.T, path string) fileID {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	id, err := statID(fi)
	if err != nil {
		t.Fatalf("statID %s: %v", path, err)
	}
	return id
}

// waitTailer blocks until the tail has started a tailer for path.
func waitTailer(t *testing.T, tl *tail, path string) *fileTailer {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		tl.mu.Lock()
		ft := tl.files[path]
		tl.mu.Unlock()
		if ft != nil {
			return ft
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no tailer for %s appeared", path)
	return nil
}

func TestNewTailValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		monitor string
		pattern string
		startAt string
		wantErr string
	}{
		{name: "ok", monitor: "m", pattern: "/tmp/x.log", startAt: "end"},
		{name: "default start_at", monitor: "m", pattern: "/tmp/x.log", startAt: ""},
		{name: "empty monitor", pattern: "/tmp/x.log", wantErr: "monitor name is empty"},
		{name: "empty pattern", monitor: "m", wantErr: "file pattern is empty"},
		{name: "bad start_at", monitor: "m", pattern: "/tmp/x.log", startAt: "middle", wantErr: "unknown start_at"},
		{name: "bad glob", monitor: "m", pattern: "/tmp/[a-.log", wantErr: "bad glob"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewTail(tc.monitor, tc.pattern, tc.startAt, nil, nil)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("NewTail = %v, want nil", err)
			case tc.wantErr == "":
				if s.Name() != tc.monitor {
					t.Errorf("Name = %q, want %q", s.Name(), tc.monitor)
				}
				if cps := s.Checkpoints(); cps != nil {
					t.Errorf("Checkpoints before Run = %v, want nil", cps)
				}
			case err == nil:
				t.Fatalf("NewTail = nil, want error containing %q", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("NewTail = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestTailStartAt(t *testing.T) {
	t.Parallel()
	const existing = "old1\nold2\n"

	tests := []struct {
		name    string
		startAt string
		// lookup builds the checkpoint map once the file exists.
		lookup func(path string, id fileID) fakeLookup
		want   []string
	}{
		{
			name:    "beginning replays the file",
			startAt: startAtBeginning,
			want:    []string{"old1", "old2", "new1"},
		},
		{
			name:    "end skips history",
			startAt: startAtEnd,
			want:    []string{"new1"},
		},
		{
			name:    "checkpoint with no store falls back to end",
			startAt: startAtCheckpoint,
			want:    []string{"new1"},
		},
		{
			name:    "checkpoint unknown path falls back to end",
			startAt: startAtCheckpoint,
			lookup:  func(string, fileID) fakeLookup { return fakeLookup{} },
			want:    []string{"new1"},
		},
		{
			name:    "checkpoint resumes mid-file",
			startAt: startAtCheckpoint,
			lookup: func(p string, id fileID) fakeLookup {
				return fakeLookup{p: {Path: p, Dev: id.dev, Inode: id.ino, Offset: 5}}
			},
			want: []string{"old2", "new1"},
		},
		{
			name:    "checkpoint inode mismatch falls back to end",
			startAt: startAtCheckpoint,
			lookup: func(p string, id fileID) fakeLookup {
				return fakeLookup{p: {Path: p, Dev: id.dev, Inode: id.ino + 1, Offset: 5}}
			},
			want: []string{"new1"},
		},
		{
			name:    "checkpoint past end restarts from zero",
			startAt: startAtCheckpoint,
			lookup: func(p string, id fileID) fakeLookup {
				return fakeLookup{p: {Path: p, Dev: id.dev, Inode: id.ino, Offset: 9999}}
			},
			want: []string{"old1", "old2", "new1"},
		},
		{
			// A hand-edited or corrupted offsets.json. Seeking to a negative
			// offset fails outright, so it has to be clamped.
			name:    "negative checkpoint offset restarts from zero",
			startAt: startAtCheckpoint,
			lookup: func(p string, id fileID) fakeLookup {
				return fakeLookup{p: {Path: p, Dev: id.dev, Inode: id.ino, Offset: -5}}
			},
			want: []string{"old1", "old2", "new1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "app.log")
			writeFile(t, path, existing)

			var lookup CheckpointLookup
			if tc.lookup != nil {
				lookup = tc.lookup(path, inodeOf(t, path))
			}
			tl, _ := newTestTail(t, path, tc.startAt, lookup, true)
			h := start(t, tl)
			// Make sure the initial open has happened before appending, so
			// "new1" is genuinely new data rather than part of the file at
			// open time.
			waitTailer(t, tl, path)
			waitOffsetSet(t, tl, path)

			appendFile(t, path, "new1\n")
			got := h.lines(len(tc.want))
			if !equalStrings(got, tc.want) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
			h.expectQuiet()
		})
	}
}

// waitOffsetSet waits until the tailer has published a checkpoint, which only
// happens after the file has been opened and positioned.
func waitOffsetSet(t *testing.T, tl *tail, path string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		tl.mu.Lock()
		_, ok := tl.saved[path]
		tl.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("tailer never published a checkpoint for %s", path)
}

// TestTailRotationDrain is the deterministic version of the rotation test:
// fsnotify is off and the poll interval is effectively infinite, so the tailer
// is guaranteed to be asleep while the rotation is staged. It then wakes to
// find unread bytes in the renamed file *and* a new file at the path, which is
// exactly the case where a naive tailer drops lines.
func TestTailRotationDrain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "a1\n")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, false)
	tl.poll = time.Hour // only manual nudges advance the tailer
	h := start(t, tl)
	ft := waitTailer(t, tl, path)

	if got := h.lines(1); !equalStrings(got, []string{"a1"}) {
		t.Fatalf("lines = %q, want [a1]", got)
	}

	// Stage the rotation while the tailer sleeps: more data lands in the old
	// inode after the rename, then a fresh file takes the path.
	rotated := filepath.Join(dir, "app.log.1")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename: %v", err)
	}
	appendFile(t, rotated, "a2\na3\n")
	writeFile(t, path, "b1\nb2\n")

	ft.nudge()
	got := h.lines(4)
	want := []string{"a2", "a3", "b1", "b2"}
	if !equalStrings(got, want) {
		t.Fatalf("lines = %q, want %q (old-file tail must be drained before switching)", got, want)
	}
	h.expectQuiet()
}

// TestTailRotationLive exercises rotation with fsnotify enabled: repeated
// rename+create cycles at machine speed, asserting every line arrives exactly
// once and in order.
//
// Each generation is consumed before the next rotation, which is what a real
// logrotate run looks like (rotations are hours apart). Rotating twice within
// a single wake cycle is a known, documented limitation — see the tail doc
// comment — so the test does not pretend otherwise.
func TestTailRotationLive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	for gen := range 3 {
		var want []string
		for i := range 5 {
			line := fmt.Sprintf("gen%d-line%d", gen, i)
			appendFile(t, path, line+"\n")
			want = append(want, line)
		}
		if got := h.lines(len(want)); !equalStrings(got, want) {
			t.Fatalf("generation %d: lines = %q, want %q", gen, got, want)
		}
		if err := os.Rename(path, filepath.Join(dir, fmt.Sprintf("app.log.%d", gen))); err != nil {
			t.Fatalf("rename: %v", err)
		}
		// logrotate's create step: the writer gets a brand new inode.
		writeFile(t, path, "")
	}
	appendFile(t, path, "final\n")
	if got := h.lines(1); !equalStrings(got, []string{"final"}) {
		t.Fatalf("lines = %q, want [final]", got)
	}
	h.expectQuiet()
}

func TestTailTruncation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "one\ntwo\n")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	if got := h.lines(2); !equalStrings(got, []string{"one", "two"}) {
		t.Fatalf("lines = %q", got)
	}

	// `cp /dev/null app.log` keeps the inode and resets the size.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	appendFile(t, path, "three\n")

	if got := h.lines(1); !equalStrings(got, []string{"three"}) {
		t.Fatalf("after truncation lines = %q, want [three]", got)
	}
	h.expectQuiet()
}

// A writer that flushes one byte at a time must never produce a partial line.
func TestTailPartialLines(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	want := []string{
		"Failed password for root from 10.0.0.1 port 22",
		"Failed password for root from 10.0.0.2 port 22",
		"Accepted password for alice from 10.0.0.3 port 22",
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, line := range want {
		for _, b := range []byte(line + "\n") {
			if _, err := f.Write([]byte{b}); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got := h.lines(len(want))
	if !equalStrings(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	h.expectQuiet()
}

func TestTailOversizedLine(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	huge := strings.Repeat("x", maxLineBytes+5000) + "SNEAKY"
	appendFile(t, path, huge+"\nshort\n")

	got := h.lines(2)
	if len(got[0]) != maxLineBytes {
		t.Errorf("first line length = %d, want %d (truncate, never drop)", len(got[0]), maxLineBytes)
	}
	if got[1] != "short" {
		t.Errorf("second line = %q, want %q (the rest of the huge line must be swallowed)", got[1], "short")
	}
	h.expectQuiet()
}

func TestTailMissingFileWarnsOnceThenFollows(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "later.log")

	tl, h2 := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)

	// Wait for the tailer to have actually looked for the file and given up
	// on it, rather than sleeping for a duration that is simultaneously too
	// long here and too short on a loaded machine.
	waitFor(t, "the missing-file warning", func() bool {
		return h2.count(slog.LevelWarn, "does not exist") >= 1
	})
	// Let a few more poll cycles go by with the file still absent, so the
	// "once" in warn-once is really being tested.
	for range 3 {
		waitTailer(t, tl, path).nudge()
	}
	writeFile(t, path, "hello\n")

	if got := h.lines(1); !equalStrings(got, []string{"hello"}) {
		t.Fatalf("lines = %q, want [hello]", got)
	}
	if n := h2.count(slog.LevelWarn, "does not exist"); n != 1 {
		t.Errorf("missing-file warnings = %d, want exactly 1", n)
	}
}

func TestTailGlob(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	writeFile(t, a, "a-old\n")

	tl, _ := newTestTail(t, filepath.Join(dir, "*.log"), startAtBeginning, nil, true)
	h := start(t, tl)
	if got := h.lines(1); !equalStrings(got, []string{"a-old"}) {
		t.Fatalf("lines = %q, want [a-old]", got)
	}

	// A file that appears later is picked up by the rescan, from its start.
	b := filepath.Join(dir, "b.log")
	writeFile(t, b, "b-1\n")
	if got := h.lines(1); !equalStrings(got, []string{"b-1"}) {
		t.Fatalf("lines = %q, want [b-1]", got)
	}

	// A rescan must not replay a.log; only the new bytes appear.
	appendFile(t, a, "a-new\n")
	if got := h.lines(1); !equalStrings(got, []string{"a-new"}) {
		t.Fatalf("lines = %q, want [a-new] (existing files must not be re-read)", got)
	}

	// Non-matching files are ignored.
	writeFile(t, filepath.Join(dir, "ignored.txt"), "nope\n")
	h.expectQuiet()

	cps := tl.Checkpoints()
	if len(cps) != 2 {
		t.Fatalf("Checkpoints = %v, want one per matched file", cps)
	}
	if cps[0].Path != a || cps[1].Path != b {
		t.Errorf("Checkpoints paths = %q, %q; want %q, %q sorted", cps[0].Path, cps[1].Path, a, b)
	}
}

// A glob member that is deleted (not rotated) must have its descriptor
// released and its tailer retired, or a daily-rotating glob accumulates
// goroutines and pins deleted files for the life of the daemon.
//
// Its checkpoint must *survive* that, though: the path may come back, and
// re-reading a file we have already emitted means re-counting every hit in it.
func TestTailGlobRetiresDeletedFileButKeepsCheckpoint(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	b := filepath.Join(dir, "b.log")
	writeFile(t, a, "a1\n")
	writeFile(t, b, "b1\n")

	tl, _ := newTestTail(t, filepath.Join(dir, "*.log"), startAtBeginning, nil, true)
	h := start(t, tl)
	if got := h.lines(2); len(got) != 2 {
		t.Fatalf("lines = %q", got)
	}
	waitTailer(t, tl, b)
	waitOffsetSet(t, tl, b)

	if err := os.Remove(b); err != nil {
		t.Fatalf("remove: %v", err)
	}
	waitFor(t, "the tailer for the deleted file to be retired", func() bool {
		tl.mu.Lock()
		defer tl.mu.Unlock()
		_, live := tl.files[b]
		return !live
	})

	tl.mu.Lock()
	cp, saved := tl.saved[b]
	tl.mu.Unlock()
	if !saved {
		t.Errorf("checkpoint for %s was dropped when its tailer retired; a file that comes back would be replayed", b)
	}
	if saved && cp.Offset != int64(len("b1\n")) {
		t.Errorf("kept checkpoint offset = %d, want %d", cp.Offset, len("b1\n"))
	}
	// The watch must go with the tailer, or a churning glob leaks one inotify
	// watch per file.
	tl.mu.Lock()
	w := tl.watcher
	tl.mu.Unlock()
	if w != nil {
		for _, p := range w.WatchList() {
			if p == b {
				t.Errorf("watch on %s outlived its tailer", b)
			}
		}
	}

	// The surviving file must still work.
	appendFile(t, a, "a2\n")
	if got := h.lines(1); !equalStrings(got, []string{"a2"}) {
		t.Fatalf("lines = %q, want [a2]", got)
	}
}

// A file that newly matches a glob is not automatically new: a rotated archive
// or a restored backup arrives with a full history behind it. Replaying it
// would trip every threshold at once, so start_at decides, exactly as it does
// for a file present at startup.
func TestTailGlobRescanHonoursStartAt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		startAt string
		// withCheckpoint pre-loads the store with an offset for the file
		// that is about to appear, the way a restart would find one.
		withCheckpoint bool
		// wantFromNewFile is what must arrive from the rediscovered file.
		wantFromNewFile []string
	}{
		{
			name:            "end skips the history it arrived with",
			startAt:         startAtEnd,
			wantFromNewFile: []string{"b-live"},
		},
		{
			name:            "checkpoint with no saved offset falls back to end",
			startAt:         startAtCheckpoint,
			wantFromNewFile: []string{"b-live"},
		},
		{
			name:            "checkpoint resumes mid-file",
			startAt:         startAtCheckpoint,
			withCheckpoint:  true,
			wantFromNewFile: []string{"b-old2", "b-live"},
		},
		{
			name:            "beginning still replays, for monitors that ask for it",
			startAt:         startAtBeginning,
			wantFromNewFile: []string{"b-old1", "b-old2", "b-live"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			a := filepath.Join(dir, "a.log")
			b := filepath.Join(dir, "b.log")
			writeFile(t, a, "")

			// Stage the newcomer outside the glob, so the store can be
			// populated (with the real inode) before anything reads it: the
			// fake store is a plain map and the tailer reads it from its own
			// goroutine. Moving a file into place is also exactly how an
			// archive or a restored backup shows up.
			staged := filepath.Join(dir, "b.staged")
			writeFile(t, staged, "b-old1\nb-old2\n")

			store := fakeLookup{}
			if tc.withCheckpoint {
				id := inodeOf(t, staged)
				store[b] = model.Checkpoint{Path: b, Dev: id.dev, Inode: id.ino, Offset: int64(len("b-old1\n"))}
			}

			tl, _ := newTestTail(t, filepath.Join(dir, "*.log"), tc.startAt, store, true)
			h := start(t, tl)
			waitOffsetSet(t, tl, a)

			if err := os.Rename(staged, b); err != nil {
				t.Fatalf("rename: %v", err)
			}
			waitOffsetSet(t, tl, b)

			appendFile(t, b, "b-live\n")
			if got := h.lines(len(tc.wantFromNewFile)); !equalStrings(got, tc.wantFromNewFile) {
				t.Fatalf("lines = %q, want %q", got, tc.wantFromNewFile)
			}
			h.expectQuiet()
		})
	}
}

// Deleting and recreating a plain (non-glob) file must resume, not wedge.
func TestTailFileDeletedThenRecreated(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "before\n")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	if got := h.lines(1); !equalStrings(got, []string{"before"}) {
		t.Fatalf("lines = %q", got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	writeFile(t, path, "after\n")
	if got := h.lines(1); !equalStrings(got, []string{"after"}) {
		t.Fatalf("lines = %q, want [after]", got)
	}
}

// When the inode is unlinked, EOF stops meaning "the writer has not finished
// this line yet" and starts meaning "nobody ever will". The unterminated
// trailing line is then real data — often the last thing written before
// someone ran `rm` — so it must be emitted, not dropped.
func TestTailDeletedFileFlushesTrailingLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "complete\nunterminated-last-words")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, false)
	tl.poll = time.Hour // only manual nudges advance the tailer
	h := start(t, tl)
	ft := waitTailer(t, tl, path)

	if got := h.lines(1); !equalStrings(got, []string{"complete"}) {
		t.Fatalf("lines = %q, want [complete] (the partial line must be withheld while the file lives)", got)
	}
	h.expectQuiet()

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	ft.nudge()
	if got := h.lines(1); !equalStrings(got, []string{"unterminated-last-words"}) {
		t.Fatalf("lines = %q, want the trailing line flushed once the inode was gone", got)
	}
}

// A fragment dropped at rotation is a line of log thrown away. That is the
// right call (the writer finishes it in the new file), but it must be counted
// rather than whispered at Debug.
func TestTailRotationCountsDiscardedFragment(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "a1\nhalf-a-line")

	tl, h2 := newTestTail(t, path, startAtBeginning, nil, false)
	tl.poll = time.Hour
	h := start(t, tl)
	ft := waitTailer(t, tl, path)
	if got := h.lines(1); !equalStrings(got, []string{"a1"}) {
		t.Fatalf("lines = %q", got)
	}

	if err := os.Rename(path, filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	writeFile(t, path, "b1\n")
	ft.nudge()

	if got := h.lines(1); !equalStrings(got, []string{"b1"}) {
		t.Fatalf("lines = %q, want [b1]", got)
	}
	if got := tl.Stats().DiscardedPartialLines; got != 1 {
		t.Errorf("Stats().DiscardedPartialLines = %d, want 1", got)
	}
	if n := h2.count(slog.LevelWarn, "discarded an unterminated trailing line"); n != 1 {
		t.Errorf("discard warnings = %d, want 1", n)
	}
}

// Over-long lines are truncated and counted; a tailer never sees an
// authoritative EOF, so the count has to surface without one.
func TestTailCountsTruncatedLines(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	appendFile(t, path, strings.Repeat("x", maxLineBytes+1)+"\nshort\n")
	if got := h.lines(2); len(got) != 2 {
		t.Fatalf("lines = %q", got)
	}
	// The file is still open and still being tailed: no EOF, no shutdown.
	waitFor(t, "the truncation to be counted", func() bool {
		return tl.Stats().TruncatedLines == 1
	})
}

// A permanently failing file (EACCES on a log we may not read) retries every
// poll tick. Without rate limiting that is a warning a second, forever, per
// file — 86400 identical lines a day, hiding everything else.
func TestTailPermanentErrorWarnsOnlyOnce(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny us anything")
	}
	path := filepath.Join(t.TempDir(), "unreadable.log")
	writeFile(t, path, "secret\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	tl, h2 := newTestTail(t, path, startAtBeginning, nil, false)
	tl.poll = time.Millisecond // hammer the failing path
	start(t, tl)

	waitFor(t, "the first open failure to be reported", func() bool {
		return h2.count(slog.LevelWarn, "tail error") >= 1
	})
	// Prove the repeats really happened and really were swallowed, rather
	// than just not arriving yet: the limiter counts what it drops.
	ft := waitTailer(t, tl, path)
	waitFor(t, "repeated failures to be suppressed", func() bool {
		ft.errWarn.mu.Lock()
		defer ft.errWarn.mu.Unlock()
		return ft.errWarn.suppressed >= 5
	})
	if n := h2.count(slog.LevelWarn, "tail error"); n != 1 {
		t.Errorf("tail error warnings = %d, want exactly 1 within the rate-limit window", n)
	}
}

// Exhausting the per-wakeup round budget must re-arm the tailer rather than
// spin or drop data: the next wakeup picks up where this one stopped.
func TestTailPumpRoundLimitReArms(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "a1\n")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, false)
	tl.poll = time.Hour
	tl.rounds = 1 // one state transition per wakeup, then back to the queue
	h := start(t, tl)
	ft := waitTailer(t, tl, path)
	if got := h.lines(1); !equalStrings(got, []string{"a1"}) {
		t.Fatalf("lines = %q", got)
	}

	// With rounds == 1 the rotation itself consumes the wakeup's only round,
	// so reading the replacement file depends entirely on pump having
	// re-nudged itself.
	if err := os.Rename(path, filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	writeFile(t, path, "b1\n")
	ft.nudge()

	if got := h.lines(1); !equalStrings(got, []string{"b1"}) {
		t.Fatalf("lines = %q, want [b1] from the re-armed wakeup", got)
	}
}

func TestTailCheckpointsTrackLineBoundaries(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	appendFile(t, path, "hello\n")
	h.lines(1)

	// A partial line must not advance the checkpoint: a restart has to
	// re-read it, not skip it.
	appendFile(t, path, "partia")
	deadline := time.Now().Add(waitTimeout)
	var cp model.Checkpoint
	for time.Now().Before(deadline) {
		cps := tl.Checkpoints()
		if len(cps) != 1 {
			t.Fatalf("Checkpoints = %v, want 1", cps)
		}
		cp = cps[0]
		if cp.Offset == int64(len("hello\n")) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if cp.Offset != int64(len("hello\n")) {
		t.Fatalf("offset = %d, want %d (checkpoint must sit on a line boundary)", cp.Offset, len("hello\n"))
	}
	id := inodeOf(t, path)
	if cp.Dev != id.dev || cp.Inode != id.ino || cp.Path != path {
		t.Errorf("checkpoint = %+v, want dev/inode of %s (%+v)", cp, path, id)
	}
}

func TestTailCancelsPromptlyWithoutLeaking(t *testing.T) {
	// Not parallel: this counts goroutines, and a neighbour running
	// concurrently would be counted too (see sourceGoroutines).
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "x\n")

	before := sourceGoroutines()

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	tl.poll = time.Hour // cancellation must not wait for the poll tick
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan model.Event, 8)
	errc := make(chan error, 1)
	go func() { errc <- tl.Run(ctx, events) }()

	select {
	case ev := <-events:
		if string(ev.Raw) != "x" {
			t.Fatalf("event = %q", ev.Raw)
		}
	case <-time.After(waitTimeout):
		t.Fatal("no event")
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run = %v, want nil on cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of cancellation")
	}
	assertNoLeak(t, before)
}

// A blocked send on a full output channel must not wedge shutdown.
func TestTailCancelWithFullChannel(t *testing.T) {
	// Not parallel: see TestTailCancelsPromptlyWithoutLeaking.
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, strings.Repeat("line\n", 100))

	before := sourceGoroutines()

	tl, _ := newTestTail(t, path, startAtBeginning, nil, true)
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan model.Event) // unbuffered, never read
	errc := make(chan error, 1)
	go func() { errc <- tl.Run(ctx, events) }()

	// Wait for the tailer to be genuinely stuck on the send rather than
	// sleeping for a duration that merely tends to be long enough: it has
	// published its first checkpoint by then and cannot proceed.
	waitOffsetSet(t, tl, path)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return while blocked on a full channel")
	}
	assertNoLeak(t, before)
}

func TestTailRunRejectsNilChannel(t *testing.T) {
	t.Parallel()
	tl, _ := newTestTail(t, filepath.Join(t.TempDir(), "x.log"), startAtEnd, nil, false)
	if err := tl.Run(context.Background(), nil); err == nil {
		t.Fatal("Run(nil channel) = nil, want error")
	}
}

// With fsnotify unavailable the tailer must still make progress on the poll
// backstop alone.
func TestTailPollingFallback(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")

	tl, _ := newTestTail(t, path, startAtBeginning, nil, false)
	h := start(t, tl)
	waitOffsetSet(t, tl, path)

	appendFile(t, path, "polled\n")
	if got := h.lines(1); !equalStrings(got, []string{"polled"}) {
		t.Fatalf("lines = %q, want [polled]", got)
	}
}
