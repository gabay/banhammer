package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"banhammer/internal/model"

	"github.com/fsnotify/fsnotify"
)

const (
	// defaultPollInterval is the backstop stat/read interval. fsnotify is the
	// fast path, but events get coalesced, dropped on queue overflow, and
	// never arrive at all on NFS, so we always poll as well — a stat per
	// second per file is free compared to missing an attack.
	defaultPollInterval = time.Second
	// defaultRescanInterval is how often a glob is re-evaluated for new files.
	defaultRescanInterval = 10 * time.Second
	// readChunk is the per-tailer read buffer size.
	readChunk = 32 << 10
	// maxPumpRounds bounds one wakeup's rotation/truncation follow-ups so a
	// pathological writer cannot livelock the tailer goroutine.
	maxPumpRounds = 32
)

// NewTail returns a Source that tails pattern, which is either a single path
// or a glob such as /var/log/nginx/*.log.
//
// startAt is checkpoint, end or beginning ("" means checkpoint). checkpoint
// resumes from cp, falling back to end when there is no saved offset or the
// saved inode no longer matches — replaying a week of history would re-ban
// half the internet.
//
// A missing file is not an error: the tailer warns once and waits for it to
// appear.
//
// # Rotation
//
// Rotation is detected by the path naming a different (dev, inode) than the
// open descriptor. The remaining tail of the old descriptor is drained before
// switching, because lines written between our last read and the rename are
// exactly the lines an attacker generates while logrotate runs.
//
// Two cases are deliberately out of reach:
//
//   - A writer that keeps writing to the renamed descriptor forever (no SIGHUP
//     and no copytruncate). We follow the path, not the inode, so those lines
//     go to the rotated file unseen — the same behaviour as fail2ban's tailer.
//   - Two rotations completing between two wakeups. The intermediate file was
//     never opened and its name is unknown by then, so its lines are lost.
//     The parent-directory watch makes wakeups event-driven, so this needs two
//     rotations inside a few milliseconds.
func NewTail(monitor, pattern, startAt string, cp CheckpointLookup, log *slog.Logger) (Source, error) {
	if monitor == "" {
		return nil, errors.New("tail: monitor name is empty")
	}
	if pattern == "" {
		return nil, fmt.Errorf("tail %q: file pattern is empty", monitor)
	}
	switch startAt {
	case "":
		startAt = startAtCheckpoint
	case startAtCheckpoint, startAtEnd, startAtBeginning:
	default:
		return nil, fmt.Errorf("tail %q: unknown start_at %q (want checkpoint|end|beginning)", monitor, startAt)
	}
	isGlob := strings.ContainsAny(pattern, "*?[")
	if isGlob {
		// Reject a malformed glob now rather than silently matching nothing.
		if _, err := filepath.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("tail %q: bad glob %q: %w", monitor, pattern, err)
		}
	}
	return &tail{
		monitor:   monitor,
		pattern:   pattern,
		startAt:   startAt,
		lookup:    cp,
		log:       orDefaultLogger(log).With("monitor", monitor, "file", pattern),
		isGlob:    isGlob,
		poll:      defaultPollInterval,
		rescan:    defaultRescanInterval,
		useNotify: true,
		files:     make(map[string]*fileTailer),
		saved:     make(map[string]model.Checkpoint),
	}, nil
}

type tail struct {
	monitor string
	pattern string
	startAt string
	lookup  CheckpointLookup
	log     *slog.Logger
	isGlob  bool

	// Tunables; overridden by tests to keep them fast. useNotify is a test
	// seam: with it off the tailer only advances when polled or nudged,
	// which is what makes the rotation tests deterministic instead of racy.
	poll      time.Duration
	rescan    time.Duration
	useNotify bool

	mu      sync.Mutex
	files   map[string]*fileTailer
	saved   map[string]model.Checkpoint
	watcher *fsnotify.Watcher // nil in polling-only mode
}

func (t *tail) Name() string { return t.monitor }

// Checkpoints returns one checkpoint per tailed file, positioned at the last
// complete line handed to the pipeline.
func (t *tail) Checkpoints() []model.Checkpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.saved) == 0 {
		return nil
	}
	out := make([]model.Checkpoint, 0, len(t.saved))
	for _, cp := range t.saved {
		out = append(out, cp)
	}
	// Stable order keeps the persisted file diff-friendly.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (t *tail) Run(ctx context.Context, out chan<- model.Event) error {
	if out == nil {
		return fmt.Errorf("tail %q: nil output channel", t.monitor)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	rescan := make(chan struct{}, 1)

	var watcher *fsnotify.Watcher
	if t.useNotify {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			// Descriptor exhaustion (fs.inotify.max_user_instances) must not
			// take the daemon down; polling still catches everything, just
			// with up to poll-interval latency.
			t.log.Warn("fsnotify unavailable, falling back to polling", "err", err, "poll", t.poll)
		} else {
			watcher = w
		}
	}
	if watcher != nil {
		t.setWatcher(watcher)
		// Watching the parent directory is what catches create-after-rotate:
		// the watch on the old inode survives the rename but goes silent.
		for _, dir := range t.watchDirs() {
			if err := watcher.Add(dir); err != nil {
				t.log.Warn("cannot watch directory, relying on polling", "dir", dir, "err", err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.watchLoop(ctx, watcher, rescan)
		}()
	}

	t.scan(ctx, out, &wg, true)

	var rescanC <-chan time.Time
	if t.isGlob {
		tk := time.NewTicker(t.rescan)
		defer tk.Stop()
		rescanC = tk.C
	}

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-rescanC:
			t.scan(ctx, out, &wg, false)
		case <-rescan:
			// A create/rename in a watched directory may be a new glob match
			// (or the recreation of a missing file).
			t.scan(ctx, out, &wg, false)
		}
	}

	cancel()
	wg.Wait()
	if watcher != nil {
		t.setWatcher(nil)
		if err := watcher.Close(); err != nil {
			t.log.Debug("closing fsnotify watcher", "err", err)
		}
	}
	return nil
}

func (t *tail) setWatcher(w *fsnotify.Watcher) {
	t.mu.Lock()
	t.watcher = w
	t.mu.Unlock()
}

// addWatch registers a watch on a file we just opened. Errors are advisory:
// the directory watch and the poll backstop still cover us.
func (t *tail) addWatch(path string) {
	t.mu.Lock()
	w := t.watcher
	t.mu.Unlock()
	if w == nil {
		return
	}
	if err := w.Add(path); err != nil {
		t.log.Debug("cannot watch file, relying on directory watch and polling", "path", path, "err", err)
	}
}

// watchDirs returns the directories to watch: for a glob, the deepest ancestor
// that contains no metacharacter, so /var/log/*/access.log watches /var/log.
func (t *tail) watchDirs() []string {
	dir := filepath.Dir(t.pattern)
	for dir != "" && dir != "." && dir != string(filepath.Separator) && strings.ContainsAny(dir, "*?[") {
		dir = filepath.Dir(dir)
	}
	if dir == "" {
		dir = "."
	}
	return []string{dir}
}

func (t *tail) watchLoop(ctx context.Context, w *fsnotify.Watcher, rescan chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			// Every tailer of this monitor is woken: there are at most a
			// handful, and matching event paths to tailers is fiddly
			// (rename events name the *old* path) for no real saving.
			t.wakeAll()
			if ev.Has(fsnotify.Create) || ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove) {
				select {
				case rescan <- struct{}{}:
				default:
				}
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			t.log.Warn("fsnotify error, continuing on the poll backstop", "err", err)
		}
	}
}

func (t *tail) wakeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ft := range t.files {
		ft.nudge()
	}
}

// scan resolves the pattern and starts a tailer for every path that does not
// have one yet. Existing tailers keep their offsets, so a rescan never
// re-reads a file from the start.
func (t *tail) scan(ctx context.Context, out chan<- model.Event, wg *sync.WaitGroup, initial bool) {
	paths := t.matches()

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range paths {
		if _, ok := t.files[p]; ok {
			continue
		}
		// Files discovered after startup are new files, so they are read from
		// the beginning regardless of start_at; start_at is about not
		// replaying history we have already seen.
		start := t.startAt
		if !initial {
			start = startAtBeginning
		}
		fctx, fcancel := context.WithCancel(ctx)
		ft := newFileTailer(t, p, start, fcancel)
		t.files[p] = ft
		wg.Add(1)
		go func() {
			defer wg.Done()
			ft.run(fctx, out)
		}()
	}
	if !t.isGlob {
		return
	}
	// Retire tailers whose file has vanished from the glob and which hold no
	// open descriptor; otherwise a daily-rotating glob accumulates goroutines.
	live := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		live[p] = struct{}{}
	}
	for p, ft := range t.files {
		if _, ok := live[p]; ok {
			continue
		}
		if !ft.idle() {
			continue
		}
		ft.cancel()
		delete(t.files, p)
		delete(t.saved, p)
		t.log.Debug("retiring tailer for vanished file", "path", p)
	}
}

func (t *tail) matches() []string {
	if !t.isGlob {
		return []string{t.pattern}
	}
	paths, err := filepath.Glob(t.pattern)
	if err != nil {
		// Only ErrBadPattern, which NewTail already rejected.
		t.log.Warn("glob failed", "err", err)
		return nil
	}
	out := paths[:0]
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (t *tail) publish(cp model.Checkpoint) {
	t.mu.Lock()
	t.saved[cp.Path] = cp
	t.mu.Unlock()
}

// fileTailer follows exactly one path across rotations. All fields other than
// wake/cancel/gone are owned by its own goroutine.
type fileTailer struct {
	t       *tail
	path    string
	startAt string
	log     *slog.Logger
	cancel  context.CancelFunc

	wake chan struct{}
	gone atomic.Bool // file absent and no descriptor held

	f      *os.File
	id     fileID
	offset int64
	sp     splitter
	rbuf   []byte
	em     emitter

	warnedMissing bool
}

func newFileTailer(t *tail, path, startAt string, cancel context.CancelFunc) *fileTailer {
	return &fileTailer{
		t:       t,
		path:    path,
		startAt: startAt,
		log:     t.log.With("path", path),
		cancel:  cancel,
		wake:    make(chan struct{}, 1),
		rbuf:    make([]byte, readChunk),
	}
}

func (ft *fileTailer) nudge() {
	select {
	case ft.wake <- struct{}{}:
	default:
	}
}

func (ft *fileTailer) idle() bool { return ft.gone.Load() }

func (ft *fileTailer) run(ctx context.Context, out chan<- model.Event) {
	ft.em = emitter{monitor: ft.t.monitor, out: out}
	defer ft.closeFile()

	tk := time.NewTicker(ft.t.poll)
	defer tk.Stop()

	for {
		if err := ft.pump(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			// A transient read error (EIO, a disappearing mount) must not
			// kill the monitor; retry on the next tick.
			ft.log.Warn("tail error, retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ft.wake:
		case <-tk.C:
		}
	}
}

// pump reads everything currently available, then reacts to rotation and
// truncation, looping so that a rotate discovered at EOF is followed
// immediately by reading the replacement file.
func (ft *fileTailer) pump(ctx context.Context) error {
	for round := 0; round < maxPumpRounds; round++ {
		if ft.f == nil {
			opened, err := ft.open()
			if err != nil {
				return err
			}
			if !opened {
				return nil
			}
		}
		if err := ft.readAvailable(ctx); err != nil {
			return err
		}
		state, err := ft.classify()
		if err != nil {
			return err
		}
		switch state {
		case stateUnchanged:
			return nil
		case stateTruncated:
			ft.log.Info("log truncated, rewinding", "was_offset", ft.offset)
			if _, err := ft.f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek %s: %w", ft.path, err)
			}
			ft.offset = 0
			// Whatever partial line we held belonged to the discarded
			// content; it can never be completed.
			ft.sp.reset()
			ft.publish()
		case stateRotated:
			// Drain the old descriptor before switching. Between our last
			// EOF and the rename the writer may have flushed more lines,
			// and dropped lines are dropped attacks.
			if err := ft.readAvailable(ctx); err != nil {
				return err
			}
			if n := ft.sp.pending(); n > 0 {
				ft.log.Debug("discarding unterminated trailing line from rotated file", "bytes", n)
			}
			ft.log.Info("log rotated, reopening")
			ft.closeFile()
		case stateDeleted:
			// Truly unlinked, not renamed: drain what is left and let the
			// descriptor go. Holding it would pin the disk space and keep a
			// goroutine alive for a file that can never come back.
			if err := ft.readAvailable(ctx); err != nil {
				return err
			}
			ft.log.Info("log file was deleted, releasing it")
			ft.closeFile()
			return nil
		}
	}
	// Out of rounds: come back on the next wakeup rather than spinning.
	ft.nudge()
	return nil
}

func (ft *fileTailer) open() (bool, error) {
	f, err := os.Open(ft.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			ft.gone.Store(true)
			if !ft.warnedMissing {
				ft.warnedMissing = true
				ft.log.Warn("log file does not exist, waiting for it to appear")
			}
			return false, nil
		}
		return false, fmt.Errorf("open %s: %w", ft.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // already failing; the close error adds nothing
		return false, fmt.Errorf("stat %s: %w", ft.path, err)
	}
	id, err := statID(fi)
	if err != nil {
		_ = f.Close() // as above
		return false, err
	}
	off := ft.startOffset(fi, id)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		_ = f.Close() // as above
		return false, fmt.Errorf("seek %s: %w", ft.path, err)
	}

	ft.f, ft.id, ft.offset = f, id, off
	ft.sp.reset()
	ft.gone.Store(false)
	if ft.warnedMissing {
		ft.warnedMissing = false
		ft.log.Info("log file appeared")
	}
	// Any later reopen is a replacement file: read it whole.
	ft.startAt = startAtBeginning
	ft.publish()
	ft.t.addWatch(ft.path)
	return true, nil
}

func (ft *fileTailer) startOffset(fi os.FileInfo, id fileID) int64 {
	switch ft.startAt {
	case startAtBeginning:
		return 0
	case startAtEnd:
		return fi.Size()
	}
	// checkpoint
	if ft.t.lookup == nil {
		return fi.Size()
	}
	cp, ok := ft.t.lookup.Lookup(ft.path)
	if !ok {
		ft.log.Debug("no checkpoint for file, starting at end")
		return fi.Size()
	}
	if !cp.SameFile(model.Checkpoint{Dev: id.dev, Inode: id.ino}) {
		// The file was replaced while we were down. We cannot know how much
		// of the new file we already saw, and replaying it could re-ban;
		// end is the safe choice and matches PROJECT.md §4.1.
		ft.log.Info("checkpoint inode mismatch, starting at end",
			"checkpoint_inode", cp.Inode, "file_inode", id.ino)
		return fi.Size()
	}
	if cp.Offset > fi.Size() {
		ft.log.Info("checkpoint past end of file, restarting from 0",
			"checkpoint_offset", cp.Offset, "size", fi.Size())
		return 0
	}
	if cp.Offset < 0 {
		return 0
	}
	return cp.Offset
}

func (ft *fileTailer) readAvailable(ctx context.Context) error {
	emit := func(line []byte) error { return ft.em.emit(ctx, line) }
	for {
		n, err := ft.f.Read(ft.rbuf)
		if n > 0 {
			ft.offset += int64(n)
			if perr := ft.sp.push(ft.rbuf[:n], emit); perr != nil {
				return perr
			}
			ft.publish()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read %s: %w", ft.path, err)
		}
		if n == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

type fileState int

const (
	stateUnchanged fileState = iota
	stateRotated
	stateTruncated
	stateDeleted
)

func (ft *fileTailer) classify() (fileState, error) {
	fi, err := os.Stat(ft.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The path is gone. If our descriptor still has a link it was
			// renamed (logrotate mid-run, or rotate+compress), so we keep
			// reading it and wait for the replacement. If it has no links
			// left it was deleted and there is nothing to come back to.
			if ofi, serr := ft.f.Stat(); serr == nil {
				if n, ok := linkCount(ofi); ok && n == 0 {
					return stateDeleted, nil
				}
			}
			return stateUnchanged, nil
		}
		return stateUnchanged, fmt.Errorf("stat %s: %w", ft.path, err)
	}
	id, err := statID(fi)
	if err != nil {
		return stateUnchanged, err
	}
	if id != ft.id {
		return stateRotated, nil
	}
	if fi.Size() < ft.offset {
		return stateTruncated, nil
	}
	return stateUnchanged, nil
}

func (ft *fileTailer) closeFile() {
	if ft.f == nil {
		return
	}
	if err := ft.f.Close(); err != nil {
		ft.log.Debug("closing tailed file", "err", err)
	}
	ft.f = nil
	ft.sp.reset()
	ft.gone.Store(true)
}

func (ft *fileTailer) publish() {
	ft.t.publish(model.Checkpoint{
		Path:   ft.path,
		Dev:    ft.id.dev,
		Inode:  ft.id.ino,
		Offset: ft.offset - int64(ft.sp.pending()),
	})
}
