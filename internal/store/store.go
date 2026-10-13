// Package store persists Banhammer's two pieces of durable state: the active
// bans and the per-file read offsets. Its only job is to be boring — never
// lose state, never corrupt it, and never stop the daemon because of a bad
// file on disk.
//
// Both files are plain JSON (small working set, human-inspectable, trivially
// repairable by hand) and are written atomically: a temp file in the same
// directory, fsynced, renamed over the target, followed by an fsync of the
// directory. A crash therefore leaves either the old file or the new one.
//
// A file that fails to parse is not fatal. It is logged, renamed aside as
// <name>.corrupt so an operator can inspect it, and the daemon starts from
// empty state.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"banhammer/internal/model"
)

const (
	// BansFile, OffsetsFile and HistoryFile are the state files inside the
	// state dir.
	BansFile    = "bans.json"
	OffsetsFile = "offsets.json"
	// HistoryFile holds the ban ledger behind the status page's statistics.
	// It is the one state file whose loss costs nothing but a chart.
	HistoryFile = "history.json"

	// CorruptSuffix is appended to a state file that could not be parsed.
	CorruptSuffix = ".corrupt"

	// tempPrefix is the fixed part of the name of an in-flight write, used
	// both to create and to recognise (and sweep) temp files.
	tempPrefix = ".tmp-"

	// DefaultBanInterval is the minimum spacing between bans.json writes. A
	// burst of offences is one write, not one per ban.
	DefaultBanInterval = time.Second

	// MaxStateFileSize bounds how much of a state file is read into memory.
	// Our own files are kilobytes; anything vastly larger is garbage, and a
	// daemon's memory use must be bounded by its config, not by whatever
	// happens to be on disk.
	MaxStateFileSize int64 = 64 << 20

	// maxWriteRetries bounds the self-healing retries of a failed debounced
	// write. Without it a transient ENOSPC would leave the newest bans in
	// memory indefinitely on an otherwise idle daemon.
	maxWriteRetries = 5

	// maxRetryDelay caps the exponential backoff between those retries.
	maxRetryDelay = 30 * time.Second

	// stateVersion tags the on-disk format so a future change can be
	// recognised instead of silently misread.
	stateVersion = 1
)

// ErrLocked is returned by Open when another process (or another Store in
// this process) already holds the state directory.
var ErrLocked = errors.New("already locked by another banhammer process")

// ErrClosed is returned by operations on a Store that has been closed.
var ErrClosed = errors.New("store is closed")

// ErrNotPersisted marks every error that means "the latest state is still
// only in memory". Callers can tell it apart from an error that leaves the
// state durable (a lock release failure, say) with errors.Is, and should
// treat it as the one shutdown failure worth retrying.
var ErrNotPersisted = errors.New("latest state was not persisted")

// ErrNotDurable marks the weaker failure of a write whose data did reach the
// file — the rename completed, so the next reader (including a restart) sees
// the new state — but whose directory fsync failed, so a power cut could
// still resurrect the old name. It is deliberately *not* ErrNotPersisted:
// that sentinel promises "the state is only in memory", which is false here,
// and a caller acting on that promise would keep retrying data it already has
// on disk. Both are worth retrying; only one means data loss is imminent.
var ErrNotDurable = errors.New("latest state was written but not fsynced")

// errTooLarge marks a state file we refuse to read; it is handled like any
// other corruption.
var errTooLarge = errors.New("state file is implausibly large")

// Stopper cancels a scheduled callback. *time.Timer satisfies it; tests
// substitute a fake so that debouncing never waits on real time.
type Stopper interface{ Stop() bool }

// Options tunes a Store. The zero value is what Open uses and is what the
// daemon wants; every field exists so tests can be hermetic.
type Options struct {
	// Log receives corruption and write-failure reports. nil means
	// slog.Default().
	Log *slog.Logger
	// Now supplies the current time for debounce accounting. nil means
	// time.Now.
	Now func() time.Time
	// BanInterval is the debounce window for bans.json. Zero means
	// DefaultBanInterval. A negative value is rejected rather than given a
	// second meaning: use SynchronousBans to turn debouncing off.
	BanInterval time.Duration
	// SynchronousBans makes SaveBans write bans.json before it returns,
	// trading the "≤1 write/s" contract for an error the caller can act on
	// immediately. Only one-shot tools and tests want this; the daemon does
	// not.
	SynchronousBans bool
	// AfterFunc schedules f after d. nil means time.AfterFunc.
	AfterFunc func(d time.Duration, f func()) Stopper

	// maxFileSize overrides MaxStateFileSize. It is unexported because it
	// exists solely so tests can exercise the oversize path at Open — which
	// reads offsets.json before any test can reach into the Store — without
	// writing 64 MiB to disk.
	maxFileSize int64
}

// Store owns a state directory. It is safe for concurrent use: the daemon
// writes bans from the ban manager goroutine and offsets from the source
// goroutines, and Lookup is called while sources start up.
type Store struct {
	dir  string
	log  *slog.Logger
	now  func() time.Time
	lock *os.File

	interval    time.Duration
	synchronous bool
	after       func(time.Duration, func()) Stopper

	// writeFile is a seam: tests replace it to count writes and to simulate
	// a full disk. It always points at writeFileAtomic in production.
	writeFile func(dir, base string, data []byte) error
	// maxFileSize is MaxStateFileSize outside tests, which shrink it so the
	// oversize path can be exercised without writing 64 MiB.
	maxFileSize int64

	mu sync.Mutex
	// pendingBans is the most recent state handed to SaveBans that has not
	// reached disk yet. It is kept on write failure so a later retry or
	// Flush still persists it.
	pendingBans []model.Ban
	hasPending  bool
	lastBanAt   time.Time
	timer       Stopper
	// gen identifies the debounce timer that is currently allowed to write.
	// See armTimerLocked for why a token is needed at all.
	gen uint64
	// retries counts consecutive failures of the debounced write, to bound
	// the backoff chain.
	retries int
	// deferredErr is an error from a debounced write, surfaced to the caller
	// of the next SaveBans (the original SaveBans had already returned by the
	// time the write happened). It is cleared as soon as the state is durable
	// so that nobody is told about a failure that no longer matters.
	deferredErr error

	offsets map[string]model.Checkpoint
	byPath  map[string]model.Checkpoint
	// offsetsOnDisk records whether offsets.json holds the current view, so
	// that an unchanged map can skip the write without ever skipping the
	// *first* one.
	offsetsOnDisk bool
	// clashWarned remembers, per path, the key of the checkpoint that won the
	// last time several of them named that path. Two monitors on one log file
	// is a legitimate configuration whose offsets keep advancing, and
	// SaveOffsets rebuilds the index every few seconds; without this the
	// daemon would warn about it forever.
	clashWarned map[string]string
	closed      bool
}

// Open prepares dir as a state directory: it creates the path (0755), takes
// an exclusive lock so two daemons cannot fight over the same state, clears
// any debris from an interrupted write, and loads the offsets into memory
// (quarantining the file if it is unreadable as JSON).
func Open(dir string) (*Store, error) { return OpenWith(dir, Options{}) }

// OpenWith is Open with injectable clock, logger and debounce behaviour.
func OpenWith(dir string, o Options) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: state directory must not be empty")
	}
	if o.BanInterval < 0 {
		return nil, fmt.Errorf("store: BanInterval must not be negative (got %v); set SynchronousBans instead", o.BanInterval)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: create state directory %s: %w", dir, err)
	}
	lock, err := acquireLock(dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	s := &Store{
		dir:         dir,
		log:         orDefaultLogger(o.Log),
		now:         o.Now,
		lock:        lock,
		interval:    o.BanInterval,
		synchronous: o.SynchronousBans,
		after:       o.AfterFunc,
		writeFile:   writeFileAtomic,
		maxFileSize: o.maxFileSize,
		offsets:     make(map[string]model.Checkpoint),
		byPath:      make(map[string]model.Checkpoint),
		clashWarned: make(map[string]string),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.interval == 0 {
		s.interval = DefaultBanInterval
	}
	if s.maxFileSize == 0 {
		s.maxFileSize = MaxStateFileSize
	}
	if s.after == nil {
		s.after = func(d time.Duration, f func()) Stopper { return time.AfterFunc(d, f) }
	}
	s.log = s.log.With("state_dir", dir)

	// Only safe now that we hold the lock: nobody else can have a write in
	// flight in this directory.
	s.sweepTempFiles()

	offsets, onDisk, err := s.loadOffsetsFromDisk()
	if err != nil {
		// A state dir we cannot read is a configuration problem, not a
		// corruption problem: fail loudly at startup.
		_ = releaseLock(lock) // best effort; we are already failing
		return nil, fmt.Errorf("store: %w", err)
	}
	s.setOffsets(offsets)
	s.offsetsOnDisk = onDisk
	return s, nil
}

// Dir reports the state directory this Store owns.
func (s *Store) Dir() string { return s.dir }

// LoadBans returns the persisted bans. A corrupt file yields no bans and no
// error: the daemon must keep running. Expiry is the ban manager's business,
// so expired entries are returned as-is.
func (s *Store) LoadBans() ([]model.Ban, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("store: LoadBans: %w", ErrClosed)
	}
	// A pending debounced write is newer than the file; prefer it so that
	// save-then-load is consistent.
	if s.hasPending {
		return slices.Clone(s.pendingBans), nil
	}

	var file bansFile
	ok, err := s.readState(BansFile, &file)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return s.validBans(file.Bans, BansFile), nil
}

// SaveBans persists bans atomically, debounced to at most one write per
// BanInterval. It returns as soon as the state is recorded in memory; the
// write may happen later, so an error from a deferred write is reported by
// the next SaveBans (wrapping ErrNotPersisted) and retried automatically a
// few times. Call Flush before exiting and check its error.
//
// The slice is copied, so the caller may reuse it. Entries the load path
// would refuse are dropped here too — see validBans.
func (s *Store) SaveBans(bans []model.Ban) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store: SaveBans: %w", ErrClosed)
	}
	// Report an earlier deferred failure once: at this point that state is
	// genuinely still not on disk.
	prev := s.deferredErr
	s.deferredErr = nil

	// validBans appends into a fresh slice, so this is also the defensive
	// copy the caller is promised.
	s.pendingBans = s.validBans(bans, "SaveBans")
	s.hasPending = true

	if s.synchronous {
		if err := s.writeBansLocked(); err != nil {
			// Two independent failures: this call did not reach the disk, and
			// neither did an earlier one. Dropping either would hide a fault.
			return errors.Join(err, deferredFailure(prev))
		}
		// The current snapshot is on disk, so the older failure no longer
		// describes anything that is at risk.
		return nil
	}
	if s.timer == nil {
		// Trailing edge: schedule the write for the end of the current
		// interval. With no recent write the delay is zero, so a quiet
		// daemon still persists a ban immediately.
		wait := s.interval - s.now().Sub(s.lastBanAt)
		if wait < 0 {
			wait = 0
		}
		s.armTimerLocked(wait)
	}
	return deferredFailure(prev)
}

// Flush forces any pending ban write out immediately. Call it on shutdown:
// without it the last state change inside a debounce interval would be lost.
// A non-nil error wraps ErrNotPersisted (or ErrNotDurable) and means the state
// is not safely on disk; the pending state is kept so a later Flush can retry.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A closed Store no longer owns the directory — another daemon may have
	// taken the lock — so writing here would clobber someone else's state.
	if s.closed {
		return fmt.Errorf("store: Flush: %w", ErrClosed)
	}
	return s.flushLocked()
}

// Close flushes pending state and releases the directory lock.
//
// If that final flush fails, Close deliberately does *not* close the store or
// release the lock: the newest bans exist only in memory, and letting another
// daemon take the directory would lose them. The error wraps ErrNotPersisted
// (or ErrNotDurable), and the failure is sticky — every subsequent Close
// retries the write and fails again until it succeeds, so a caller cannot
// mistake a second Close for success. Process exit releases the lock
// regardless, so give up after a bounded number of attempts.
//
// Once the state is durable Close is idempotent and returns nil.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.flushLocked(); err != nil {
		s.log.Error("final state write failed; keeping the state directory locked so the data is not handed to another daemon",
			"error", err)
		return fmt.Errorf("store: close %s: %w", s.dir, err)
	}
	s.closed = true
	err := releaseLock(s.lock)
	s.lock = nil
	if err != nil {
		// The state is durable; only the lock handling went wrong. Callers
		// distinguish the two cases with errors.Is(err, ErrNotPersisted).
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// LoadOffsets returns a copy of the checkpoint map, keyed as it was saved
// (the daemon keys by source file path). Open populated it from disk and
// SaveOffsets keeps it current, so this never hits the disk.
func (s *Store) LoadOffsets() (map[string]model.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("store: LoadOffsets: %w", ErrClosed)
	}
	return maps.Clone(s.offsets), nil
}

// SaveOffsets persists the checkpoint map atomically. Unlike bans this is not
// debounced: the daemon already rate-limits it (every 5s and on shutdown),
// and a synchronous error is more useful there.
//
// An unchanged map is not rewritten. The daemon calls this on a fixed tick
// whether or not anything moved, and an idle host would otherwise pay ~17k
// marshal+write+fsync cycles a day to store bytes it already stores.
func (s *Store) SaveOffsets(offsets map[string]model.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store: SaveOffsets: %w", ErrClosed)
	}
	// Validate before the comparison: the in-memory view is by construction
	// what a reload of the file would produce, so comparing anything else
	// would make the dirty check lie.
	clean := s.validOffsets(offsets, "SaveOffsets")
	if s.offsetsOnDisk && maps.Equal(s.offsets, clean) {
		return nil
	}
	data, err := marshalState(offsetsFile{
		envelope: envelope{Version: stateVersion},
		Offsets:  clean,
	})
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", OffsetsFile, err)
	}
	if err := s.writeFile(s.dir, OffsetsFile, data); err != nil {
		return saveError(OffsetsFile, err)
	}
	// Only adopt the new view once it is durable, so a failed write does not
	// make Lookup lie about what a restart would see.
	s.setOffsetsLocked(clean)
	s.offsetsOnDisk = true
	return nil
}

// LoadHistory returns the persisted ban ledger. Like LoadBans, a corrupt or
// missing file yields no events and no error: the statistics page is the
// least important thing the daemon does, and must never be the reason it
// fails to start. Entries are returned as written; retention is the ledger's
// business.
func (s *Store) LoadHistory() ([]model.BanEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("store: LoadHistory: %w", ErrClosed)
	}
	var file historyFile
	ok, err := s.readState(HistoryFile, &file)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return s.validEvents(file.Events, HistoryFile), nil
}

// SaveHistory persists the ban ledger atomically. It is synchronous and not
// debounced, like SaveOffsets: the daemon already calls it on a slow tick and
// at shutdown, and a write that fails should say so to that caller. The slice
// is not retained.
func (s *Store) SaveHistory(events []model.BanEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store: SaveHistory: %w", ErrClosed)
	}
	clean := s.validEvents(events, "SaveHistory")
	if clean == nil {
		clean = []model.BanEvent{} // encode as [], not null
	}
	data, err := marshalState(historyFile{
		envelope: envelope{Version: stateVersion},
		Events:   clean,
	})
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", HistoryFile, err)
	}
	if err := s.writeFile(s.dir, HistoryFile, data); err != nil {
		return saveError(HistoryFile, err)
	}
	return nil
}

// validEvents is validBans' counterpart for the ledger: an event without a
// usable address or timestamp can feed no statistic, and dropping it on both
// the save and the load path keeps the two in agreement. The result never
// aliases the input.
func (s *Store) validEvents(events []model.BanEvent, origin string) []model.BanEvent {
	kept := events[:0:0]
	dropped := 0
	for _, e := range events {
		if !e.IP.IsValid() || e.At.IsZero() {
			dropped++
			continue
		}
		kept = append(kept, e)
	}
	if dropped > 0 {
		s.log.Warn("dropped unusable ban history entries", "origin", origin,
			"dropped", dropped, "kept", len(kept))
	}
	return kept
}

// Lookup returns the checkpoint recorded for a file path, implementing
// source.CheckpointLookup.
//
// The daemon keys offsets by path, so an exact key match wins. Entries stored
// under some other key (a monitor name, say) are found through a secondary
// index on Checkpoint.Path; if several entries name the same file — two
// monitors watching one log is a normal configuration — the one with the
// largest Offset wins, deterministically, because re-reading a little is
// cheaper than skipping lines.
//
// A closed Store reports nothing found: it no longer owns the directory, so
// whatever it remembers may already have been superseded by another daemon.
func (s *Store) Lookup(path string) (model.Checkpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return model.Checkpoint{}, false
	}
	if cp, ok := s.offsets[path]; ok && (cp.Path == "" || cp.Path == path) {
		return cp, true
	}
	cp, ok := s.byPath[path]
	return cp, ok
}

// armTimerLocked schedules the debounced write and stamps the callback with a
// generation token.
//
// The token is what makes cancellation reliable. Stop reports false for a
// timer that has already fired and is blocked on the mutex, so a Flush can
// believe it cancelled a timer that is in fact about to run; if that zombie
// callback then wrote, it would both break the one-write-per-interval
// contract and overwrite s.timer, orphaning the timer armed in the meantime.
// A callback whose token no longer matches simply does nothing.
func (s *Store) armTimerLocked(wait time.Duration) {
	s.gen++
	gen := s.gen
	s.timer = s.after(wait, func() { s.onTimer(gen) })
}

// cancelTimerLocked stops the debounce timer and invalidates its callback.
// The generation bump is the part that matters: Stop cannot recall a callback
// that is already waiting for the mutex.
func (s *Store) cancelTimerLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.gen++
}

// onTimer runs the debounced write and, on failure, schedules a bounded
// backoff chain so that a transient disk problem does not pin the newest
// bans in memory until the next save (which on a quiet daemon may never
// come — and a quiet daemon is exactly when the last ban matters).
func (s *Store) onTimer(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		// Superseded while this callback waited for the mutex. Touching
		// s.timer here would discard whoever superseded us.
		return
	}
	s.timer = nil
	if s.closed || !s.hasPending {
		return
	}
	// The scheduler alone cannot enforce "at most one write per interval":
	// this timer may have been armed before the write that just happened.
	// Re-arm for the remainder instead of writing early, so the rate limit
	// holds no matter how the timers were scheduled.
	if wait := s.interval - s.now().Sub(s.lastBanAt); wait > 0 {
		s.armTimerLocked(wait)
		return
	}
	err := s.writeBansLocked()
	if err == nil {
		return
	}
	s.deferredErr = err
	if s.retries >= maxWriteRetries {
		s.log.Error("giving up on the debounced ban write; state stays in memory until the next save or Flush",
			"attempts", s.retries+1, "error", err)
		s.retries = 0 // a later SaveBans gets a fresh budget
		return
	}
	s.retries++
	delay := s.interval << uint(s.retries-1)
	if delay <= 0 || delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	s.log.Warn("ban write failed; retrying", "attempt", s.retries, "retry_in", delay, "error", err)
	s.armTimerLocked(delay)
}

func (s *Store) flushLocked() error {
	s.cancelTimerLocked()
	if err := s.writeBansLocked(); err != nil {
		s.deferredErr = err // sticky: every later Close/Flush sees it again
		return err
	}
	// The state on disk is now current, so an older failure is history and
	// must not be reported as if data were at risk.
	s.deferredErr = nil
	s.retries = 0
	return nil
}

// writeBansLocked persists pendingBans. On failure the pending state is kept
// so that a retry or Flush still writes it instead of dropping bans.
func (s *Store) writeBansLocked() error {
	if !s.hasPending {
		return nil
	}
	bans := s.pendingBans
	if bans == nil {
		bans = []model.Ban{} // encode as [], not null
	}
	data, err := marshalState(bansFile{
		envelope: envelope{Version: stateVersion},
		Bans:     bans,
	})
	if err != nil {
		return fmt.Errorf("store: encode %s: %w: %w", BansFile, ErrNotPersisted, err)
	}
	if err := s.writeFile(s.dir, BansFile, data); err != nil {
		return saveError(BansFile, err)
	}
	s.hasPending = false
	s.lastBanAt = s.now()
	s.retries = 0
	if s.deferredErr != nil {
		s.log.Info("ban state is durable again after an earlier write failure",
			"earlier_error", s.deferredErr)
		s.deferredErr = nil
	}
	return nil
}

// saveError classifies a failed state write. A write that never reached the
// file leaves the state only in memory, which is what ErrNotPersisted
// promises; a rename that landed but whose directory fsync failed is already
// visible to the next reader, so labelling it "not persisted" would tell the
// shutdown path to protect data that is in fact on disk.
func saveError(base string, err error) error {
	if errors.Is(err, ErrNotDurable) {
		return fmt.Errorf("store: save %s: %w", base, err)
	}
	return fmt.Errorf("store: save %s: %w: %w", base, ErrNotPersisted, err)
}

// deferredFailure labels an error that belongs to an earlier debounced write.
// Without the label the caller cannot tell it from a failure of the call it
// just made — and the state it just handed over is fine, safely in memory and
// queued for the next write.
func deferredFailure(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("store: an earlier debounced %s write failed: %w", BansFile, err)
}

// validBans drops the entries the load path refuses, so that both paths agree
// on what a valid ban is. Asymmetric validation would let a store hand out,
// within one run, exactly the value a restart silently discards.
//
// Individual junk entries are dropped rather than the whole file: one broken
// line must not cost every other ban. This package is the quarantine
// boundary; downstream code should not have to defend itself against values
// that cannot occur.
//
// The result is always a fresh slice, never aliasing the input.
func (s *Store) validBans(bans []model.Ban, origin string) []model.Ban {
	kept := bans[:0:0]
	var invalid, backwards int
	sample := ""
	for i, b := range bans {
		switch {
		case !b.IP.IsValid():
			invalid++
			if sample == "" {
				sample = fmt.Sprintf("entry %d has an invalid address", i)
			}
		case b.Until.Before(b.At):
			backwards++
			if sample == "" {
				sample = fmt.Sprintf("entry %d (%s) expires %s, before it started %s",
					i, b.IP, b.Until.Format(time.RFC3339), b.At.Format(time.RFC3339))
			}
		default:
			kept = append(kept, b)
		}
	}
	if dropped := invalid + backwards; dropped > 0 {
		// One line with a count, not one line per entry: a corrupt file with
		// 50k bad entries must not turn startup into 50k log lines
		// (PROJECT.md §4.9 asks for rate-limited repeated errors).
		s.log.Warn("dropped unusable ban entries", "origin", origin,
			"dropped", dropped, "kept", len(kept),
			"invalid_address", invalid, "expires_before_start", backwards,
			"example", sample)
	}
	return kept
}

// validOffsets is validBans' counterpart for checkpoints: a negative offset
// would make a source seek backwards forever, and rewinding to the start of
// the file is the safe reading. The result is always a fresh, non-nil map, so
// an empty save renders as {} rather than null.
func (s *Store) validOffsets(offsets map[string]model.Checkpoint, origin string) map[string]model.Checkpoint {
	out := make(map[string]model.Checkpoint, len(offsets))
	clamped := 0
	sample := ""
	for k, cp := range offsets {
		if cp.Offset < 0 {
			clamped++
			if sample == "" || k < sample { // map order must not pick the example
				sample = k
			}
			cp.Offset = 0
		}
		out[k] = cp
	}
	if clamped > 0 {
		s.log.Warn("clamped negative checkpoint offsets to 0", "origin", origin,
			"clamped", clamped, "example_key", sample)
	}
	return out
}

func (s *Store) setOffsets(offsets map[string]model.Checkpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setOffsetsLocked(offsets)
}

// setOffsetsLocked rebuilds both the primary map and the by-path index. The
// keys are walked in sorted order: map iteration order must not decide which
// checkpoint a source resumes from.
func (s *Store) setOffsetsLocked(offsets map[string]model.Checkpoint) {
	s.offsets = maps.Clone(offsets)
	if s.offsets == nil {
		s.offsets = make(map[string]model.Checkpoint)
	}
	s.byPath = make(map[string]model.Checkpoint, len(offsets))

	var clashed []string                // paths named more than once, in key order
	winner := make(map[string]string)   // path -> key of the entry we kept
	discarded := make(map[string]int64) // the furthest offset we did not take
	for _, k := range slices.Sorted(maps.Keys(offsets)) {
		v := offsets[k]
		key := v.Path
		if key == "" {
			// Nothing better to index it by; the key is the caller's own
			// choice of identifier and may well be the path.
			key = k
		}
		prev, clash := s.byPath[key]
		if !clash {
			s.byPath[key] = v
			winner[key] = k
			continue
		}
		if _, seen := discarded[key]; !seen {
			clashed = append(clashed, key)
		}
		loser := v
		if v.Offset > prev.Offset {
			s.byPath[key] = v
			winner[key] = k
			loser = prev
		}
		discarded[key] = max(discarded[key], loser.Offset)
	}
	s.reportClashesLocked(clashed, winner, discarded)
}

// reportClashesLocked warns about paths named by more than one checkpoint —
// once per path, and again only if a different entry starts winning. Two
// monitors on one log file is a legitimate configuration whose offsets both
// advance, and the daemon rebuilds this index on every SaveOffsets (every 5s):
// warning per rebuild, or even per change of offset, would fill the log
// forever. PROJECT.md §4.9 asks for repeated errors to be rate-limited.
func (s *Store) reportClashesLocked(clashed []string, winner map[string]string, discarded map[string]int64) {
	for _, path := range clashed {
		if last, warned := s.clashWarned[path]; warned && last == winner[path] {
			continue // same clash, same answer: nothing new to tell the operator
		}
		s.clashWarned[path] = winner[path]
		// Separate keys for the two offsets: a single list left the reader
		// guessing which of the numbers was actually used. Naming the winner
		// also keeps the message true on the branch that drops the candidate.
		s.log.Warn("several checkpoints name the same file; resuming from the furthest one",
			"path", path, "kept_key", winner[path],
			"kept_offset", s.byPath[path].Offset, "discarded_offset", discarded[path])
	}
	// Forget paths that no longer clash, so the map cannot grow without bound
	// and a recurrence is reported again.
	maps.DeleteFunc(s.clashWarned, func(path string, _ string) bool {
		return !slices.Contains(clashed, path)
	})
}

// loadOffsetsFromDisk reads offsets.json. The second result reports whether
// the file was actually there and usable, which is what tells SaveOffsets
// that skipping an unchanged write is safe.
func (s *Store) loadOffsetsFromDisk() (map[string]model.Checkpoint, bool, error) {
	var file offsetsFile
	ok, err := s.readState(OffsetsFile, &file)
	if err != nil || !ok {
		return nil, false, err
	}
	return s.validOffsets(file.Offsets, OffsetsFile), true, nil
}

// envelope is the head both state files share: the version tag readState
// checks. Declaring it once means readState can do that check itself instead
// of every caller repeating an anonymous struct and a closure to reach its
// own Version field.
type envelope struct {
	Version int `json:"version"`
}

func (e envelope) fileVersion() int { return e.Version }

// versioned is what readState needs of a decode target.
type versioned interface{ fileVersion() int }

type bansFile struct {
	envelope
	Bans []model.Ban `json:"bans"`
}

type offsetsFile struct {
	envelope
	Offsets map[string]model.Checkpoint `json:"offsets"`
}

type historyFile struct {
	envelope
	Events []model.BanEvent `json:"events"`
}

// readState reads and decodes a state file. It reports ok=false (with a nil
// error) when the file is absent, empty, oversized, unparseable or of an
// unknown version; in the latter four cases the file is quarantined first. A
// non-nil error means the directory itself is unusable, which the caller
// should treat as fatal.
func (s *Store) readState(base string, dst versioned) (bool, error) {
	path := filepath.Join(s.dir, base)
	data, err := s.readCapped(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil // first run
	case errors.Is(err, errTooLarge):
		s.quarantine(base, err)
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		s.quarantine(base, errors.New("file is empty"))
		return false, nil
	}
	if err := json.Unmarshal(data, dst); err != nil {
		s.quarantine(base, err)
		return false, nil
	}
	if v := dst.fileVersion(); v != stateVersion {
		s.quarantine(base, fmt.Errorf("unsupported state version %d (want %d)", v, stateVersion))
		return false, nil
	}
	return true, nil
}

// readCapped reads a file, refusing anything larger than maxFileSize so that
// a garbage (or malicious) state file cannot be turned into a multi-gigabyte
// allocation before we even discover it is garbage.
func (s *Store) readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only handle

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if fi.Size() > s.maxFileSize {
		return nil, fmt.Errorf("%w: %d bytes (limit %d)", errTooLarge, fi.Size(), s.maxFileSize)
	}
	// LimitReader guards the gap between Stat and the read: a pipe or a file
	// someone is still appending to reports a size that means nothing.
	data, err := io.ReadAll(io.LimitReader(f, s.maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > s.maxFileSize {
		return nil, fmt.Errorf("%w: grew past %d bytes while being read", errTooLarge, s.maxFileSize)
	}
	return data, nil
}

// sweepTempFiles removes the temp files of writes that never completed — a
// crash between create and rename, or a rename that failed because the
// directory was unwritable. Holding the exclusive lock is what makes this
// safe: no other process can have a write in flight here.
func (s *Store) sweepTempFiles() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.log.Warn("could not scan the state directory for leftover temp files", "error", err)
		return
	}
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() {
			continue
		}
		if !strings.HasPrefix(name, BansFile+tempPrefix) && !strings.HasPrefix(name, OffsetsFile+tempPrefix) && !strings.HasPrefix(name, HistoryFile+tempPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			s.log.Warn("could not remove leftover temp file", "file", name, "error", err)
			continue
		}
		s.log.Info("removed the temp file of an interrupted write", "file", name)
	}
}

// quarantine renames a bad state file aside instead of deleting it: the
// operator may need the evidence, and a silently vanished file makes a
// post-mortem impossible.
func (s *Store) quarantine(base string, cause error) {
	src := filepath.Join(s.dir, base)
	dst := src + CorruptSuffix
	if err := os.Rename(src, dst); err != nil {
		s.log.Error("could not set aside corrupt state file; starting from empty state",
			"file", src, "cause", cause, "error", err)
		return
	}
	if err := fsyncDir(s.dir); err != nil {
		s.log.Warn("corrupt state file renamed but directory not synced", "file", dst, "error", err)
	}
	s.log.Error("corrupt state file set aside; starting from empty state",
		"file", src, "moved_to", dst, "cause", cause)
}

// marshalState renders state indented and newline-terminated, because these
// files are meant to be read (and occasionally hand-edited) by operators.
func marshalState(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func orDefaultLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}
