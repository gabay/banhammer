//go:build unix

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockFileName is the sentinel inside the state dir that daemons contend for.
// It is never removed: flock ownership is tied to the open file description,
// not to the file's existence, and unlinking it would race a competing Open.
const lockFileName = ".lock"

// lockFilePerm matches the state files' 0644 — the lock holds no secrets and
// an operator should be able to see who owns the directory — but it is spelled
// out separately: borrowing stateFilePerm made it look as if the lock were one
// of the state files, and the two are free to diverge.
const lockFilePerm fs.FileMode = 0o644

// acquireLock takes an exclusive, non-blocking flock on dir/.lock.
//
// flock is used rather than a PID file because the kernel drops the lock when
// the holding process dies for any reason, including SIGKILL and a power cut;
// a stale PID file would wedge the daemon until an operator cleaned up.
func acquireLock(dir string) (*os.File, error) {
	path := filepath.Join(dir, lockFileName)
	// O_NOFOLLOW: if someone plants a symlink here, the flock would otherwise
	// be taken on a completely unrelated file and two daemons could both
	// "own" this directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, lockFilePerm)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("lock file %s is a symlink; refusing to follow it", path)
		}
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close() //nolint:errcheck // we are already returning an error
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("state directory %s: %w", dir, ErrLocked)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return f, nil
}

// releaseLock unlocks and closes the lock file. Closing alone would release
// the flock, but the explicit unlock keeps the intent obvious.
func releaseLock(f *os.File) error {
	if f == nil {
		return nil
	}
	unlockErr := unix.Flock(int(f.Fd()), unix.LOCK_UN)
	closeErr := f.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock %s: %w", f.Name(), unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lock file %s: %w", f.Name(), closeErr)
	}
	return nil
}
