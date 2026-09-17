package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// stateFilePerm is deliberately world-readable: the state files hold no
// secrets and an operator inspecting them should not need to be root.
const stateFilePerm fs.FileMode = 0o644

// writeFileAtomic writes data to dir/base such that a crash at any point
// leaves either the previous contents of the file or the new ones, never a
// truncated mixture.
func writeFileAtomic(dir, base string, data []byte) error {
	return atomicWrite(dir, base, data, plainWrite)
}

func plainWrite(f *os.File, data []byte) error {
	_, err := f.Write(data)
	return err
}

// atomicWrite is writeFileAtomic with the data-writing step factored out so
// that tests can inject I/O failures (a full disk, a short write) without
// needing a real full filesystem.
//
// The sequence is: write a temp file in the *same* directory (so the rename
// cannot cross filesystems), fsync it, rename it over the target, then fsync
// the directory so the rename itself is durable.
func atomicWrite(dir, base string, data []byte, write func(*os.File, []byte) error) (err error) {
	target := filepath.Join(dir, base)

	// The temp name shares tempPrefix with the sweep at Open, so debris from
	// an interrupted write is always recognisable.
	f, err := os.CreateTemp(dir, base+tempPrefix+"*")

	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if err == nil {
			return
		}
		// The temp file is useless now; leaving it behind would leak one
		// file per failed write. Report a failed cleanup rather than hide it.
		if !closed {
			_ = f.Close() // already failing; the close error adds nothing
		}
		if rmErr := os.Remove(tmp); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temp file %s: %w", tmp, rmErr))
		}
	}()

	// CreateTemp makes the file 0600; widen it before it becomes the target.
	if err = f.Chmod(stateFilePerm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err = write(f, data); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	closed = true
	if err = os.Rename(tmp, target); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, target, err)
	}
	if err = fsyncDir(dir); err != nil {
		// The rename already happened, so the new contents are visible but
		// possibly not durable. That is a weaker failure than "the data never
		// reached the file", so it is tagged ErrNotDurable: a caller that
		// treated it as ErrNotPersisted would refuse to hand over a state
		// directory whose contents are in fact correct. The deferred cleanup
		// still runs and still tries to remove the temp name; that is
		// harmless, because the name is gone and a not-exist removal is
		// tolerated above.
		err = fmt.Errorf("durability of %s: %w: %w", target, ErrNotDurable, err)
		return err
	}

	return nil
}

// fsyncDir flushes a directory entry change (a rename, a creation) to disk.
// Without it a crash can resurrect the old name even though the rename
// "completed".
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	defer d.Close() //nolint:errcheck // read-only handle, nothing to flush on close
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}
