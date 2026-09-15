package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if err := writeFileAtomic(dir, "f.json", []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeFileAtomic(dir, "f.json", []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "f.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
	// No temp files may survive a successful write.
	if names := dirEntries(t, dir); len(names) != 1 || names[0] != "f.json" {
		t.Errorf("dir contains %v, want only the target", names)
	}
	fi, err := os.Stat(filepath.Join(dir, "f.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != stateFilePerm {
		t.Errorf("mode = %v, want %v", fi.Mode().Perm(), stateFilePerm)
	}
}

func TestAtomicWriteFailureLeavesNoDebris(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		write   func(*os.File, []byte) error
		wantErr error
	}{
		{
			name:    "full disk",
			write:   func(*os.File, []byte) error { return syscall.ENOSPC },
			wantErr: syscall.ENOSPC,
		},
		{
			name:    "io error",
			write:   func(*os.File, []byte) error { return errors.New("disk on fire") },
			wantErr: nil,
		},
		{
			name: "partial write then failure",
			write: func(f *os.File, b []byte) error {
				if _, err := f.Write(b[:len(b)/2]); err != nil {
					return err
				}
				return syscall.ENOSPC
			},
			wantErr: syscall.ENOSPC,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			target := filepath.Join(dir, "f.json")
			if err := os.WriteFile(target, []byte("old but valid"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}

			err := atomicWrite(dir, "f.json", []byte("brand new contents"), tc.write)
			if err == nil {
				t.Fatal("atomicWrite succeeded, want failure")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}

			// The previous, good file must be untouched...
			got, readErr := os.ReadFile(target)
			if readErr != nil {
				t.Fatalf("read target: %v", readErr)
			}
			if string(got) != "old but valid" {
				t.Errorf("target was clobbered: %q", got)
			}
			// ...and no half-written temp file may be left behind.
			if names := dirEntries(t, dir); len(names) != 1 || names[0] != "f.json" {
				t.Errorf("dir contains %v, want only the untouched target", names)
			}
		})
	}
}

func TestAtomicWriteMissingDir(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	err := writeFileAtomic(dir, "f.json", []byte("x"))
	if err == nil {
		t.Fatal("writeFileAtomic succeeded on a missing directory")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want a not-exist error", err)
	}
}

func TestFsyncDirMissing(t *testing.T) {
	t.Parallel()
	if err := fsyncDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("fsyncDir succeeded on a missing directory")
	}
}
