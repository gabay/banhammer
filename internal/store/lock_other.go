//go:build !unix

package store

import (
	"fmt"
	"os"
)

// lockFileName is unused off unix but keeps the two implementations symmetric.
const lockFileName = ".lock"

// acquireLock fails on platforms without flock. Banhammer is a unix daemon;
// refusing to start is safer than pretending the state dir is exclusive.
func acquireLock(dir string) (*os.File, error) {
	return nil, fmt.Errorf("state directory %s: locking is not supported on this platform", dir)
}

func releaseLock(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Close()
}
