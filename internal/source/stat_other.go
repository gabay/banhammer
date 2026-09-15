//go:build !unix

package source

import (
	"fmt"
	"io/fs"
)

// fileID is the (device, inode) pair that identifies a file independently of
// its name. Only unix exposes it, so non-unix builds compile but cannot tail.
type fileID struct {
	dev uint64
	ino uint64
}

func statID(fi fs.FileInfo) (fileID, error) {
	return fileID{}, fmt.Errorf("stat %s: inode identity is not available on this platform", fi.Name())
}

// linkCount is unavailable off unix, so callers must treat a vanished path as
// possibly-renamed rather than deleted.
func linkCount(fs.FileInfo) (uint64, bool) { return 0, false }
