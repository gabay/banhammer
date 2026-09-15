//go:build unix

package source

import (
	"fmt"
	"io/fs"
	"syscall"
)

// fileID is the (device, inode) pair that identifies a file independently of
// its name. Rotation is exactly "the path now names a different fileID".
type fileID struct {
	dev uint64
	ino uint64
}

func statID(fi fs.FileInfo) (fileID, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("stat %s: unsupported FileInfo backing %T", fi.Name(), fi.Sys())
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

// linkCount reports how many names the file still has. Zero means it was
// unlinked, which is what separates "deleted" from "renamed by logrotate":
// a renamed file keeps its link and may still be written to.
func linkCount(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
