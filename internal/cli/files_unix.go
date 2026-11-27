//go:build unix

package cli

import (
	"io/fs"
	"syscall"
)

// noFollow refuses a final symbolic link; nonBlock keeps opening a FIFO from waiting.
const (
	noFollow = syscall.O_NOFOLLOW
	nonBlock = syscall.O_NONBLOCK
)

func ownerUID(info fs.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
