//go:build unix

package store

import (
	"io/fs"
	"os"
	"syscall"
)

func ownedByMe(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || int(stat.Uid) == os.Geteuid()
}
