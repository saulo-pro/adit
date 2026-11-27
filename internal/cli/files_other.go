//go:build !unix

package cli

import "io/fs"

const (
	noFollow = 0
	nonBlock = 0
)

func ownerUID(fs.FileInfo) (uint32, bool) { return 0, false }
