//go:build !unix

package store

import "io/fs"

// ownedByMe has no owner to compare on Windows; access there will come from the directory's ACL.
func ownedByMe(info fs.FileInfo) bool { return true }
