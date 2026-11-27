package cli

import (
	"io"
	"os"
	"path/filepath"
)

// stageCopies copies aditd and the tray (when tray is not empty) into a new folder only its owner,
// root under sudo, can enter. The caller removes it with the returned function.
func stageCopies(aditd, tray string) ([2]string, func(), error) {
	var staged [2]string
	dir, err := os.MkdirTemp("", "adit-install-")
	if err != nil {
		return staged, func() {}, err
	}
	cleanUp := func() { os.RemoveAll(dir) }
	for i, source := range []string{aditd, tray} {
		if source == "" {
			continue
		}
		staged[i] = filepath.Join(dir, filepath.Base(source))
		if err := copyFile(source, staged[i]); err != nil {
			cleanUp()
			return staged, func() {}, err
		}
	}
	return staged, cleanUp, nil
}

func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writableByOthers walks from path up to / and names the first file or folder that an account other
// than root owns, or that a group or everyone may write (a sticky folder such as /tmp is fine for
// what lies below it only when root owns that).
func writableByOthers(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	for p := resolved; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return ""
		}
		if uid, ok := ownerUID(info); ok {
			sticky := info.Mode()&os.ModeSticky != 0 && p != resolved
			if uid != 0 || (info.Mode().Perm()&0o022 != 0 && !sticky) {
				return p
			}
		}
		if p == filepath.Dir(p) {
			return ""
		}
	}
}
