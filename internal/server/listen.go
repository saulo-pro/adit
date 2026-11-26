//go:build darwin || linux

package server

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
)

// Listen creates aditd's socket at path. The file is root's with group group and mode 0660, so the
// kernel lets only root and the group's members connect; with no group it is 0600, root only.
func Listen(path, group string) (*net.UnixListener, error) {
	gid := -1
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return nil, fmt.Errorf("the group %s does not exist; sudo adit install creates it", group)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}

	// Born unreadable, then opened to the group: no moment when anyone else could connect.
	previous := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(previous)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			l.Close()
			return nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

// removeStale deletes a socket left by an aditd that is gone, and nothing else.
func removeStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; aditd will not replace it", path)
	}
	if conn, err := net.Dial("unix", path); err == nil {
		conn.Close()
		return fmt.Errorf("another aditd is already answering on %s", path)
	}
	return os.Remove(path)
}

func username(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// inGroup asks the system's directory, so a member added a moment ago counts at once.
func inGroup(uid int, group string) (bool, error) {
	if group == "" {
		return false, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return false, nil
		}
		return false, err
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, g.Gid), nil
}
