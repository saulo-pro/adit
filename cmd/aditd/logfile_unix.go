//go:build unix

package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openLog makes path aditd's standard error, so its own lines and anything the runtime writes (a
// panic) land there. The file is root's alone (0600): the log names tunnels, endpoints and who asked
// for what. It is opened again after newsyslog rotates it, on SIGHUP.
func openLog(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("could not open the log %s: %w", path, err)
	}
	defer file.Close()
	// A log made by an earlier version, or by launchd, may be readable by everyone.
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	return unix.Dup2(int(file.Fd()), 2)
}

// writePid records aditd's process id where newsyslog looks for it, so a rotation sends SIGHUP.
func writePid(path string) error {
	_ = os.Remove(path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
