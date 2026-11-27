//go:build !unix

package main

import "errors"

func openLog(string) error {
	return errors.New("a log file is only supported on macOS")
}

func writePid(string) error {
	return errors.New("a pid file is only supported on macOS")
}
