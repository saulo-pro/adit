//go:build !darwin && !linux

package server

import (
	"errors"
	"net"
	"strconv"
)

var errUnsupported = errors.New("aditd runs only on macOS and Linux for now")

func Listen(path, group string) (*net.UnixListener, error) { return nil, errUnsupported }
func peerUID(conn *net.UnixConn) (int, error)              { return -1, errUnsupported }
func inGroup(uid int, group string) (bool, error)          { return false, errUnsupported }
func username(uid int) string                              { return strconv.Itoa(uid) }
