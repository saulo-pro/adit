package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID asks the kernel which user is on the other end: the caller cannot choose the answer.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
