//go:build !darwin

package api

import (
	"errors"
	"net"
)

func peerUID(net.Conn) (int, error) {
	return -1, errors.New("checking who answers on the socket is only supported on macOS")
}
