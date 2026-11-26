package netwatch

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"
)

// Watch calls changed after the Mac's network changes, once things have been quiet for settle: a
// move between networks sends a burst of messages, and the tunnels should follow once. It returns
// when ctx ends.
func Watch(ctx context.Context, settle time.Duration, changed func()) error {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return err
	}
	// Non-blocking, so the runtime's poller reads it and closing it ends a read in progress.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return err
	}
	socket := os.NewFile(uintptr(fd), "routing socket")
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	defer stop()

	events := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := socket.Read(buf)
			if err != nil {
				close(events)
				return
			}
			if relevant(buf[:n], interfaceName) {
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}
	}()

	timer := time.NewTimer(settle)
	timer.Stop()
	for {
		select {
		case _, open := <-events:
			if !open {
				return ctx.Err()
			}
			timer.Reset(settle)
		case <-timer.C:
			changed()
		}
	}
}

func interfaceName(index int) string {
	if iface, err := net.InterfaceByIndex(index); err == nil {
		return iface.Name
	}
	return ""
}
