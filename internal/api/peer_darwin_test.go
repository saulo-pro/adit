package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootPeerRefusesASocketNotServedByRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test's own socket is root's when the test runs as root")
	}
	dir, err := os.MkdirTemp("", "adit")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				conn.Read(buf) // the request, before answering
				conn.Write([]byte(`{"ok":true,"version":"fake"}` + "\n"))
			}()
		}
	}()

	if _, err := (&Client{Socket: socket}).Do(context.Background(), Request{Command: CommandVersion}); err != nil {
		t.Fatalf("without RootPeer: %v", err)
	}
	_, err = (&Client{Socket: socket, RootPeer: true}).Do(context.Background(), Request{Command: CommandVersion})
	if err == nil || !strings.Contains(err.Error(), "is not root's aditd") {
		t.Errorf("with RootPeer: got %v", err)
	}
}
