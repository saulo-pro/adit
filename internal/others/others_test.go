package others

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const scutilList = `Available network connection services in the current set (*=enabled):
* (Connected)      AAAAAAAA-0000-4000-8000-000000000001 VPN (com.wireguard.macos) "williamsburg"                            [VPN:com.wireguard.macos]
* (Disconnected)   AAAAAAAA-0000-4000-8000-000000000002 VPN (com.wireguard.macos) "office network"  [VPN:com.wireguard.macos]
* (Connected)      11111111-2222-3333-4444-555555555555 VPN (com.cisco.anyconnect) "corp"  [VPN:com.cisco.anyconnect]
`

const scutilStatus = `Connected
Extended Status <dictionary> {
  IPv4 : <dictionary> {
    Addresses : <array> {
      0 : 10.99.3.254
    }
    InterfaceName : utun7
  }
}
`

func TestTheAppsTunnelsComeFromScutil(t *testing.T) {
	var asked []string
	f := &Finder{WireGuardDir: t.TempDir(), Run: func(name string, args ...string) ([]byte, error) {
		asked = append(asked, strings.Join(args, " "))
		if args[1] == "list" {
			return []byte(scutilList), nil
		}
		return []byte(scutilStatus), nil
	}}

	tunnels := f.All()
	if len(tunnels) != 2 {
		t.Fatalf("got %+v; the Cisco VPN is not a WireGuard app tunnel", tunnels)
	}
	williamsburg, office := tunnels[0], tunnels[1]
	if williamsburg.Name != "williamsburg" || williamsburg.State != "connected" || williamsburg.Interface != "utun7" || williamsburg.Source != SourceApp {
		t.Errorf("williamsburg: %+v", williamsburg)
	}
	if office.Name != "office network" || office.State != "disconnected" || office.Interface != "" {
		t.Errorf("office network: %+v", office)
	}
	if strings.Join(asked, "; ") != "--nc list; --nc status AAAAAAAA-0000-4000-8000-000000000001" {
		t.Errorf("asked scutil %q; only connected tunnels need their interface", asked)
	}
}

func TestNoAppIsNoTunnels(t *testing.T) {
	f := &Finder{WireGuardDir: t.TempDir(), Run: func(string, ...string) ([]byte, error) { return nil, errors.New("no scutil") }}
	if tunnels := f.All(); len(tunnels) != 0 {
		t.Errorf("got %+v", tunnels)
	}
}

func TestWgQuicksTunnelsReportTheirDevice(t *testing.T) {
	dir, err := os.MkdirTemp("", "wg") // short: a socket path must fit in 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "diner.name"), []byte("utun8\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "evil.name"), []byte("../../etc/passwd\n"), 0o600)

	l, err := net.Listen("unix", filepath.Join(dir, "utun8.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		conn.Read(buf)
		conn.Write([]byte("private_key=" + strings.Repeat("aa", 32) + "\npublic_key=" + strings.Repeat("bb", 32) +
			"\nlast_handshake_time_sec=1795000000\nlast_handshake_time_nsec=0\nrx_bytes=100\ntx_bytes=200\nerrno=0\n\n"))
	}()

	f := &Finder{WireGuardDir: dir, Run: func(string, ...string) ([]byte, error) { return nil, errors.New("no scutil") }}
	tunnels := f.All()
	if len(tunnels) != 1 {
		t.Fatalf("got %+v; a name file pointing outside utunN must be ignored", tunnels)
	}
	diner := tunnels[0]
	if diner.Name != "diner" || diner.Interface != "utun8" || diner.Source != SourceWgQuick || len(diner.Peers) != 1 {
		t.Fatalf("got %+v", diner)
	}
	if peer := diner.Peers[0]; peer.Received != 100 || peer.Sent != 200 || !peer.LastHandshake.Equal(time.Unix(1795000000, 0)) {
		t.Errorf("peer %+v", peer)
	}
}

func TestDescribe(t *testing.T) {
	tunnels := []Tunnel{{Name: "williamsburg", Source: SourceApp, Interface: "utun7"}, {Name: "diner", Source: SourceWgQuick, Interface: "utun8"}}
	for iface, want := range map[string]string{
		"utun7": "utun7 (the WireGuard app's williamsburg)",
		"utun8": "utun8 (wg-quick's diner)",
		"utun9": "utun9, another program's tunnel",
	} {
		if got := Describe(tunnels, iface); got != want {
			t.Errorf("%s: %q, want %q", iface, got, want)
		}
	}
}
