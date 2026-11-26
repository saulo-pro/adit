// Package others finds the WireGuard tunnels other software runs on this Mac, so adit can show them
// beside its own, read-only: the official WireGuard app's and wg-quick's.
package others

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/saulo-pro/adit/internal/tunnel"
)

const (
	SourceWgQuick = "wg-quick"
	SourceApp     = "WireGuard app"
)

// Tunnel is another program's tunnel. Only wg-quick's report handshakes and counters: the app
// keeps those to itself.
type Tunnel struct {
	Name      string
	Source    string
	State     string // the app's own word, such as "connected"; for wg-quick, "running"
	Interface string
	Peers     []tunnel.PeerStatus // wg-quick only
}

// Finder reads other software's tunnels; its fields let tests stand in for the Mac.
type Finder struct {
	WireGuardDir string // where wg-quick keeps NAME.name and utunN.sock
	Run          func(name string, args ...string) ([]byte, error)
}

// All returns every tunnel the Finder can see, the app's then wg-quick's. A source it cannot read
// is skipped: showing the others is a courtesy, not a reason to fail.
func (f *Finder) All() []Tunnel {
	return append(f.app(), f.wgQuick()...)
}

// wgQuick reads each tunnel wg-quick brought up: its name from NAME.name, its state from the
// device's control socket, which only root may open.
func (f *Finder) wgQuick() []Tunnel {
	names, _ := filepath.Glob(filepath.Join(f.WireGuardDir, "*.name"))
	var tunnels []Tunnel
	for _, path := range names {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		iface := strings.TrimSpace(string(content))
		if !validInterface(iface) {
			continue
		}
		t := Tunnel{Name: strings.TrimSuffix(filepath.Base(path), ".name"), Source: SourceWgQuick, State: "running", Interface: iface}
		if status, err := ask(filepath.Join(f.WireGuardDir, iface+".sock")); err == nil {
			t.Peers = status.Peers
		}
		tunnels = append(tunnels, t)
	}
	return tunnels
}

var utun = regexp.MustCompile(`^utun[0-9]+$`)

func validInterface(name string) bool {
	return utun.MatchString(name)
}

// ask sends a device the get request of WireGuard's configuration protocol.
func ask(socket string) (tunnel.Status, error) {
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return tunnel.Status{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		return tunnel.Status{}, err
	}
	var text strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		text.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil {
		return tunnel.Status{}, err
	}
	return tunnel.ParseStatus(strings.TrimSuffix(filepath.Base(socket), ".sock"), text.String())
}

// The app's tunnels in scutil --nc list, such as:
//
//   - (Connected)      AAAAAAAA-0000-4000-8000-000000000001 VPN (com.wireguard.macos) "williamsburg"   [VPN:com.wireguard.macos]
var appLine = regexp.MustCompile(`^\*?\s*\(([A-Za-z]+)\)\s+([0-9A-F-]{36})\s+VPN \(com\.wireguard\.macos\)\s+"(.*)"\s+\[`)

var interfaceLine = regexp.MustCompile(`^\s*InterfaceName : (utun[0-9]+)\s*$`)

// app asks macOS's network configuration for the official app's tunnels, and for the interface of
// each one connected.
func (f *Finder) app() []Tunnel {
	output, err := f.Run("/usr/sbin/scutil", "--nc", "list")
	if err != nil {
		return nil
	}
	var tunnels []Tunnel
	for line := range strings.Lines(string(output)) {
		m := appLine.FindStringSubmatch(strings.TrimRight(line, "\n"))
		if m == nil {
			continue
		}
		state, id, name := strings.ToLower(m[1]), m[2], m[3]
		t := Tunnel{Name: name, Source: SourceApp, State: state}
		if state == "connected" || state == "connecting" {
			t.Interface = f.appInterface(id)
		}
		tunnels = append(tunnels, t)
	}
	return tunnels
}

func (f *Finder) appInterface(id string) string {
	output, err := f.Run("/usr/sbin/scutil", "--nc", "status", id)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(output)) {
		if m := interfaceLine.FindStringSubmatch(strings.TrimRight(line, "\n")); m != nil {
			return m[1]
		}
	}
	return ""
}

// Describe names the software behind an interface for a message, from the tunnels found.
func Describe(tunnels []Tunnel, iface string) string {
	for _, t := range tunnels {
		if t.Interface == iface {
			if t.Source == SourceApp {
				return fmt.Sprintf("%s (the WireGuard app's %s)", iface, t.Name)
			}
			return fmt.Sprintf("%s (%s's %s)", iface, t.Source, t.Name)
		}
	}
	return iface + ", another program's tunnel"
}
