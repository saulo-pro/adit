// Package routes reads which networks other software's tunnels route: adit compares them with a
// tunnel's AllowedIPs before bringing it up.
package routes

import (
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Route is one network the kernel sends into a tunnel interface.
type Route struct {
	Prefix    netip.Prefix
	Interface string
}

// TunnelInterface says whether an interface is a tunnel: utun (WireGuard, most VPNs), ipsec, ppp.
func TunnelInterface(name string) bool {
	for _, prefix := range []string{"utun", "ipsec", "ppp", "tun", "wg"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Missing lists the networks of want that the kernel does not route through iface exactly, given
// its routing table: a route can fail to go in (another interface already holds the same network)
// while /sbin/route still exits 0.
func Missing(table []Route, iface string, want []netip.Prefix) []netip.Prefix {
	have := map[netip.Prefix]bool{}
	for _, r := range table {
		if r.Interface == iface {
			have[r.Prefix] = true
		}
	}
	var missing []netip.Prefix
	for _, p := range want {
		if !have[p.Masked()] {
			missing = append(missing, p)
		}
	}
	return missing
}

// ignored are routes every utun carries that say nothing about which networks a tunnel serves:
// link-local, multicast, loopback and broadcast.
func ignored(p netip.Prefix) bool {
	addr := p.Addr()
	return addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// CatchAll says whether a route takes everything of its family: a full tunnel, whether as /0 or as
// the pair of /1 routes some programs use to win over the default route.
func CatchAll(p netip.Prefix) bool {
	return p.Bits() <= 1
}

// maskBits counts a netmask's leading ones.
func maskBits(mask []byte) int {
	n := 0
	for _, b := range mask {
		n += bits.LeadingZeros8(^b)
		if b != 0xff {
			break
		}
	}
	return n
}

// WireGuardDir is where wg-quick on macOS writes NAME.name, holding the utun its tunnel NAME uses.
const WireGuardDir = "/var/run/wireguard"

// Describe names the software behind an interface as well as adit can tell: wg-quick's tunnels by
// name, anything else by interface.
func Describe(dir, iface string) string {
	names, _ := filepath.Glob(filepath.Join(dir, "*.name"))
	for _, path := range names {
		if content, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(content)) == iface {
			return iface + " (wg-quick's " + strings.TrimSuffix(filepath.Base(path), ".name") + ")"
		}
	}
	return iface + ", another program's tunnel"
}
