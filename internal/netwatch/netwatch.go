// Package netwatch tells aditd when the Mac's network changes, so its tunnels can follow: Wi-Fi to
// Ethernet, one Wi-Fi network to another, a cable plugged in or out.
package netwatch

import (
	"encoding/binary"
	"strings"

	"github.com/saulo-pro/adit/internal/routes"
)

// Kernel routing messages that mean the network changed: an address added or removed, an interface
// up or down. Their values are the same on every BSD-derived kernel.
const (
	rtmNewAddr = 0xc
	rtmDelAddr = 0xd
	rtmIfInfo  = 0xe
)

// noisy are interfaces that come and go without the network changing: Apple's peer-to-peer
// Wi-Fi, low-latency WLAN, USB management, bridges and the virtual machine networks of Docker and
// friends.
var noisy = []string{"awdl", "llw", "anpi", "ap", "bridge", "vmenet", "gif", "stf", "lo"}

// relevant says whether a routing message reports a change on an interface a tunnel's packets
// may leave through. ifaceName maps an interface index to its name.
func relevant(message []byte, ifaceName func(index int) string) bool {
	// Every such message starts with length (2 bytes), version (1), type (1), address mask (4),
	// flags (4), interface index (2).
	if len(message) < 14 {
		return false
	}
	switch message[3] {
	case rtmNewAddr, rtmDelAddr, rtmIfInfo:
	default:
		return false
	}
	name := ifaceName(int(binary.LittleEndian.Uint16(message[12:14])))
	if name == "" || routes.TunnelInterface(name) {
		return false
	}
	for _, prefix := range noisy {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}
