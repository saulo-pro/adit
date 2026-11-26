// Package conf reads and writes WireGuard configuration files: the .conf format of wg-quick and the
// official WireGuard apps.
//
// Parse accepts what those tools accept — setting names in any case, comments, several Address, DNS
// and AllowedIPs lines, CRLF line ends, a byte-order mark — and reports the first problem in one
// sentence with its line number. Format writes the canonical form the official apps export, so a
// file already in that form comes back byte for byte.
//
// Private and preshared keys are Secrets: they never appear in fmt output, JSON or error messages.
package conf

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Config struct {
	Interface Interface
	Peers     []Peer
}

// Interface is the [Interface] section. A zero value means the line was absent.
type Interface struct {
	PrivateKey Secret
	ListenPort uint16
	FwMark     uint32         // Linux only
	Addresses  []netip.Prefix // as written: the tunnel's own address with its prefix length
	DNS        []netip.Addr
	DNSSearch  []string // the DNS entries that are domains rather than addresses
	MTU        int
	Table      string // "off", "auto" or a routing table; Linux only
	SaveConfig bool   // Linux only

	// Shell commands wg-quick runs around bringing the tunnel up and down. They are kept so export
	// gives them back, and are never run.
	PreUp, PostUp, PreDown, PostDown []string
}

// Hooks names the hook settings present, such as "PostUp", for warning on import.
func (i *Interface) Hooks() []string {
	var names []string
	for _, hook := range i.hooks() {
		if len(hook.commands) > 0 {
			names = append(names, hook.name)
		}
	}
	return names
}

func (i *Interface) hooks() []struct {
	name     string
	commands []string
} {
	return []struct {
		name     string
		commands []string
	}{
		{"PreUp", i.PreUp},
		{"PostUp", i.PostUp},
		{"PreDown", i.PreDown},
		{"PostDown", i.PostDown},
	}
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey           Key
	PresharedKey        Secret
	AllowedIPs          []netip.Prefix // as written; Masked gives the network
	Endpoint            Endpoint
	PersistentKeepalive uint16 // seconds; 0 is off
}

// Endpoint is where a peer is reached: an IP address or a host name, and a UDP port.
type Endpoint struct {
	Host string
	Port uint16
}

func (e Endpoint) IsZero() bool {
	return e == Endpoint{}
}

func (e Endpoint) String() string {
	if e.IsZero() {
		return ""
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// Format writes c in the canonical form: settings in the order the official apps export them,
// lists joined with ", ", one blank line before each [Peer].
func Format(c *Config) []byte {
	var w writer
	i := &c.Interface

	w.section("[Interface]")
	if !i.PrivateKey.IsZero() {
		w.set("PrivateKey", i.PrivateKey.base64())
	}
	if i.ListenPort != 0 {
		w.set("ListenPort", strconv.Itoa(int(i.ListenPort)))
	}
	if i.FwMark != 0 {
		w.set("FwMark", strconv.FormatUint(uint64(i.FwMark), 10))
	}
	w.set("Address", joinPrefixes(i.Addresses))
	w.set("DNS", joinDNS(i.DNS, i.DNSSearch))
	if i.MTU != 0 {
		w.set("MTU", strconv.Itoa(i.MTU))
	}
	w.set("Table", i.Table)
	for _, hook := range i.hooks() {
		for _, command := range hook.commands {
			w.set(hook.name, command)
		}
	}
	if i.SaveConfig {
		w.set("SaveConfig", "true")
	}

	for _, p := range c.Peers {
		w.section("\n[Peer]")
		w.set("PublicKey", p.PublicKey.String())
		if !p.PresharedKey.IsZero() {
			w.set("PresharedKey", p.PresharedKey.base64())
		}
		w.set("AllowedIPs", joinPrefixes(p.AllowedIPs))
		w.set("Endpoint", p.Endpoint.String())
		if p.PersistentKeepalive != 0 {
			w.set("PersistentKeepalive", strconv.Itoa(int(p.PersistentKeepalive)))
		}
	}
	return []byte(w.String())
}

type writer struct {
	strings.Builder
}

func (w *writer) section(header string) {
	w.WriteString(header)
	w.WriteByte('\n')
}

// set writes one setting, or nothing when the value is empty.
func (w *writer) set(name, value string) {
	if value != "" {
		fmt.Fprintf(w, "%s = %s\n", name, value)
	}
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for n, prefix := range prefixes {
		parts[n] = prefix.String()
	}
	return strings.Join(parts, ", ")
}

func joinDNS(servers []netip.Addr, search []string) string {
	parts := make([]string, 0, len(servers)+len(search))
	for _, server := range servers {
		parts = append(parts, server.String())
	}
	return strings.Join(append(parts, search...), ", ")
}
