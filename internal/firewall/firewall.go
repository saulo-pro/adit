// Package firewall is a full tunnel's kill switch: a pf anchor of aditd's own that blocks every
// packet that does not go through one of adit's tunnels, so that when the full tunnel is down,
// coming up or gone with a dead aditd, nothing leaves the Mac around it.
//
// The anchor sits under com.apple/, which macOS's /etc/pf.conf loads, so adit never edits pf.conf.
// pf is enabled with a reference (pfctl -E), so another program that uses pf keeps it on when adit
// lets go. The anchor stays in the kernel when aditd dies: traffic stays blocked until aditd, back,
// takes over again, or `adit uninstall` removes it.
package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// DefaultAnchor sorts before Apple's own anchors (200.AirDrop, 250.ApplicationFirewall): pf
	// reads com.apple's anchors in name order, and an earlier anchor that passes traffic would let
	// it through adit's block.
	DefaultAnchor    = "com.apple/000.adit"
	DefaultStateFile = "/var/run/adit/firewall.json"
)

// Rules are what the anchor lets through. With BlockAll (the kill switch), only adit's tunnels and
// what they need; without it, everything but the local network (a full tunnel's `lan block`).
type Rules struct {
	Interfaces []string         // adit's tunnel interfaces that are up
	Servers    []netip.AddrPort // every adit tunnel's server: only root (aditd) may send to them
	BlockAll   bool             // the kill switch: block what does not go through adit's tunnels
	AllowLAN   bool             // the local network: printers, file shares, AirDrop
	Guards     []string         // the full tunnels the kill switch is on for; kept for aditd's next start
}

// Firewall loads and removes the anchor with pfctl.
type Firewall struct {
	Anchor    string
	StateFile string
	// Run runs /sbin/pfctl with args, giving it stdin when not empty.
	Run func(stdin string, args ...string) ([]byte, error)
}

// state is what the kill switch keeps across aditd's restarts, in /var/run (gone at boot, as the
// anchor is).
type state struct {
	Token   string   `json:"token"`   // pf's reference, released with pfctl -X
	Ruleset string   `json:"ruleset"` // as last loaded
	Guards  []string `json:"guards"`
}

// Block loads the rules into the anchor, if they differ from what is loaded, and makes sure pf is on.
func (f *Firewall) Block(r Rules) error {
	s, err := f.load()
	if err != nil {
		return err
	}
	ruleset := Ruleset(r)
	if s.Token != "" && s.Ruleset == ruleset && f.loaded() {
		if !slices.Equal(s.Guards, r.Guards) {
			s.Guards = r.Guards
			return f.save(s)
		}
		return nil
	}
	if output, err := f.Run(ruleset, "-a", f.Anchor, "-f", "-"); err != nil {
		return fmt.Errorf("pf refused the kill switch's rules: %s", lastLine(output, err))
	}
	if !f.loaded() {
		return fmt.Errorf("pf did not keep the kill switch's rules")
	}
	if s.Token == "" {
		output, err := f.Run("", "-E")
		token := tokenOf(string(output))
		if err != nil || token == "" {
			return fmt.Errorf("pf did not turn on: %s", lastLine(output, err))
		}
		s.Token = token
	}
	s.Ruleset, s.Guards = ruleset, r.Guards
	return f.save(s)
}

// Release removes the anchor's rules and lets go of pf, which stays on only if another program
// holds it. It does nothing when the kill switch is off already.
func (f *Firewall) Release() error {
	s, err := f.load()
	if err != nil {
		return err
	}
	if s.Token == "" && !f.loaded() {
		return f.remove()
	}
	if output, err := f.Run("", "-a", f.Anchor, "-F", "all"); err != nil {
		return fmt.Errorf("pf did not drop the kill switch's rules: %s", lastLine(output, err))
	}
	if s.Token != "" {
		// A token from before a reboot, or already released, is refused: nothing to undo then.
		f.Run("", "-X", s.Token)
	}
	return f.remove()
}

// Guards are the full tunnels the kill switch was on for, as an earlier aditd left it: at start, aditd
// brings them back up rather than leave the Mac blocked for nothing, or lets go when none is left.
func (f *Firewall) Guards() ([]string, error) {
	s, err := f.load()
	return s.Guards, err
}

// loaded says whether the anchor holds rules now.
func (f *Firewall) loaded() bool {
	output, err := f.Run("", "-a", f.Anchor, "-s", "rules")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "pass ") || strings.HasPrefix(line, "block ") {
			return true
		}
	}
	return false
}

// lan is the local network as the market's "allow LAN" means it: private, link-local and multicast
// IPv4, and unique local IPv6.
var lan = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fc00::/7",
}

// link is IPv6's link-local and multicast: neighbour discovery and router advertisements need them
// for IPv6 to work at all, so they pass whatever the local network setting.
var link = []string{"fe80::/10", "ff00::/8"}

// Ruleset writes the anchor's rules. pf reads them top to bottom and stops at the first quick rule
// that matches. Passes on loopback, the tunnels and the local network keep no state: a connection
// already open when the kill switch comes on keeps going (with state, pf would only let its first
// packet through). Interface names and addresses come from the system and parsed configurations,
// never from text a person typed.
func Ruleset(r Rules) string {
	var b strings.Builder
	if r.BlockAll {
		b.WriteString("# adit's kill switch: what does not go through adit's tunnels is blocked.\n")
	} else {
		b.WriteString("# adit's full tunnel blocks the local network.\n")
	}
	b.WriteString("pass quick on lo0 no state\n")
	if len(r.Interfaces) > 0 {
		fmt.Fprintf(&b, "pass quick on { %s } no state\n", strings.Join(r.Interfaces, " "))
	}
	for _, server := range r.Servers {
		fmt.Fprintf(&b, "pass out quick proto udp to %s port %d user root keep state\n", server.Addr().Unmap(), server.Port())
	}
	// DHCP, so the Mac can join a network at all.
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67 no state\n")
	b.WriteString("pass in quick inet proto udp from any port 67 to any port 68 no state\n")
	// By direction, here and below: out to the local network, in from it. "From a private address"
	// would match everything a Mac behind a router sends, since its own address is one.
	fmt.Fprintf(&b, "pass out quick to { %s } no state\n", strings.Join(link, " "))
	fmt.Fprintf(&b, "pass in quick from { %s } no state\n", strings.Join(link, " "))
	if r.BlockAll {
		// aditd looks the servers' names up itself, as root; nobody else's DNS leaves outside a
		// tunnel.
		b.WriteString("pass out quick proto { udp tcp } to any port 53 user root keep state\n")
		b.WriteString("block return out quick proto { udp tcp } to any port 53\n")
	}
	if r.AllowLAN {
		fmt.Fprintf(&b, "pass out quick to { %s } no state\n", strings.Join(lan, " "))
		fmt.Fprintf(&b, "pass in quick from { %s } no state\n", strings.Join(lan, " "))
	} else {
		fmt.Fprintf(&b, "block return out quick to { %s }\n", strings.Join(lan, " "))
		fmt.Fprintf(&b, "block drop in quick from { %s }\n", strings.Join(lan, " "))
	}
	if r.BlockAll {
		b.WriteString("block return out quick all\n")
		b.WriteString("block drop in quick all\n")
	}
	return b.String()
}

// tokenOf reads the reference pfctl -E prints: "Token : 1420488880338432422".
func tokenOf(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(name) == "Token" {
			token := strings.TrimSpace(value)
			if token != "" && strings.Trim(token, "0123456789") == "" {
				return token
			}
		}
	}
	return ""
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var kept []string
	for _, line := range lines {
		// pfctl warns about ALTQ and -f on every load: noise.
		if line != "" && !strings.Contains(line, "ALTQ") && !strings.Contains(line, "-f option") &&
			!strings.Contains(line, "present in the main ruleset") && !strings.Contains(line, "/etc/pf.conf for further") {
			kept = append(kept, line)
		}
	}
	if len(kept) > 0 {
		return kept[len(kept)-1]
	}
	if err != nil {
		return err.Error()
	}
	return "no reason given"
}

func (f *Firewall) load() (state, error) {
	var s state
	content, err := os.ReadFile(f.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if json.Unmarshal(content, &s) != nil {
		return state{}, nil
	}
	return s, nil
}

func (f *Firewall) save(s state) error {
	content, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.StateFile), 0o755); err != nil {
		return err
	}
	tmp := f.StateFile + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.StateFile)
}

func (f *Firewall) remove() error {
	if err := os.Remove(f.StateFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
