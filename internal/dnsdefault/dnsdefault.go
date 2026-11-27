// Package dnsdefault makes a full tunnel's DNS servers the Mac's default resolver while it is up:
// every name not under a domain of /etc/resolver goes to them.
//
// It registers the tunnel in macOS's System Configuration dynamic store as a DNS service whose
// supplemental match domain is the empty domain, which matches every name: macOS then lists it first,
// ahead of the network's own resolver. The key is adit's alone (State:/Network/Service/adit-NAME/DNS);
// adit never changes another service's keys. Keys in State: are volatile: a reboot clears them, and
// aditd removes any it left when it starts.
package dnsdefault

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"
)

const keyPrefix = "State:/Network/Service/adit-"

// Default sets and clears the default resolver through scutil.
type Default struct {
	// Run runs /usr/sbin/scutil with the script on its standard input.
	Run func(script string) ([]byte, error)
}

func key(tunnel string) string {
	return keyPrefix + tunnel + "/DNS"
}

// Set makes servers the default resolver, on behalf of the tunnel. Tunnel names are letters, digits,
// dots, hyphens and underscores (store.ValidName), and the servers parsed addresses, so the script
// holds nothing scutil would read as a command.
func (d *Default) Set(tunnel string, servers []netip.Addr) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS server to use")
	}
	var list []string
	for _, server := range servers {
		list = append(list, server.String())
	}
	script := "d.init\n" +
		"d.add ServerAddresses * " + strings.Join(list, " ") + "\n" +
		"d.add SupplementalMatchDomains * \"\"\n" +
		"set " + key(tunnel) + "\n"
	if output, err := d.Run(script); err != nil || len(strings.TrimSpace(string(output))) > 0 {
		return fmt.Errorf("macOS did not take the tunnel's DNS servers: %s", strings.TrimSpace(string(output)+" "+errText(err)))
	}
	return nil
}

// Clear gives the default resolver back to the network.
func (d *Default) Clear(tunnel string) error {
	if output, err := d.Run("remove " + key(tunnel) + "\n"); err != nil {
		return fmt.Errorf("macOS did not drop the tunnel's DNS servers: %s", strings.TrimSpace(string(output)+" "+errText(err)))
	}
	return nil
}

// ClearAll removes every key adit set: at aditd's start, none is in use.
func (d *Default) ClearAll() error {
	output, err := d.Run("list " + keyPrefix + "[^/]+/DNS\n")
	if err != nil {
		return fmt.Errorf("could not list adit's DNS settings: %s", errText(err))
	}
	var script strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		// Lines read "  subKey [0] = State:/Network/Service/adit-diner/DNS".
		_, found, ok := strings.Cut(scanner.Text(), "= ")
		if ok && strings.HasPrefix(found, keyPrefix) && strings.HasSuffix(found, "/DNS") && !strings.ContainsAny(found, " \t\"") {
			script.WriteString("remove " + found + "\n")
		}
	}
	if script.Len() == 0 {
		return nil
	}
	if output, err := d.Run(script.String()); err != nil {
		return fmt.Errorf("could not remove adit's DNS settings: %s", strings.TrimSpace(string(output)+" "+errText(err)))
	}
	return nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
