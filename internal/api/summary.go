package api

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// Summary says in one sentence where the Mac's traffic goes when a full tunnel is up, or that its
// kill switch blocks it; empty when only split tunnels (or none) are up. The command line prints it
// under the list, and the menu at its top.
func Summary(tunnels []Tunnel) string {
	for _, t := range tunnels {
		if t.Blocking {
			return fmt.Sprintf("The internet is blocked until %s is up (kill switch).", t.Name)
		}
	}
	var full *Tunnel
	var splits []string
	for n, t := range tunnels {
		switch {
		case t.State == "down":
		case t.KillSwitch != "":
			full = &tunnels[n]
		default:
			splits = append(splits, t.Name)
		}
	}
	if full == nil {
		return ""
	}
	except := splits
	if full.LAN != "block" {
		except = append(except, "the local network")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Everything goes through %s", full.Name)
	if len(except) > 0 {
		fmt.Fprintf(&b, ", except %s", list(except))
	}
	if full.LAN == "block" {
		b.WriteString("; the local network is blocked")
	}
	switch full.KillSwitch {
	case "off":
		b.WriteString(". If it drops, traffic goes out directly.")
	default:
		b.WriteString(". If it drops, the internet is blocked (kill switch).")
	}
	return b.String()
}

// list joins names the way a sentence does: "a", "a and b", "a, b and c".
func list(names []string) string {
	if len(names) <= 1 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// SortByReach orders tunnels from the one that routes the least to the one that routes the most, so
// a full tunnel comes last: the order in which the routes win (a narrower route beats a wider one).
// Ties keep the order they came in: aditd's, by name.
func SortByReach(tunnels []Tunnel) []Tunnel {
	sorted := slices.Clone(tunnels)
	slices.SortStableFunc(sorted, func(a, b Tunnel) int { return cmp.Compare(reach(a), reach(b)) })
	return sorted
}

// reach is the share of the address space a tunnel routes, IPv4 and IPv6 added: 2 for everything.
func reach(t Tunnel) float64 {
	if t.KillSwitch != "" {
		return 3 // a full tunnel, whatever its networks say
	}
	var share float64
	for _, network := range t.Networks {
		if prefix, err := netip.ParsePrefix(network); err == nil {
			share += math.Ldexp(1, -prefix.Bits())
		}
	}
	return share
}
