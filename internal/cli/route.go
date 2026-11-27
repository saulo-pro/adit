package cli

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/dns"
	"github.com/saulo-pro/adit/internal/dnsdefault"
)

// kernelRoute is what the kernel answers for one address: `route -n get`.
type kernelRoute struct {
	Destination string // the route that matched: an address, a network, or "default"
	Interface   string
	Gateway     string
	Blackhole   bool
}

// routeTools are what `adit route` reads, none of which needs root. Fakes stand in for them in tests.
type routeTools struct {
	get       func(addr netip.Addr) (kernelRoute, error)
	lookup    func(ctx context.Context, name string) ([]netip.Addr, error)
	resolvers *dns.Resolvers
	current   func() (tunnel string, servers []netip.Addr, err error) // the full tunnel's default resolver
}

func systemRouteTools() routeTools {
	return routeTools{
		get: kernelRouteOf,
		lookup: func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		},
		resolvers: &dns.Resolvers{Dir: dns.DefaultDir},
		current: (&dnsdefault.Default{Run: func(script string) ([]byte, error) {
			command := exec.Command("/usr/sbin/scutil")
			command.Stdin = strings.NewReader(script)
			return command.CombinedOutput()
		}}).Current,
	}
}

// kernelRouteOf asks the kernel which route an address takes. The address is a parsed one, never text
// a person typed.
func kernelRouteOf(addr netip.Addr) (kernelRoute, error) {
	family := "-inet"
	if addr.Is6() && !addr.Is4In6() {
		family = "-inet6"
	}
	output, err := exec.Command("/sbin/route", "-n", "get", family, addr.Unmap().String()).CombinedOutput()
	if err != nil {
		return kernelRoute{}, fmt.Errorf("the kernel has no route to %s: %s", addr, strings.TrimSpace(string(output)))
	}
	return parseKernelRoute(string(output)), nil
}

func parseKernelRoute(output string) kernelRoute {
	var r kernelRoute
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "destination":
			r.Destination = value
		case "interface":
			r.Interface = value
		case "gateway":
			r.Gateway = value
		case "flags":
			r.Blackhole = strings.Contains(value, "BLACKHOLE") || strings.Contains(value, "REJECT")
		}
	}
	return r
}

// routeAnswer is what `adit route` says, for scripts.
type routeAnswer struct {
	Destination string        `json:"destination"`
	Resolver    *resolverJSON `json:"resolver"` // for a name: who answers it
	Address     string        `json:"address"`
	Interface   string        `json:"interface"`
	Gateway     *string       `json:"gateway"`
	Tunnel      *string       `json:"tunnel"`  // the tunnel that carries it, adit's or another program's
	Source      *string       `json:"source"`  // "adit", "wg-quick", "WireGuard app"
	Verdict     string        `json:"verdict"` // tunnel, local, direct, outside, nowhere, mac
	Sentence    string        `json:"sentence"`
}

type resolverJSON struct {
	By      string   `json:"by"`     // an adit tunnel's name, or "network" or "file"
	Domain  string   `json:"domain"` // the resolver file's domain, if one answers
	Servers []string `json:"servers"`
}

func (c *CLI) route(ctx context.Context, out *output, args []string) error {
	positional, err := parse(out, newFlags("route"), args, 1, 1, "ADDRESS|NAME")
	if err != nil {
		return err
	}
	dest := strings.TrimSuffix(positional[0], ".")
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandList})
	if err != nil {
		return err
	}
	tools := c.routeTools
	if tools.get == nil {
		tools = systemRouteTools()
	}

	answer := routeAnswer{Destination: dest}
	var words strings.Builder
	addr, err := netip.ParseAddr(dest)
	if err != nil {
		if !validName(dest) {
			return usageError("usage: adit route ADDRESS|NAME: %q is neither an address nor a host name", dest)
		}
		resolver, sentence := resolverOf(tools, resp.Tunnels, dest)
		answer.Resolver = resolver
		addrs, err := tools.lookup(ctx, dest)
		if err != nil || len(addrs) == 0 {
			fmt.Fprintf(&words, "%s is looked up by %s, which does not find it.\n", dest, sentence)
			answer.Sentence = strings.TrimSpace(words.String())
			c.print(out, answer, words.String())
			return nil
		}
		addr = addrs[0]
		fmt.Fprintf(&words, "%s is looked up by %s: %s.\n", dest, sentence, addr.Unmap())
	}
	addr = addr.Unmap()
	answer.Address = addr.String()
	kernel, err := tools.get(addr)
	if err != nil {
		return err
	}
	answer.Interface = kernel.Interface
	if kernel.Gateway != "" && !strings.HasPrefix(kernel.Gateway, "link#") && !strings.HasPrefix(kernel.Gateway, "utun") {
		answer.Gateway = &kernel.Gateway
	}
	sentence := describeRoute(&answer, kernel, resp.Tunnels, resp.Others)
	fmt.Fprintf(&words, "%s %s.\n", addr, sentence)
	answer.Sentence = strings.TrimSpace(words.String())
	c.print(out, answer, words.String())
	return nil
}

// validName accepts a host name's characters only.
func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// resolverOf says who answers a name: a resolver file (an adit tunnel's or someone else's), the full
// tunnel's servers, or the network's.
func resolverOf(tools routeTools, tunnels []api.Tunnel, name string) (*resolverJSON, string) {
	if answer, ok := tools.resolvers.For(name); ok {
		r := &resolverJSON{By: "file", Domain: answer.Domain, Servers: addrStrings(answer.Servers)}
		if answer.Owner != "" {
			r.By = answer.Owner
			return r, fmt.Sprintf("%s's DNS (%s, for %s)", answer.Owner, strings.Join(r.Servers, ", "), answer.Domain)
		}
		return r, fmt.Sprintf("the servers in %s (%s), which adit did not write", answer.File, strings.Join(r.Servers, ", "))
	}
	if tunnel, servers, err := tools.current(); err == nil && tunnel != "" {
		r := &resolverJSON{By: tunnel, Servers: addrStrings(servers)}
		return r, fmt.Sprintf("%s's DNS (%s), the full tunnel's", tunnel, strings.Join(r.Servers, ", "))
	}
	return &resolverJSON{By: "network", Servers: []string{}}, "the network's DNS"
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for n, addr := range addrs {
		out[n] = addr.String()
	}
	return out
}

// describeRoute puts the kernel's answer in words, naming the tunnel behind an interface.
func describeRoute(answer *routeAnswer, kernel kernelRoute, tunnels, others []api.Tunnel) string {
	var full, blocking *api.Tunnel
	for n, t := range tunnels {
		if t.KillSwitch != "" && t.State != "down" {
			full = &tunnels[n]
		}
		if t.Blocking {
			blocking = &tunnels[n]
		}
	}
	blocked := ""
	if blocking != nil {
		blocked = fmt.Sprintf(", but the kill switch blocks it until %s is up", blocking.Name)
	}
	via := ""
	if answer.Gateway != nil {
		via = " via " + *answer.Gateway
	}

	switch {
	case kernel.Blackhole:
		answer.Verdict = "nowhere"
		if full != nil {
			return fmt.Sprintf("goes nowhere: IPv6 is blocked while %s is up, since it carries only IPv4", full.Name)
		}
		return "goes nowhere: a route sends it to a blackhole"
	case kernel.Interface == "lo0":
		answer.Verdict = "mac"
		return "is this Mac"
	}
	for _, t := range tunnels {
		if t.Interface != "" && t.Interface == kernel.Interface {
			answer.Verdict = "tunnel"
			answer.Tunnel, answer.Source = &t.Name, ptr("adit")
			if t.KillSwitch != "" {
				return fmt.Sprintf("goes through %s (%s), the full tunnel", t.Name, kernel.Interface)
			}
			return fmt.Sprintf("goes through %s (%s)", t.Name, kernel.Interface)
		}
	}
	for _, t := range others {
		if t.Interface != "" && t.Interface == kernel.Interface {
			answer.Verdict = "tunnel"
			answer.Tunnel, answer.Source = &t.Name, &t.Source
			return fmt.Sprintf("goes through %s (%s), run by %s", t.Name, kernel.Interface, t.Source)
		}
	}
	if strings.HasPrefix(kernel.Interface, "utun") || strings.HasPrefix(kernel.Interface, "ipsec") || strings.HasPrefix(kernel.Interface, "ppp") {
		answer.Verdict = "tunnel"
		return fmt.Sprintf("goes through %s, another program's tunnel", kernel.Interface)
	}
	switch {
	case answer.Gateway == nil:
		answer.Verdict = "local"
		if full != nil && full.LAN == "block" {
			return fmt.Sprintf("is on the local network (%s), which is blocked while %s is up", kernel.Interface, full.Name)
		}
		if blocking != nil && blocking.LAN == "block" {
			return fmt.Sprintf("is on the local network (%s), which the kill switch blocks until %s is up", kernel.Interface, blocking.Name)
		}
		return fmt.Sprintf("is on the local network (%s)", kernel.Interface)
	case kernel.Destination != "default" && full != nil:
		answer.Verdict = "outside"
		return fmt.Sprintf("goes outside the tunnels, through %s%s: adit keeps every tunnel's server outside %s", kernel.Interface, via, full.Name)
	case full != nil:
		answer.Verdict = "direct"
		return fmt.Sprintf("goes out directly through %s%s, outside %s", kernel.Interface, via, full.Name)
	default:
		answer.Verdict = "direct"
		return fmt.Sprintf("goes out directly through %s%s, outside every tunnel%s", kernel.Interface, via, blocked)
	}
}

func ptr(s string) *string {
	return &s
}
