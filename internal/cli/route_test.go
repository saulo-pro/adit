package cli

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/dns"
)

func TestParseKernelRoute(t *testing.T) {
	output := "   route to: 203.0.113.10\ndestination: 203.0.113.10\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n"
	got := parseKernelRoute(output)
	if got != (kernelRoute{Destination: "203.0.113.10", Interface: "en0", Gateway: "192.168.1.1"}) {
		t.Errorf("got %+v", got)
	}
	if !parseKernelRoute("destination: ::\n  interface: lo0\n      flags: <UP,GATEWAY,DONE,STATIC,BLACKHOLE>\n").Blackhole {
		t.Error("a blackhole route was not seen")
	}
}

// A Mac with the full tunnel manhattan and the split tunnel diner up, and wg-quick's brooklyn.
func routeMac(t *testing.T) (*run, map[string]kernelRoute) {
	t.Helper()
	tunnels := []api.Tunnel{
		{Name: "diner", State: "up", Interface: "utun4"},
		{Name: "manhattan", State: "up", Interface: "utun5", KillSwitch: "on-drop", LAN: "allow"},
	}
	others := []api.Tunnel{{Name: "brooklyn", State: "up", Interface: "utun7", Source: "wg-quick", ReadOnly: true}}
	run := newRun(t, func(req api.Request) api.Response { return api.Response{OK: true, Tunnels: tunnels, Others: others} })
	routes := map[string]kernelRoute{
		"1.1.1.1":       {Destination: "default", Interface: "utun5"},
		"10.99.2.5":     {Destination: "10.99.2.0", Interface: "utun4"},
		"10.30.0.9":     {Destination: "10.30.0.0", Interface: "utun7"},
		"192.168.1.20":  {Destination: "192.168.1.0", Interface: "en0", Gateway: "link#7"},
		"203.0.113.10":  {Destination: "203.0.113.10", Interface: "en0", Gateway: "192.168.1.1"},
		"2001:db8::1":   {Destination: "::", Interface: "lo0", Gateway: "::1", Blackhole: true},
		"127.0.0.1":     {Destination: "127.0.0.1", Interface: "lo0"},
		"198.51.100.20": {Destination: "198.51.100.20", Interface: "utun5"},
	}
	dir := t.TempDir()
	resolvers := &dns.Resolvers{Dir: dir}
	resolvers.Set("diner", []netip.Addr{netip.MustParseAddr("10.99.2.1")}, []string{"diner.example"})
	run.c.routeTools = routeTools{
		get: func(addr netip.Addr) (kernelRoute, error) {
			if r, ok := routes[addr.String()]; ok {
				return r, nil
			}
			return kernelRoute{}, errors.New("no route")
		},
		lookup: func(_ context.Context, name string) ([]netip.Addr, error) {
			switch name {
			case "www.diner.example":
				return []netip.Addr{netip.MustParseAddr("10.99.2.5")}, nil
			case "cupcakes.example":
				return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
			}
			return nil, errors.New("no such host")
		},
		resolvers: resolvers,
		current: func() (string, []netip.Addr, error) {
			return "manhattan", []netip.Addr{netip.MustParseAddr("10.64.0.1")}, nil
		},
	}
	return run, routes
}

func TestRouteSaysWhichTunnelCarriesAnAddress(t *testing.T) {
	for dest, want := range map[string]string{
		"1.1.1.1":      "1.1.1.1 goes through manhattan (utun5), the full tunnel.\n",
		"10.99.2.5":    "10.99.2.5 goes through diner (utun4).\n",
		"10.30.0.9":    "10.30.0.9 goes through brooklyn (utun7), run by wg-quick.\n",
		"192.168.1.20": "192.168.1.20 is on the local network (en0).\n",
		"203.0.113.10": "203.0.113.10 goes outside the tunnels, through en0 via 192.168.1.1: adit keeps every tunnel's server outside manhattan.\n",
		"2001:db8::1":  "2001:db8::1 goes nowhere: IPv6 is blocked while manhattan is up, since it carries only IPv4.\n",
		"127.0.0.1":    "127.0.0.1 is this Mac.\n",
	} {
		run, _ := routeMac(t)
		if code := run.cli("route", dest); code != 0 || run.stdout.String() != want {
			t.Errorf("%s: exit %d, got %q, want %q (%s)", dest, code, run.stdout, want, run.stderr)
		}
	}
}

func TestRouteSaysWhoLooksANameUp(t *testing.T) {
	run, _ := routeMac(t)
	run.cli("route", "www.diner.example")
	want := "www.diner.example is looked up by diner's DNS (10.99.2.1, for diner.example): 10.99.2.5.\n10.99.2.5 goes through diner (utun4).\n"
	if run.stdout.String() != want {
		t.Errorf("got %q", run.stdout)
	}

	run, _ = routeMac(t)
	run.cli("route", "cupcakes.example", "--json")
	got := run.stdout.String()
	for _, part := range []string{`"by": "manhattan"`, `"10.64.0.1"`, `"tunnel": "manhattan"`, `"verdict": "tunnel"`} {
		if !strings.Contains(got, part) {
			t.Errorf("no %s in %s", part, got)
		}
	}
}

func TestRouteRefusesWhatIsNotANameOrAnAddress(t *testing.T) {
	run, _ := routeMac(t)
	if code := run.cli("route", "diner; rm -rf /"); code != 2 {
		t.Errorf("exit %d", code)
	}
}

func TestRouteOfAnOtherFileNamesIt(t *testing.T) {
	run, _ := routeMac(t)
	os.WriteFile(filepath.Join(run.c.routeTools.resolvers.Dir, "example"), []byte("nameserver 192.0.2.53\n"), 0o644)
	run.cli("route", "cupcakes.example")
	if !strings.Contains(run.stdout.String(), "which adit did not write") {
		t.Errorf("got %q", run.stdout)
	}
}
