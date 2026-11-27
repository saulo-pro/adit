package bypass

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saulo-pro/adit/internal/routes"
)

// fakeMac is a routing table that /sbin/route changes, as the kernel would.
type fakeMac struct {
	table []routes.Route
	runs  []string
	fail  string // a command containing this fails
}

func (f *fakeMac) Table() ([]routes.Route, error) { return slices.Clone(f.table), nil }

func (f *fakeMac) Run(args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.runs = append(f.runs, line)
	if f.fail != "" && strings.Contains(line, f.fail) {
		return []byte("route: writing to routing socket: File exists"), errFake
	}
	dest := args[5]
	if args[4] == "-net" || args[4] == "-host" {
		dest = args[5]
	}
	prefix, err := netip.ParsePrefix(dest)
	if err != nil {
		addr := netip.MustParseAddr(dest)
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	switch args[2] {
	case "add":
		r := routes.Route{Prefix: prefix}
		switch rest := args[6:]; {
		case slices.Contains(rest, "-blackhole"):
			r.Interface, r.Gateway = "lo0", netip.MustParseAddr(rest[0])
		case rest[0] == "-interface":
			r.Interface = rest[1]
		default:
			r.Interface, r.Gateway = "en0", netip.MustParseAddr(rest[0])
		}
		f.table = append(f.table, r)
	case "delete":
		f.table = slices.DeleteFunc(f.table, func(r routes.Route) bool { return r.Prefix == prefix })
	}
	return nil, nil
}

type fakeError struct{}

func (fakeError) Error() string { return "exit status 1" }

var errFake = fakeError{}

func newMac() *fakeMac {
	return &fakeMac{table: []routes.Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")},
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: "en0"},
		{Prefix: netip.MustParsePrefix("::/0"), Interface: "en0", Gateway: netip.MustParseAddr("fe80::1%en0")},
		{Prefix: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun4"},
		{Prefix: netip.MustParsePrefix("128.0.0.0/1"), Interface: "utun4"},
	}}
}

func newRoutes(t *testing.T, mac *fakeMac) *Routes {
	return &Routes{StateFile: filepath.Join(t.TempDir(), "routes.json"), Table: mac.Table, Run: mac.Run}
}

func addrs(list ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestEndpointsGoThroughTheRealGateway(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{Endpoints: addrs("203.0.113.10", "198.51.100.7", "203.0.113.10", "2001:db8::7")}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-q -n add -inet -host 203.0.113.10 192.168.1.1",
		"-q -n add -inet -host 198.51.100.7 192.168.1.1",
		"-q -n add -inet6 -host 2001:db8::7 fe80::1%en0",
	}
	if !slices.Equal(mac.runs, want) {
		t.Errorf("ran:\n%s", strings.Join(mac.runs, "\n"))
	}
}

func TestLocalEndpointsNeedNoRoute(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{Endpoints: addrs("192.168.1.20", "127.0.0.1", "::ffff:192.168.1.21")}); err != nil {
		t.Fatal(err)
	}
	if len(mac.runs) != 0 {
		t.Errorf("ran %v", mac.runs)
	}
}

func TestApplyIsQuietWhenNothingChanged(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	plan := Plan{Endpoints: addrs("203.0.113.10"), BlockIPv6: true}
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	mac.runs = nil
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	if len(mac.runs) != 0 {
		t.Errorf("ran %v", mac.runs)
	}
}

func TestARouteTheNetworkTookAwayComesBack(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	plan := Plan{Endpoints: addrs("203.0.113.10")}
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	// A DHCP renewal removes host routes through the gateway.
	mac.table = newMac().table
	mac.runs = nil
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(mac.runs, []string{"-q -n add -inet -host 203.0.113.10 192.168.1.1"}) {
		t.Errorf("ran %v", mac.runs)
	}
}

func TestANewGatewayMovesTheRoute(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	plan := Plan{Endpoints: addrs("203.0.113.10")}
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	mac.table[0].Gateway = netip.MustParseAddr("192.168.1.254")
	mac.runs = nil
	if err := r.Apply(plan); err != nil {
		t.Fatal(err)
	}
	want := []string{"-q -n delete -inet -host 203.0.113.10", "-q -n add -inet -host 203.0.113.10 192.168.1.254"}
	if !slices.Equal(mac.runs, want) {
		t.Errorf("ran %v", mac.runs)
	}
}

func TestNoGatewayMeansNowhere(t *testing.T) {
	mac := newMac()
	mac.table = mac.table[3:] // offline: only the full tunnel's routes
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{Endpoints: addrs("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(mac.runs, []string{"-q -n add -inet -host 203.0.113.10 127.0.0.1 -blackhole"}) {
		t.Errorf("ran %v", mac.runs)
	}
}

func TestIPv6IsBlockedAndUnblocked(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{BlockIPv6: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.Clear(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-q -n add -inet6 -net ::/1 ::1 -blackhole",
		"-q -n add -inet6 -net 8000::/1 ::1 -blackhole",
		"-q -n delete -inet6 -net ::/1",
		"-q -n delete -inet6 -net 8000::/1",
	}
	if !slices.Equal(mac.runs, want) {
		t.Errorf("ran:\n%s", strings.Join(mac.runs, "\n"))
	}
}

func TestClearLeavesOthersRoutesAlone(t *testing.T) {
	mac := newMac()
	someone := routes.Route{Prefix: netip.MustParsePrefix("203.0.113.10/32"), Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}
	mac.table = append(mac.table, someone)
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{Endpoints: addrs("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
	if err := r.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(mac.runs) != 0 || !slices.Contains(mac.table, someone) {
		t.Errorf("ran %v; table %v", mac.runs, mac.table)
	}
}

func TestClearAfterARestartUsesTheStateFile(t *testing.T) {
	mac := newMac()
	r := newRoutes(t, mac)
	if err := r.Apply(Plan{Endpoints: addrs("203.0.113.10"), BlockIPv6: true}); err != nil {
		t.Fatal(err)
	}
	again := &Routes{StateFile: r.StateFile, Table: mac.Table, Run: mac.Run}
	if err := again.Clear(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(mac.table, newMac().table) {
		t.Errorf("left %v", mac.table)
	}
}

func TestAFailedRouteIsReported(t *testing.T) {
	mac := newMac()
	mac.fail = "203.0.113.10"
	r := newRoutes(t, mac)
	err := r.Apply(Plan{Endpoints: addrs("203.0.113.10")})
	if err == nil || !strings.Contains(err.Error(), "File exists") {
		t.Errorf("got %v", err)
	}
}
