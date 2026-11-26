package routes

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestMaskBits(t *testing.T) {
	for want, mask := range map[int][]byte{0: {0, 0, 0, 0}, 8: {255}, 24: {255, 255, 255, 0}, 25: {255, 255, 255, 128}, 32: {255, 255, 255, 255}} {
		if got := maskBits(mask); got != want {
			t.Errorf("%v: %d, want %d", mask, got, want)
		}
	}
}

func TestCatchAll(t *testing.T) {
	for prefix, want := range map[string]bool{"0.0.0.0/0": true, "128.0.0.0/1": true, "::/0": true, "8000::/1": true, "10.0.0.0/8": false} {
		if got := CatchAll(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("%s: %v", prefix, got)
		}
	}
}

func TestRoutesEveryTunnelHasAreIgnored(t *testing.T) {
	for _, prefix := range []string{"fe80::/64", "ff00::/8", "224.0.0.0/4", "255.255.255.255/32", "127.0.0.0/8"} {
		if !ignored(netip.MustParsePrefix(prefix)) {
			t.Errorf("%s is not ignored", prefix)
		}
	}
	if ignored(netip.MustParsePrefix("10.30.0.0/24")) {
		t.Error("a tunnel's own network was ignored")
	}
}

func TestDescribeNamesWgQuickTunnels(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "diner.name"), []byte("utun8\n"), 0o600)
	if got := Describe(dir, "utun8"); got != "utun8 (wg-quick's diner)" {
		t.Errorf("got %q", got)
	}
	if got := Describe(dir, "utun7"); got != "utun7, another program's tunnel" {
		t.Errorf("got %q", got)
	}
}

func TestTunnelsReadsTheRoutingTable(t *testing.T) {
	routes, err := Tunnels()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if !TunnelInterface(r.Interface) || ignored(r.Prefix) {
			t.Errorf("unexpected route %+v", r)
		}
	}
}
