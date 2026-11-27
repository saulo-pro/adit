//go:build integration && darwin

package bypass

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/saulo-pro/adit/internal/routes"
)

// Real routes, as root: run with test/integration. The endpoint is a documentation address, so the
// host route sends nothing anyone uses through the real gateway; IPv6 is not blocked here, since the
// machine running the test may need it.
func TestIntegrationEndpointRouteThroughTheRealGateway(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root; run test/integration")
	}
	r := &Routes{StateFile: filepath.Join(t.TempDir(), "routes.json"), Table: routes.All,
		Run: func(args ...string) ([]byte, error) { return exec.Command("/sbin/route", args...).CombinedOutput() }}
	t.Cleanup(func() { r.Clear() })
	table, err := routes.All()
	if err != nil {
		t.Fatal(err)
	}
	gateway, ok := routes.Default(table, true)
	if !ok {
		t.Skip("this Mac has no IPv4 default route")
	}
	endpoint := netip.MustParseAddr("192.0.2.77")
	if err := r.Apply(Plan{Endpoints: []netip.Addr{endpoint}}); err != nil {
		t.Fatal(err)
	}
	after, _ := routes.All()
	found := false
	for _, route := range after {
		if route.Prefix == netip.PrefixFrom(endpoint, 32) && route.Interface == gateway.Interface {
			found = true
		}
	}
	if !found {
		t.Errorf("no host route for %s through %s", endpoint, gateway.Interface)
	}
	if err := r.Clear(); err != nil {
		t.Fatal(err)
	}
	after, _ = routes.All()
	for _, route := range after {
		if route.Prefix == netip.PrefixFrom(endpoint, 32) {
			t.Errorf("the host route is still there: %+v", route)
		}
	}
}
