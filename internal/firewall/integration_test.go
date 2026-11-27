//go:build integration && darwin

package firewall

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Real pf, as root: run with test/integration. CI's Macs talk to GitHub through the network a
// blocking anchor would cut, so the anchor loaded here only passes; every ruleset adit writes is
// parsed by pf without being loaded.
func TestIntegrationPfTakesEveryRuleset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root; run test/integration")
	}
	servers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:51820"), netip.MustParseAddrPort("[2001:db8::10]:51820")}
	for _, r := range []Rules{
		{Interfaces: []string{"utun98", "utun99"}, Servers: servers, BlockAll: true, AllowLAN: true},
		{Interfaces: []string{"utun99"}, Servers: servers, BlockAll: true},
		{Servers: servers, BlockAll: true},
		{Interfaces: []string{"utun99"}, Servers: servers},
	} {
		command := exec.Command("/sbin/pfctl", "-n", "-a", "com.apple/zzz.adit-test", "-f", "-")
		command.Stdin = strings.NewReader(Ruleset(r))
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("pf refused:\n%s\n%s", Ruleset(r), lastLine(output, err))
		}
	}
}

func TestIntegrationLoadEnableAndRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root; run test/integration")
	}
	run := func(stdin string, args ...string) ([]byte, error) {
		command := exec.Command("/sbin/pfctl", args...)
		if stdin != "" {
			command.Stdin = strings.NewReader(stdin)
		}
		return command.CombinedOutput()
	}
	f := &Firewall{Anchor: "com.apple/zzz.adit-test", StateFile: filepath.Join(t.TempDir(), "firewall.json"), Run: run}
	t.Cleanup(func() { f.Release() })
	// Passes only: the local network allowed and no kill switch leaves no block rule.
	rules := Rules{Interfaces: []string{"utun99"}, AllowLAN: true, Guards: []string{"manhattan"}}
	if err := f.Block(rules); err != nil {
		t.Fatal(err)
	}
	output, _ := run("", "-a", f.Anchor, "-s", "rules")
	if !strings.Contains(string(output), "pass quick on utun99 all no state") {
		t.Errorf("the anchor holds:\n%s", output)
	}
	info, _ := run("", "-s", "info")
	if !strings.Contains(string(info), "Status: Enabled") {
		t.Errorf("pf is not on:\n%s", info)
	}
	if guards, _ := f.Guards(); len(guards) != 1 {
		t.Errorf("guards %v", guards)
	}
	if err := f.Release(); err != nil {
		t.Fatal(err)
	}
	if output, _ := run("", "-a", f.Anchor, "-s", "rules"); strings.Contains(string(output), "pass ") {
		t.Errorf("the anchor still holds:\n%s", output)
	}
}
