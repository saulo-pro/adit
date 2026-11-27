package dnsdefault

import (
	"net/netip"
	"strings"
	"testing"
)

type fakeScutil struct {
	scripts []string
	answer  string
}

func (f *fakeScutil) Run(script string) ([]byte, error) {
	f.scripts = append(f.scripts, script)
	return []byte(f.answer), nil
}

func TestSetMakesTheServersTheDefault(t *testing.T) {
	f := &fakeScutil{}
	d := &Default{Run: f.Run}
	if err := d.Set("diner", []netip.Addr{netip.MustParseAddr("10.99.1.1"), netip.MustParseAddr("2001:db8::53")}); err != nil {
		t.Fatal(err)
	}
	want := "d.init\nd.add ServerAddresses * 10.99.1.1 2001:db8::53\nd.add SupplementalMatchDomains * \"\"\nset State:/Network/Service/adit-diner/DNS\n"
	if f.scripts[0] != want {
		t.Errorf("script:\n%s", f.scripts[0])
	}
}

func TestSetRefusesNoServers(t *testing.T) {
	if err := (&Default{Run: (&fakeScutil{}).Run}).Set("diner", nil); err == nil {
		t.Error("no error")
	}
}

func TestSetReportsWhatScutilSays(t *testing.T) {
	d := &Default{Run: (&fakeScutil{answer: "  set: invalid key\n"}).Run}
	if err := d.Set("diner", []netip.Addr{netip.MustParseAddr("10.99.1.1")}); err == nil || !strings.Contains(err.Error(), "invalid key") {
		t.Errorf("got %v", err)
	}
}

func TestClearAllRemovesOnlyAditsKeys(t *testing.T) {
	f := &fakeScutil{answer: "  subKey [0] = State:/Network/Service/adit-diner/DNS\n" +
		"  subKey [1] = State:/Network/Service/adit-cupcakes.v2/DNS\n" +
		"  subKey [2] = State:/Network/Service/1F2C21DD/DNS\n"}
	d := &Default{Run: f.Run}
	if err := d.ClearAll(); err != nil {
		t.Fatal(err)
	}
	want := "remove State:/Network/Service/adit-diner/DNS\nremove State:/Network/Service/adit-cupcakes.v2/DNS\n"
	if len(f.scripts) != 2 || f.scripts[1] != want {
		t.Errorf("scripts %q", f.scripts)
	}
}
