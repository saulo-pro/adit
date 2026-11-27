package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/bypass"
	"github.com/saulo-pro/adit/internal/conf"
	"github.com/saulo-pro/adit/internal/dns"
	"github.com/saulo-pro/adit/internal/firewall"
	"github.com/saulo-pro/adit/internal/others"
	"github.com/saulo-pro/adit/internal/routes"
	"github.com/saulo-pro/adit/internal/store"
	"github.com/saulo-pro/adit/internal/tunnel"
)

// A throwaway key made for these tests; it guards nothing.
const file = "[Interface]\n" +
	"PrivateKey = cLzT3oxyUzSXHZQPIOcI2LSoG5mBzVunYbXpSonv2UU=\n" +
	"Address = 10.99.1.2/24\n" +
	"PostUp = iptables -A FORWARD -i %i -j ACCEPT\n" +
	"PostDown = iptables -D FORWARD -i %i -j ACCEPT\n" +
	"\n" +
	"[Peer]\n" +
	"PublicKey = L4oNLijDi5zJ8gOyZv1Rj4tmLS6jVBGWWwWoN/jYCAQ=\n" +
	"AllowedIPs = 10.99.1.0/24\n" +
	"Endpoint = 127.0.0.1:51821\n"

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestImportWarnsAboutHooks(t *testing.T) {
	m, _ := newTestManager(t)
	warnings, err := m.Import("work", []byte(file))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PostUp line kept but not run: adit never runs commands from a configuration.",
		"PostDown line kept but not run: adit never runs commands from a configuration.",
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
}

func TestImportRefusesABrokenFile(t *testing.T) {
	m, _ := newTestManager(t)
	_, err := m.Import("work", []byte("[Interface]\nMTU = 100\n"))
	var confErr *conf.Error
	if !errors.As(err, &confErr) {
		t.Errorf("got %v, want the parser's error", err)
	}
}

func TestStatesFollowTheHandshake(t *testing.T) {
	m, devices := newTestManager(t)
	mustImport(t, m, "work")
	assertState(t, m, "work", StateDown)

	if err := m.Up(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	assertState(t, m, "work", StateConnecting)

	devices.last().handshake(now.Add(-time.Minute))
	assertState(t, m, "work", StateUp)

	devices.last().handshake(now.Add(-upWithin - time.Second))
	assertState(t, m, "work", StateIdle)

	if err := m.Down("work"); err != nil {
		t.Fatal(err)
	}
	assertState(t, m, "work", StateDown)
	if !devices.last().closed {
		t.Error("Down did not close the device")
	}
}

func TestStatusAddsUpThePeers(t *testing.T) {
	m, devices := newTestManager(t)
	mustImport(t, m, "work")
	if err := m.Up(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	devices.last().status.Peers = []tunnel.PeerStatus{
		{LastHandshake: now.Add(-2 * time.Minute), Received: 100, Sent: 200},
		{LastHandshake: now.Add(-30 * time.Second), Received: 1, Sent: 2},
	}

	status, err := m.Status("work")
	if err != nil {
		t.Fatal(err)
	}
	if status.Interface != "utun20" || status.Received != 101 || status.Sent != 202 || !status.LastHandshake.Equal(now.Add(-30*time.Second)) {
		t.Errorf("got %+v", status)
	}
}

func TestUpTwiceStartsOneDevice(t *testing.T) {
	m, devices := newTestManager(t)
	mustImport(t, m, "work")
	for range 2 {
		if err := m.Up(context.Background(), "work"); err != nil {
			t.Fatal(err)
		}
	}
	if len(*devices) != 1 {
		t.Errorf("started %d devices", len(*devices))
	}
}

func TestFailureToStartNamesTheTunnel(t *testing.T) {
	m, _ := newTestManager(t)
	m.start = func(context.Context, *conf.Config, func([]netip.AddrPort) error) (device, error) {
		return nil, errors.New("the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line")
	}
	mustImport(t, m, "work")
	err := m.Up(context.Background(), "work")
	if err == nil || err.Error() != "work did not come up: the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line" {
		t.Errorf("got %v", err)
	}
	assertState(t, m, "work", StateDown)
}

func TestUnknownTunnel(t *testing.T) {
	m, _ := newTestManager(t)
	for _, err := range []error{m.Up(context.Background(), "nowhere"), m.Down("nowhere"), m.Remove("nowhere"), m.SetAutostart("nowhere", true)} {
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("got %v, want store.ErrNotFound", err)
		}
	}
}

func TestRemoveTakesTheTunnelDownFirst(t *testing.T) {
	m, devices := newTestManager(t)
	mustImport(t, m, "work")
	if err := m.Up(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove("work"); err != nil {
		t.Fatal(err)
	}
	if !devices.last().closed {
		t.Error("the device was left running")
	}
	if statuses, _ := m.List(); len(statuses) != 0 {
		t.Errorf("still listed: %+v", statuses)
	}
}

func TestAutostartIsKept(t *testing.T) {
	m, _ := newTestManager(t)
	mustImport(t, m, "work")
	if err := m.SetAutostart("WORK", true); err != nil {
		t.Fatal(err)
	}
	status, err := m.Status("work")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Autostart {
		t.Error("autostart was not kept")
	}
}

func TestCloseTakesEveryTunnelDown(t *testing.T) {
	m, devices := newTestManager(t)
	for name, allowed := range map[string]string{"one": "10.99.1.0/24", "two": "10.99.2.0/24"} {
		importText(t, m, name, fileWith(allowed, ""))
		if err := m.Up(context.Background(), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, dev := range *devices {
		if !dev.closed {
			t.Errorf("%s left running", dev.status.Interface)
		}
	}
}

type fakeDevice struct {
	status tunnel.Status
	closed bool
}

func (d *fakeDevice) Interface() string              { return d.status.Interface }
func (d *fakeDevice) Status() (tunnel.Status, error) { return d.status, nil }
func (d *fakeDevice) Close() error                   { d.closed = true; return nil }

func (d *fakeDevice) handshake(at time.Time) {
	d.status.Peers = []tunnel.PeerStatus{{LastHandshake: at}}
}

type fakeDevices []*fakeDevice

func (d fakeDevices) last() *fakeDevice { return d[len(d)-1] }

func newTestManager(t *testing.T) (*Manager, *fakeDevices) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tunnels"))
	if err != nil {
		t.Fatal(err)
	}
	devices := &fakeDevices{}
	start := func(_ context.Context, c *conf.Config, beforeRoutes func([]netip.AddrPort) error) (device, error) {
		dev := &fakeDevice{status: tunnel.Status{Interface: "utun2" + string(rune('0'+len(*devices)))}}
		for _, peer := range c.Peers {
			if addr, err := netip.ParseAddr(peer.Endpoint.Host); err == nil {
				dev.status.Peers = append(dev.status.Peers, tunnel.PeerStatus{PublicKey: peer.PublicKey, Endpoint: netip.AddrPortFrom(addr, peer.Endpoint.Port)})
			}
		}
		if err := beforeRoutes(dev.status.Endpoints()); err != nil {
			return nil, err
		}
		*devices = append(*devices, dev)
		return dev, nil
	}
	m := newManager(st, system{
		start:     start,
		now:       func() time.Time { return now },
		resolvers: &dns.Resolvers{Dir: filepath.Join(t.TempDir(), "resolver")},
		bypass:    &fakeBypass{},
		firewall:  &fakeFirewall{},
		signIn:    2 * time.Minute,
		dnsAll:    &fakeDefaultDNS{set: map[string][]netip.Addr{}},
		routes:    func() ([]routes.Route, error) { return nil, nil },
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, devices
}

// fakeBypass keeps the last plan.
type fakeBypass struct {
	plans []bypass.Plan
	fail  error
}

func (f *fakeBypass) Apply(p bypass.Plan) error {
	f.plans = append(f.plans, p)
	return f.fail
}

func (f *fakeBypass) last() bypass.Plan {
	if len(f.plans) == 0 {
		return bypass.Plan{}
	}
	return f.plans[len(f.plans)-1]
}

// fakeFirewall is pf's anchor: blocking with some rules, or not.
type fakeFirewall struct {
	rules    *firewall.Rules
	previous []string // guards an earlier aditd left
	loads    int
}

func (f *fakeFirewall) Block(r firewall.Rules) error {
	f.rules = &r
	f.loads++
	return nil
}

func (f *fakeFirewall) Release() error {
	f.rules = nil
	f.previous = nil
	return nil
}

func (f *fakeFirewall) Guards() ([]string, error) {
	if f.rules != nil {
		return f.rules.Guards, nil
	}
	return f.previous, nil
}

// fakeDefaultDNS keeps which tunnel's servers are the default.
type fakeDefaultDNS struct {
	set     map[string][]netip.Addr
	cleared bool
}

func (f *fakeDefaultDNS) Set(tunnel string, servers []netip.Addr) error {
	f.set[tunnel] = servers
	return nil
}

func (f *fakeDefaultDNS) Clear(tunnel string) error {
	delete(f.set, tunnel)
	return nil
}

func (f *fakeDefaultDNS) ClearAll() error {
	clear(f.set)
	f.cleared = true
	return nil
}

func mustImport(t *testing.T, m *Manager, name string) {
	t.Helper()
	if _, err := m.Import(name, []byte(file)); err != nil {
		t.Fatal(err)
	}
}

func assertState(t *testing.T, m *Manager, name string, want State) {
	t.Helper()
	status, err := m.Status(name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != want {
		t.Errorf("%s is %s, want %s", name, status.State, want)
	}
}

func TestStatusAnswersWhileATunnelComesUp(t *testing.T) {
	m, _ := newTestManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	m.start = func(context.Context, *conf.Config, func([]netip.AddrPort) error) (device, error) {
		close(started)
		<-release
		return &fakeDevice{status: tunnel.Status{Interface: "utun30"}}, nil
	}
	mustImport(t, m, "work")

	done := make(chan error)
	go func() { done <- m.Up(context.Background(), "work") }()
	<-started
	assertStateWithin(t, m, "work", StateConnecting)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	status, err := m.Status("work")
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateConnecting || status.Interface != "utun30" {
		t.Errorf("after coming up without a handshake: %+v", status)
	}
}

func TestDownStopsATunnelComingUp(t *testing.T) {
	m, _ := newTestManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	dev := &fakeDevice{}
	m.start = func(ctx context.Context, _ *conf.Config, _ func([]netip.AddrPort) error) (device, error) {
		close(started)
		<-release
		return dev, nil
	}
	mustImport(t, m, "work")

	done := make(chan error)
	go func() { done <- m.Up(context.Background(), "work") }()
	<-started
	if err := m.Down("work"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil || err.Error() != "work was taken down while it was coming up" {
		t.Errorf("Up returned %v", err)
	}
	if !dev.closed {
		t.Error("the device that came up late was left running")
	}
	assertState(t, m, "work", StateDown)
}

func TestChangesAreSignalled(t *testing.T) {
	m, _ := newTestManager(t)
	changes, stop := m.Changes()
	defer stop()

	steps := []struct {
		what string
		do   func() error
	}{
		{"import", func() error { _, err := m.Import("work", []byte(file)); return err }},
		{"up", func() error { return m.Up(context.Background(), "work") }},
		{"autostart", func() error { return m.SetAutostart("work", true) }},
		{"down", func() error { return m.Down("work") }},
		{"remove", func() error { return m.Remove("work") }},
	}
	for _, step := range steps {
		if err := step.do(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-changes:
		case <-time.After(time.Second):
			t.Errorf("%s signalled no change", step.what)
		}
	}
}

func TestFileIsTheImportedText(t *testing.T) {
	m, _ := newTestManager(t)
	mustImport(t, m, "work")
	got, err := m.File("work")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != file {
		t.Errorf("File gave:\n%s", got)
	}
}

// assertStateWithin fails rather than hangs if status waits for a tunnel coming up.
func assertStateWithin(t *testing.T, m *Manager, name string, want State) {
	t.Helper()
	got := make(chan State, 1)
	go func() {
		status, _ := m.Status(name)
		got <- status.State
	}()
	select {
	case state := <-got:
		if state != want {
			t.Errorf("%s is %s, want %s", name, state, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Status waited for the tunnel coming up")
	}
}

func TestOverlappingTunnelsAreRefused(t *testing.T) {
	m, devices := newTestManager(t)
	importText(t, m, "one", fileWith("10.99.0.0/16", ""))
	importText(t, m, "two", fileWith("10.99.2.0/24", ""))
	if err := m.Up(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}

	err := m.Up(context.Background(), "two")
	want := "two's AllowedIPs 10.99.2.0/24 overlaps 10.99.0.0/16 of one, which is up; take one down first, or change one of them"
	if !errors.Is(err, ErrConflict) || err.Error() != want {
		t.Errorf("got %v", err)
	}
	if len(*devices) != 1 {
		t.Error("the refused tunnel was started")
	}

	if err := m.Down("one"); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(context.Background(), "two"); err != nil {
		t.Errorf("with one down, two was still refused: %v", err)
	}
}

func TestATunnelComingUpAlreadyHoldsItsNetworks(t *testing.T) {
	m, _ := newTestManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	m.start = func(context.Context, *conf.Config, func([]netip.AddrPort) error) (device, error) {
		close(started)
		<-release
		return &fakeDevice{}, nil
	}
	importText(t, m, "one", fileWith("10.99.1.0/24", ""))
	importText(t, m, "two", fileWith("10.99.1.128/25", ""))

	done := make(chan error)
	go func() { done <- m.Up(context.Background(), "one") }()
	<-started
	if err := m.Up(context.Background(), "two"); !errors.Is(err, ErrConflict) {
		t.Errorf("two came up beside one coming up: %v", err)
	}
	close(release)
	<-done
}

func TestOtherProgramsRoutesAreChecked(t *testing.T) {
	m, _ := newTestManager(t)
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{{Prefix: netip.MustParsePrefix("10.99.0.0/16"), Interface: "utun8"}}, nil
	}
	m.others = func() []others.Tunnel {
		return []others.Tunnel{{Name: "diner", Source: others.SourceWgQuick, Interface: "utun8", State: "running"}}
	}
	mustImport(t, m, "work")

	err := m.Up(context.Background(), "work")
	want := "work's AllowedIPs 10.99.1.0/24 overlaps 10.99.0.0/16, which utun8 (wg-quick's diner) routes; take that tunnel down first, or change AllowedIPs"
	if !errors.Is(err, ErrConflict) || err.Error() != want {
		t.Errorf("got %v", err)
	}
}

func TestAnotherProgramsFullTunnelIsANoteNotAConflict(t *testing.T) {
	m, _ := newTestManager(t)
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{
			{Prefix: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun7"},
			{Prefix: netip.MustParsePrefix("128.0.0.0/1"), Interface: "utun7"},
		}, nil
	}
	importText(t, m, "work", strings.Replace(file, "127.0.0.1:51821", "203.0.113.10:51820", 1))
	if err := m.Up(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	status, _ := m.Status("work")
	want := []string{"the endpoint 203.0.113.10 is probably reached through utun7, another program's tunnel, which routes everything"}
	if strings.Join(status.Notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes %q", status.Notes)
	}
}

func TestFullTunnelsAsTwoHalvesWaitToo(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "halves", fileWith("0.0.0.0/1, 128.0.0.0/1", ""))
	if err := m.Up(context.Background(), "halves"); err == nil || !strings.Contains(err.Error(), "routes everything") {
		t.Errorf("got %v", err)
	}
}

func TestUpWritesResolverFilesAndDownRemovesThem(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "work", fileWith("10.99.1.0/24", "10.99.1.1, corp.example, lab.example"))
	if err := m.Up(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"corp.example", "lab.example"} {
		content, err := os.ReadFile(filepath.Join(m.resolvers.Dir, domain))
		if err != nil || !strings.Contains(string(content), "nameserver 10.99.1.1\n") {
			t.Errorf("%s: %q, %v", domain, content, err)
		}
	}

	if err := m.Down("work"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(m.resolvers.Dir); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestDNSDomainsAreNotShared(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "one", fileWith("10.99.1.0/24", "10.99.1.1, corp.example"))
	importText(t, m, "two", fileWith("10.99.2.0/24", "10.99.2.1, CORP.example."))
	if err := m.Up(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	err := m.Up(context.Background(), "two")
	if !errors.Is(err, ErrConflict) || err.Error() != "two's DNS domain CORP.example. is already resolved through one, which is up; take one down first" {
		t.Errorf("got %v", err)
	}
}

func TestAResolverFileAditDidNotWriteIsLeftAlone(t *testing.T) {
	m, devices := newTestManager(t)
	os.MkdirAll(m.resolvers.Dir, 0o755)
	foreign := filepath.Join(m.resolvers.Dir, "corp.example")
	os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0o644)
	importText(t, m, "work", fileWith("10.99.1.0/24", "10.99.1.1, corp.example"))

	err := m.Up(context.Background(), "work")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "exists and adit did not write it") {
		t.Errorf("got %v", err)
	}
	if content, _ := os.ReadFile(foreign); string(content) != "nameserver 192.0.2.53\n" {
		t.Errorf("the file was changed: %q", content)
	}
	if len(*devices) != 0 {
		t.Error("the tunnel was started")
	}
}

func TestDNSWithoutADomainIsExplained(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "work", fileWith("10.99.1.0/24", "10.99.1.1"))
	status, _ := m.Status("work")
	if len(status.Notes) != 1 || !strings.HasPrefix(status.Notes[0], "DNS 10.99.1.1 is not used: adit sends a tunnel's DNS queries only for the domains on its DNS line") {
		t.Errorf("notes %q", status.Notes)
	}
}

func TestCleanUpRemovesOnlyAditsStaleFiles(t *testing.T) {
	m, _ := newTestManager(t)
	stale := &dns.Resolvers{Dir: m.resolvers.Dir}
	if err := stale.Set("gone", []netip.Addr{netip.MustParseAddr("10.99.9.1")}, []string{"stale.example"}); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(m.resolvers.Dir, "corp.example")
	os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0o644)

	if err := m.CleanUp(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.resolvers.Dir, "stale.example")); err == nil {
		t.Error("the stale file is still there")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("a file adit did not write was removed")
	}
}

// fileWith is file with other AllowedIPs, and a DNS line when dns is not empty.
// fileWith is the test file with other AllowedIPs, its Address the second host of their first network.
func fileWith(allowed, dns string) string {
	text := strings.Replace(file, "AllowedIPs = 10.99.1.0/24", "AllowedIPs = "+allowed, 1)
	first := strings.TrimSpace(strings.Split(allowed, ",")[0])
	if network, err := netip.ParsePrefix(first); err == nil && network.Addr().Is4() {
		address := network.Masked().Addr().Next().Next()
		text = strings.Replace(text, "Address = 10.99.1.2/24\n", "Address = "+address.String()+"/32\n", 1)
	}
	if dns != "" {
		text = strings.Replace(text, "\n[Peer]", "\nDNS = "+dns+"\n\n[Peer]", 1)
	}
	return text
}

func importText(t *testing.T, m *Manager, name, text string) {
	t.Helper()
	if _, err := m.Import(name, []byte(text)); err != nil {
		t.Fatal(err)
	}
}

func TestAutostartKeepsTryingUntilTheTunnelComesUp(t *testing.T) {
	m, devices := newTestManager(t)
	m.retryWait = 10 * time.Millisecond
	failures := 2
	start := m.start
	var mu sync.Mutex
	m.start = func(ctx context.Context, c *conf.Config, beforeRoutes func([]netip.AddrPort) error) (device, error) {
		mu.Lock()
		defer mu.Unlock()
		if failures > 0 {
			failures--
			return nil, errors.New("the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line")
		}
		return start(ctx, c, beforeRoutes)
	}
	importText(t, m, "work", fileWith("10.99.1.0/24", ""))
	importText(t, m, "manual", fileWith("10.99.2.0/24", ""))
	if err := m.SetAutostart("work", true); err != nil {
		t.Fatal(err)
	}

	if err := m.Autostart(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, "work", StateConnecting, func(s Status) bool { return s.Interface != "" })
	if len(*devices) != 1 {
		t.Errorf("%d devices started, want 1", len(*devices))
	}
	assertState(t, m, "manual", StateDown)
}

func TestStatusExplainsAnAutostartStillTrying(t *testing.T) {
	m, _ := newTestManager(t)
	m.retryWait = time.Hour
	m.start = func(context.Context, *conf.Config, func([]netip.AddrPort) error) (device, error) {
		return nil, errors.New("the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line")
	}
	importText(t, m, "work", fileWith("10.99.1.0/24", ""))
	m.SetAutostart("work", true)
	m.Autostart(context.Background())

	waitForState(t, m, "work", StateConnecting, func(s Status) bool { return len(s.Notes) > 0 })
	status, _ := m.Status("work")
	want := "aditd is bringing it up and will try again in 1h0m0s: work did not come up: the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line"
	if status.Notes[0] != want {
		t.Errorf("note %q", status.Notes[0])
	}

	if err := m.Down("work"); err != nil {
		t.Fatal(err)
	}
	assertState(t, m, "work", StateDown)
}

func TestTunnelsFollowTheNetwork(t *testing.T) {
	m, _ := newTestManager(t)
	var followers []*followingDevice
	m.start = func(context.Context, *conf.Config, func([]netip.AddrPort) error) (device, error) {
		d := &followingDevice{fakeDevice: fakeDevice{status: tunnel.Status{Interface: "utun30"}}}
		followers = append(followers, d)
		return d, nil
	}
	importText(t, m, "fresh", fileWith("10.99.1.0/24", ""))
	importText(t, m, "stale", fileWith("10.99.2.0/24", ""))
	m.Up(context.Background(), "fresh")
	m.Up(context.Background(), "stale")
	fresh, stale := followers[0], followers[1]
	fresh.handshake(now.Add(-time.Minute))
	stale.handshake(now.Add(-10 * time.Minute))

	m.NetworkChanged(context.Background())
	if fresh.moved != 1 || stale.moved != 1 {
		t.Errorf("after a network change: moved %d and %d times, want 1 each", fresh.moved, stale.moved)
	}

	m.ReresolveStale(context.Background())
	if fresh.reresolved != 0 || stale.reresolved != 1 {
		t.Errorf("re-resolved %d and %d times; only the stale tunnel should be", fresh.reresolved, stale.reresolved)
	}
}

type followingDevice struct {
	fakeDevice
	moved, reresolved int
}

func (d *followingDevice) NetworkChanged(context.Context) error { d.moved++; return nil }
func (d *followingDevice) Reresolve(context.Context) error      { d.reresolved++; return nil }

func waitForState(t *testing.T, m *Manager, name string, want State, also func(Status) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := m.Status(name)
		if err == nil && status.State == want && also(status) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached %s: %+v", name, want, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAPersonAskingSeesOtherTunnelsAsTheyAreNow(t *testing.T) {
	m, _ := newTestManager(t)
	tunnels := []others.Tunnel{{Name: "aditwq", Source: others.SourceWgQuick, Interface: "utun10", State: "running"}}
	m.others = func() []others.Tunnel { return tunnels }
	if got := m.Others(false); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}

	tunnels = nil // wg-quick took it down
	if got := m.Others(false); len(got) != 1 {
		t.Errorf("a watch's reading should still be the cached one: %+v", got)
	}
	if got := m.Others(true); len(got) != 0 {
		t.Errorf("a person asking still sees a tunnel that is gone: %+v", got)
	}
}

// fullFile is a full tunnel's file: everything through 203.0.113.10, with DNS (if any) inside it.
func fullFile(allowed, dns string) string {
	text := strings.Replace(file, "AllowedIPs = 10.99.1.0/24", "AllowedIPs = "+allowed, 1)
	text = strings.Replace(text, "Address = 10.99.1.2/24", "Address = 10.64.0.2/32", 1)
	text = strings.Replace(text, "Endpoint = 127.0.0.1:51821", "Endpoint = 203.0.113.10:51820", 1)
	if dns != "" {
		text = strings.Replace(text, "\n[Peer]", "\nDNS = "+dns+"\n\n[Peer]", 1)
	}
	return text
}

// splitFile is a split tunnel's file reached at 198.51.100.7.
func splitFile(allowed, dns string) string {
	return strings.Replace(fileWith(allowed, dns), "Endpoint = 127.0.0.1:51821", "Endpoint = 198.51.100.7:51820", 1)
}

func addrs(list ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestAFullTunnelComesUp(t *testing.T) {
	m, devices := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	b := m.bypass.(*fakeBypass)
	want := bypass.Plan{Endpoints: addrs("203.0.113.10"), BlockIPv6: true}
	if !reflect.DeepEqual(b.plans[0], want) {
		t.Errorf("before its routes: plan %+v, want %+v", b.plans[0], want)
	}
	if !reflect.DeepEqual(b.last(), want) {
		t.Errorf("once up: plan %+v, want %+v", b.last(), want)
	}
	if got := m.dnsAll.(*fakeDefaultDNS).set["manhattan"]; !reflect.DeepEqual(got, addrs("10.64.0.1")) {
		t.Errorf("default DNS %v", got)
	}
	status, err := m.Status("manhattan")
	if err != nil {
		t.Fatal(err)
	}
	if notes := strings.Join(status.Notes, "\n"); !strings.Contains(notes, "it routes all traffic") || !strings.Contains(notes, "IPv6 is blocked") {
		t.Errorf("notes:\n%s", notes)
	}

	if err := m.Down("manhattan"); err != nil {
		t.Fatal(err)
	}
	if !devices.last().closed || len(m.dnsAll.(*fakeDefaultDNS).set) != 0 || !reflect.DeepEqual(b.last(), bypass.Plan{}) {
		t.Errorf("down left: closed %v, DNS %v, plan %+v", devices.last().closed, m.dnsAll.(*fakeDefaultDNS).set, b.last())
	}
}

func TestAFullTunnelWithIPv6LetsItThrough(t *testing.T) {
	for _, allowed := range []string{"0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", "0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2, 192.0.0.0/2, ::/0"} {
		m, _ := newTestManager(t)
		importText(t, m, "manhattan", fullFile(allowed, "10.64.0.1"))
		if err := m.Up(context.Background(), "manhattan"); err != nil {
			t.Fatalf("%s: %v", allowed, err)
		}
		if m.bypass.(*fakeBypass).last().BlockIPv6 {
			t.Errorf("%s: IPv6 blocked", allowed)
		}
	}
}

func TestSplitTunnelsKeepWorkingBesideAFullTunnel(t *testing.T) {
	for _, fullFirst := range []bool{true, false} {
		m, _ := newTestManager(t)
		importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
		importText(t, m, "diner", splitFile("10.99.1.0/24", "10.99.1.1, diner.example"))
		order := []string{"manhattan", "diner"}
		if !fullFirst {
			order = []string{"diner", "manhattan"}
		}
		for _, name := range order {
			if err := m.Up(context.Background(), name); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		got := m.bypass.(*fakeBypass).last().Endpoints
		slices.SortFunc(got, netip.Addr.Compare)
		if !reflect.DeepEqual(got, addrs("198.51.100.7", "203.0.113.10")) {
			t.Errorf("full first %v: endpoints kept outside %v", fullFirst, got)
		}
		if _, err := os.Stat(filepath.Join(m.resolvers.Dir, "diner.example")); err != nil {
			t.Errorf("the split tunnel's resolver file: %v", err)
		}

		if err := m.Down("manhattan"); err != nil {
			t.Fatal(err)
		}
		if got := m.bypass.(*fakeBypass).last(); !reflect.DeepEqual(got, bypass.Plan{}) {
			t.Errorf("with no full tunnel left: plan %+v", got)
		}
	}
}

func TestOneFullTunnelAtATime(t *testing.T) {
	m, devices := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	importText(t, m, "brooklyn", strings.Replace(fullFile("0.0.0.0/0", "10.65.0.1"), "10.64.0.2/32", "10.65.0.2/32", 1))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	err := m.Up(context.Background(), "brooklyn")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "manhattan routes everything already") {
		t.Errorf("got %v", err)
	}
	if len(*devices) != 1 {
		t.Errorf("started %d devices", len(*devices))
	}
}

func TestAnotherProgramsFullTunnelIsRefused(t *testing.T) {
	m, _ := newTestManager(t)
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{{Prefix: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun9"}}, nil
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	err := m.Up(context.Background(), "manhattan")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "utun9, another program's tunnel routes everything already") {
		t.Errorf("got %v", err)
	}
}

func TestTheLocalNetworkStaysBesideAFullTunnel(t *testing.T) {
	m, _ := newTestManager(t)
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{
			{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")},
			{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: "en0"},
		}, nil
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
}

func TestAFullTunnelNeedsADNSServer(t *testing.T) {
	m, devices := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", ""))
	err := m.Up(context.Background(), "manhattan")
	if err == nil || !strings.Contains(err.Error(), "manhattan routes everything but names no DNS server") {
		t.Errorf("got %v", err)
	}
	if len(*devices) != 0 {
		t.Error("a device was started")
	}
}

func TestASplitTunnelMayNotTakeTheFullTunnelsDNSServer(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	importText(t, m, "diner", splitFile("10.64.0.0/16", ""))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	err := m.Up(context.Background(), "diner")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "the full tunnel's DNS server 10.64.0.1 lies in diner's AllowedIPs 10.64.0.0/16") {
		t.Errorf("got %v", err)
	}
}

func TestWideTunnelsThatAreNotFullAreRefused(t *testing.T) {
	for _, allowed := range []string{"0.0.0.0/1", "2000::/3", "10.0.0.0/7", "::/0", "0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2"} {
		m, devices := newTestManager(t)
		importText(t, m, "pieces", fullFile(allowed, "10.64.0.1"))
		if err := m.Up(context.Background(), "pieces"); err == nil || !strings.Contains(err.Error(), "without routing all of it") {
			t.Errorf("%s: got %v", allowed, err)
		}
		if len(*devices) != 0 {
			t.Errorf("%s: a device was started", allowed)
		}
	}
}

func TestAFailedStartTakesTheBypassAway(t *testing.T) {
	m, _ := newTestManager(t)
	m.start = func(_ context.Context, _ *conf.Config, beforeRoutes func([]netip.AddrPort) error) (device, error) {
		if err := beforeRoutes([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820")}); err != nil {
			return nil, err
		}
		return nil, errors.New("WireGuard did not start on utun9")
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.Up(context.Background(), "manhattan"); err == nil {
		t.Fatal("no error")
	}
	if got := m.bypass.(*fakeBypass).last(); !reflect.DeepEqual(got, bypass.Plan{}) {
		t.Errorf("plan %+v", got)
	}
}

func TestCleanUpRemovesWhatAFullTunnelLeft(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.CleanUp(); err != nil {
		t.Fatal(err)
	}
	if !m.dnsAll.(*fakeDefaultDNS).cleared || len(m.bypass.(*fakeBypass).plans) != 1 || !reflect.DeepEqual(m.bypass.(*fakeBypass).last(), bypass.Plan{}) {
		t.Error("CleanUp left the default resolver or the bypass routes")
	}
}

func TestALocalRouteThatTakesTheTunnelsTrafficIsRefused(t *testing.T) {
	m, devices := newTestManager(t)
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{
			{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Interface: "en0"},
			{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Interface: "en0"},
			{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: "en0"},
		}, nil
	}
	importText(t, m, "williamsburg", fileWith("10.99.1.0/24", ""))
	if err := m.Up(context.Background(), "williamsburg"); err != nil {
		t.Fatalf("a wider local route should lose to the tunnel's own: %v", err)
	}
	importText(t, m, "brooklyn", fileWith("192.168.1.0/24", ""))
	err := m.Up(context.Background(), "brooklyn")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "the local network routes through en0") {
		t.Errorf("got %v", err)
	}
	if len(*devices) != 1 {
		t.Errorf("%d devices started, want 1", len(*devices))
	}
}

func TestAnEndpointUnderAnotherTunnelsDomainIsRefused(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "diner", fileWith("10.99.1.0/24", "10.99.1.1, example.com"))
	named := strings.Replace(fileWith("10.99.2.0/24", ""), "Endpoint = 127.0.0.1:51821", "Endpoint = vpn.example.com:51821", 1)
	importText(t, m, "cupcakes", named)
	if err := m.Up(context.Background(), "diner"); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(context.Background(), "cupcakes"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "the endpoint vpn.example.com is under the DNS domain example.com") {
		t.Errorf("got %v", err)
	}
}

func TestRecheckNotesARouteThatAppearedLater(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "manhattan", fileWith("10.99.1.0/24", ""))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	m.routes = func() ([]routes.Route, error) {
		return []routes.Route{{Prefix: netip.MustParsePrefix("10.99.1.128/25"), Interface: "utun12"}}, nil
	}
	m.Recheck()
	status, _ := m.Status("manhattan")
	if len(status.Notes) == 0 || !strings.Contains(strings.Join(status.Notes, " "), "now routes 10.99.1.128/25") {
		t.Errorf("notes %q", status.Notes)
	}
	m.routes = func() ([]routes.Route, error) { return nil, nil }
	m.Recheck()
	if status, _ := m.Status("manhattan"); len(status.Notes) != 0 {
		t.Errorf("the note stayed: %q", status.Notes)
	}
}

func TestTheKillSwitchGuardsAFullTunnelUntilItIsTakenDown(t *testing.T) {
	m, _ := newTestManager(t)
	fw := m.firewall.(*fakeFirewall)
	var atRoutes *firewall.Rules
	start := m.start
	m.start = func(ctx context.Context, c *conf.Config, beforeRoutes func([]netip.AddrPort) error) (device, error) {
		return start(ctx, c, func(endpoints []netip.AddrPort) error {
			err := beforeRoutes(endpoints)
			if fw.rules != nil {
				copied := *fw.rules
				atRoutes = &copied
			}
			return err
		})
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	importText(t, m, "diner", splitFile("10.99.1.0/24", ""))
	if err := m.Up(context.Background(), "diner"); err != nil {
		t.Fatal(err)
	}
	if fw.rules != nil {
		t.Fatal("a split tunnel alone turned the kill switch on")
	}
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	if atRoutes == nil || !slices.Contains(atRoutes.Servers, netip.MustParseAddrPort("203.0.113.10:51820")) {
		t.Errorf("before its routes, the kill switch was %+v: it must be on, letting the server through", atRoutes)
	}
	want := firewall.Rules{
		Interfaces: []string{"utun20", "utun21"},
		Servers:    []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820"), netip.MustParseAddrPort("203.0.113.10:51820")},
		AllowLAN:   true,
		Guards:     []string{"manhattan"},
	}
	slices.SortFunc(fw.rules.Servers, func(a, b netip.AddrPort) int { return a.Compare(b) })
	if !reflect.DeepEqual(*fw.rules, want) {
		t.Errorf("rules %+v, want %+v", *fw.rules, want)
	}
	status, _ := m.Status("manhattan")
	if status.KillSwitch != "on-drop" || status.Blocking || !strings.Contains(strings.Join(status.Notes, " "), "if it drops, the internet is blocked") {
		t.Errorf("status %+v", status)
	}

	if err := m.Down("manhattan"); err != nil {
		t.Fatal(err)
	}
	if fw.rules != nil {
		t.Error("taking it down did not turn the kill switch off")
	}
}

func TestAlwaysBlocksWhileTheFullTunnelIsDown(t *testing.T) {
	m, _ := newTestManager(t)
	fw := m.firewall.(*fakeFirewall)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.SetKillSwitch("manhattan", "always"); err != nil {
		t.Fatal(err)
	}
	if fw.rules == nil || len(fw.rules.Guards) != 0 {
		t.Fatalf("always, down: rules %+v (blocking, with nothing to bring back up)", fw.rules)
	}
	status, _ := m.Status("manhattan")
	if !status.Blocking || !strings.Contains(strings.Join(status.Notes, " "), "adit killswitch manhattan off lets it through") {
		t.Errorf("status %+v", status)
	}
	if err := m.SetKillSwitch("manhattan", "off"); err != nil {
		t.Fatal(err)
	}
	if fw.rules != nil {
		t.Error("off did not lift it")
	}
}

func TestRemovingTheTunnelLiftsItsKillSwitch(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	m.SetKillSwitch("manhattan", "always")
	if err := m.Remove("manhattan"); err != nil {
		t.Fatal(err)
	}
	if m.firewall.(*fakeFirewall).rules != nil {
		t.Error("the kill switch outlived its tunnel")
	}
}

func TestOffNeverBlocks(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	m.SetKillSwitch("manhattan", "off")
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	if m.firewall.(*fakeFirewall).rules != nil {
		t.Error("blocking with the kill switch off")
	}
	status, _ := m.Status("manhattan")
	if !strings.Contains(strings.Join(status.Notes, " "), "traffic goes out directly (kill switch off)") {
		t.Errorf("notes %v", status.Notes)
	}
}

func TestTheKillSwitchIsForFullTunnels(t *testing.T) {
	m, _ := newTestManager(t)
	mustImport(t, m, "diner")
	err := m.SetKillSwitch("diner", "always")
	if err == nil || !strings.Contains(err.Error(), "the kill switch is for a full tunnel") {
		t.Errorf("got %v", err)
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.SetKillSwitch("manhattan", "sometimes"); err == nil {
		t.Error("a made-up mode was taken")
	}
}

func TestANewAditdBringsBackWhatTheKillSwitchGuarded(t *testing.T) {
	m, _ := newTestManager(t)
	fw := m.firewall.(*fakeFirewall)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	// The last aditd died with manhattan up: its anchor still blocks.
	fw.previous = []string{"manhattan"}
	if err := m.CleanUp(); err != nil {
		t.Fatal(err)
	}
	if err := m.Autostart(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, _ := m.Status("manhattan")
		if status.State == StateConnecting && status.Interface != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("manhattan did not come back up: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fw.rules == nil {
		t.Error("the kill switch let go")
	}
}

func TestANewAditdLetsGoWhenNothingIsLeftToGuard(t *testing.T) {
	m, _ := newTestManager(t)
	fw := m.firewall.(*fakeFirewall)
	fw.previous = []string{"gone"} // removed since
	fw.rules = &firewall.Rules{Guards: []string{"gone"}}
	m.CleanUp()
	m.Autostart(context.Background())
	if fw.rules != nil {
		t.Error("an earlier aditd's kill switch kept blocking for a tunnel that is gone")
	}
}

func TestStoppingAditdKeepsTheKillSwitch(t *testing.T) {
	m, _ := newTestManager(t)
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	if err := m.Up(context.Background(), "manhattan"); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if fw := m.firewall.(*fakeFirewall); fw.rules == nil || !slices.Equal(fw.rules.Guards, []string{"manhattan"}) {
		t.Errorf("aditd stopping opened the Mac: %+v", fw.rules)
	}
}

func TestSignInLiftsTheKillSwitchForAWhile(t *testing.T) {
	m, _ := newTestManager(t)
	fw := m.firewall.(*fakeFirewall)
	if _, err := m.SignIn(); err == nil || !strings.Contains(err.Error(), "the kill switch is off") {
		t.Errorf("with nothing blocking: %v", err)
	}
	importText(t, m, "manhattan", fullFile("0.0.0.0/0", "10.64.0.1"))
	m.SetKillSwitch("manhattan", "always")
	m.signIn = 50 * time.Millisecond
	clock := time.Now()
	m.now = func() time.Time { return clock }

	until, err := m.SignIn()
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(clock.Add(50*time.Millisecond)) || fw.rules != nil {
		t.Errorf("until %v, rules %+v", until, fw.rules)
	}
	status, _ := m.Status("manhattan")
	if status.Blocking || !strings.Contains(strings.Join(status.Notes, " "), "to sign in to this network") {
		t.Errorf("status %+v", status)
	}

	m.mu.Lock()
	clock = clock.Add(time.Second)
	m.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		back := fw.rules != nil
		m.mu.Unlock()
		if back {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the kill switch did not come back")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
