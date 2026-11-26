package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/conf"
	"github.com/saulo-pro/adit/internal/dns"
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

func TestFullTunnelsWaitForALaterVersion(t *testing.T) {
	for _, allowed := range []string{"0.0.0.0/0", "::/0"} {
		m, devices := newTestManager(t)
		full := strings.Replace(file, "AllowedIPs = 10.99.1.0/24", "AllowedIPs = 10.99.1.0/24, "+allowed, 1)
		if _, err := m.Import("everything", []byte(full)); err != nil {
			t.Fatal(err)
		}
		err := m.Up(context.Background(), "everything")
		if err == nil || !strings.Contains(err.Error(), "everything routes everything (AllowedIPs "+allowed+")") {
			t.Errorf("got %v", err)
		}
		if len(*devices) != 0 {
			t.Error("a device was started")
		}
	}
}

func TestFailureToStartNamesTheTunnel(t *testing.T) {
	m, _ := newTestManager(t)
	m.start = func(context.Context, *conf.Config) (device, error) {
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
	start := func(context.Context, *conf.Config) (device, error) {
		dev := &fakeDevice{status: tunnel.Status{Interface: "utun2" + string(rune('0'+len(*devices)))}}
		*devices = append(*devices, dev)
		return dev, nil
	}
	m := newManager(st, system{
		start:     start,
		now:       func() time.Time { return now },
		resolvers: &dns.Resolvers{Dir: filepath.Join(t.TempDir(), "resolver")},
		routes:    func() ([]routes.Route, error) { return nil, nil },
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, devices
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
	m.start = func(context.Context, *conf.Config) (device, error) {
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
	m.start = func(ctx context.Context, _ *conf.Config) (device, error) {
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
	m.start = func(context.Context, *conf.Config) (device, error) {
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
		return []others.Tunnel{{Name: "stamford", Source: others.SourceWgQuick, Interface: "utun8", State: "running"}}
	}
	mustImport(t, m, "work")

	err := m.Up(context.Background(), "work")
	want := "work's AllowedIPs 10.99.1.0/24 overlaps 10.99.0.0/16, which utun8 (wg-quick's stamford) routes; take that tunnel down first, or change AllowedIPs"
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
func fileWith(allowed, dns string) string {
	text := strings.Replace(file, "AllowedIPs = 10.99.1.0/24", "AllowedIPs = "+allowed, 1)
	if dns != "" {
		text = strings.Replace(text, "Address = 10.99.1.2/24\n", "Address = 10.99.1.2/24\nDNS = "+dns+"\n", 1)
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
	m.start = func(ctx context.Context, c *conf.Config) (device, error) {
		mu.Lock()
		defer mu.Unlock()
		if failures > 0 {
			failures--
			return nil, errors.New("the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line")
		}
		return start(ctx, c)
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
	m.start = func(context.Context, *conf.Config) (device, error) {
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
	m.start = func(context.Context, *conf.Config) (device, error) {
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
