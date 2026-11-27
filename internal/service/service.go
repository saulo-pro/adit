// Package service is aditd's core: it owns adit's tunnels, brings them up and down, reports their
// state and tells watchers when something changed.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/saulo-pro/adit/internal/bypass"
	"github.com/saulo-pro/adit/internal/conf"
	"github.com/saulo-pro/adit/internal/dns"
	"github.com/saulo-pro/adit/internal/dnsdefault"
	"github.com/saulo-pro/adit/internal/firewall"
	"github.com/saulo-pro/adit/internal/others"
	"github.com/saulo-pro/adit/internal/routes"
	"github.com/saulo-pro/adit/internal/store"
	"github.com/saulo-pro/adit/internal/tunnel"
)

// A tunnel that handshook within this long is up. WireGuard renews a handshake every two minutes
// while packets flow, so anything shorter would flap.
const upWithin = 3 * time.Minute

type State string

const (
	StateDown       State = "down"
	StateConnecting State = "connecting" // coming up, or up with no handshake yet
	StateUp         State = "up"         // handshake within upWithin
	StateIdle       State = "idle"       // running, last handshake older: healthy but unproven
)

// Status is one tunnel as status shows it. It holds no key but the peers' public ones.
type Status struct {
	Name          string
	Autostart     bool
	State         State
	Interface     string    // empty until the tunnel has one
	LastHandshake time.Time // the most recent of any peer's; zero if none
	Received      uint64    // bytes, all peers
	Sent          uint64
	Notes         []string // what a person should know about it, one sentence each
	KillSwitch    string   // a full tunnel's kill switch setting; empty for a split tunnel
	Blocking      bool     // its kill switch blocks the internet now: it is not up
	LAN           string   // a full tunnel's local network setting: allow or block
	Source        string   // "adit", or the other software running it
	ReadOnly      bool     // another program's tunnel: adit shows it and leaves it alone
}

// ErrConflict is matched with errors.Is when a tunnel would take networks or DNS domains that
// another tunnel already has; the error says which.
var ErrConflict = errors.New("tunnel conflict")

type conflictError struct{ msg string }

func (e *conflictError) Error() string { return e.msg }
func (e *conflictError) Unwrap() error { return ErrConflict }

func conflict(format string, args ...any) error {
	return &conflictError{fmt.Sprintf(format, args...)}
}

// device is a running tunnel; tunnel.Tunnel in aditd, a fake in tests.
type device interface {
	Interface() string
	Status() (tunnel.Status, error)
	Close() error
}

// starter brings a tunnel up; beforeRoutes runs with its endpoints' addresses before its routes go
// in.
type starter func(ctx context.Context, c *conf.Config, beforeRoutes func(endpoints []netip.AddrPort) error) (device, error)

// bypasser keeps the routes a full tunnel needs beside its own: bypass.Routes in aditd.
type bypasser interface {
	Apply(bypass.Plan) error
}

// killSwitch blocks what does not go through adit's tunnels: firewall.Firewall in aditd.
type killSwitch interface {
	Block(firewall.Rules) error
	Release() error
	Guards() ([]string, error)
}

// defaultResolver makes a full tunnel's DNS servers the Mac's default: dnsdefault.Default in aditd.
type defaultResolver interface {
	Set(tunnel string, servers []netip.Addr) error
	Clear(tunnel string) error
	ClearAll() error
}

// system is everything the Manager reaches outside itself: the Mac in aditd, fakes in tests.
type system struct {
	start     starter
	now       func() time.Time
	resolvers *dns.Resolvers
	bypass    bypasser
	firewall  killSwitch
	dnsAll    defaultResolver
	signIn    time.Duration                  // how long "Sign in to this network" lifts the kill switch
	routes    func() ([]routes.Route, error) // the routing table: other tunnels and the local network
	others    func() []others.Tunnel         // other software's tunnels: the WireGuard app's, wg-quick's
	retryWait time.Duration                  // the first pause between tries of an autostart tunnel
}

type running struct {
	dev    device
	config *conf.Config
	shape  shape
	notes  []string
	live   []string // what changed around it since it came up, as of the last check
}

// attempt is a tunnel coming up. Down and Remove cancel it; its own pointer tells Up whether the
// attempt it began is still the current one.
type attempt struct {
	cancel    context.CancelFunc
	config    *conf.Config
	shape     shape
	endpoints []netip.AddrPort // as resolved, once known: kept outside a full tunnel from the start
	done      chan struct{}    // closed once the attempt has finished and closed any device it made
}

type Manager struct {
	system
	store *store.Store
	log   *slog.Logger

	mu       sync.Mutex
	running  map[string]*running // by stored name
	starting map[string]*attempt // by stored name
	retrying map[string]*retry   // autostart tunnels aditd keeps trying, by stored name
	stopping map[string]*attempt // attempts taken down while starting, until their device is closed
	watchers map[chan struct{}]struct{}

	othersSeen []others.Tunnel // other software's tunnels, as last read
	othersRead time.Time

	resume      []string  // full tunnels an earlier aditd's kill switch guarded: brought back up at start
	pausedUntil time.Time // "Sign in to this network" lifts the kill switch until then
	pauseTimer  *time.Timer
}

func New(st *store.Store, log *slog.Logger) *Manager {
	return newManager(st, system{
		start: func(ctx context.Context, c *conf.Config, beforeRoutes func([]netip.AddrPort) error) (device, error) {
			t, err := tunnel.Start(ctx, c, beforeRoutes, log)
			if err != nil {
				return nil, err // not t: a nil *Tunnel in an interface is not nil
			}
			return t, nil
		},
		now:       time.Now,
		resolvers: &dns.Resolvers{Dir: dns.DefaultDir},
		bypass: &bypass.Routes{StateFile: bypass.DefaultStateFile, Table: routes.All, Run: func(args ...string) ([]byte, error) {
			return exec.Command("/sbin/route", args...).CombinedOutput()
		}},
		firewall: &firewall.Firewall{Anchor: firewall.DefaultAnchor, StateFile: firewall.DefaultStateFile, Run: func(stdin string, args ...string) ([]byte, error) {
			command := exec.Command("/sbin/pfctl", args...)
			if stdin != "" {
				command.Stdin = strings.NewReader(stdin)
			}
			return command.CombinedOutput()
		}},
		signIn: 2 * time.Minute,
		dnsAll: &dnsdefault.Default{Run: func(script string) ([]byte, error) {
			command := exec.Command("/usr/sbin/scutil")
			command.Stdin = strings.NewReader(script)
			return command.CombinedOutput()
		}},
		routes: routes.All,
		others: (&others.Finder{WireGuardDir: routes.WireGuardDir, Run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output()
		}}).All,
		retryWait: time.Second,
	}, log)
}

func newManager(st *store.Store, sys system, log *slog.Logger) *Manager {
	return &Manager{
		system:   sys,
		store:    st,
		log:      log,
		running:  map[string]*running{},
		starting: map[string]*attempt{},
		retrying: map[string]*retry{},
		stopping: map[string]*attempt{},
		watchers: map[chan struct{}]struct{}{},
	}
}

// CleanUp removes what an aditd that stopped without cleaning up left behind. At start no tunnel
// is up, so every resolver file and default resolver adit set is stale, and so are the routes a
// full tunnel needed beside its own; interfaces and their routes die with the process. The kill
// switch is not: it stays on, and the full tunnels it guarded come back up with Autostart, so the
// Mac is never left open between two aditds.
func (m *Manager) CleanUp() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	guards, err := m.firewall.Guards()
	m.resume = guards
	return errors.Join(m.resolvers.ClearAll(), m.dnsAll.ClearAll(), m.bypass.Apply(bypass.Plan{}), err)
}

// Changes signals after every import, removal, up, down and autostart change. Signals coalesce: a
// watcher reads the state afresh. A tunnel's handshake and counters change without a signal, so
// watchers also look again from time to time. Call stop when done.
func (m *Manager) Changes() (changes <-chan struct{}, stop func()) {
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	m.watchers[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		delete(m.watchers, ch)
		m.mu.Unlock()
	}
}

// notify must be called with m.mu held.
func (m *Manager) notify() {
	for ch := range m.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Import stores a tunnel from a file's text. It returns warnings a person should read: hook lines
// are kept but never run.
func (m *Manager) Import(name string, text []byte) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Add(name, text)
	if err != nil {
		return nil, err
	}
	m.log.Info("tunnel imported", "tunnel", t.Name)
	m.notify()

	var warnings []string
	for _, hook := range t.Config.Interface.Hooks() {
		warnings = append(warnings, fmt.Sprintf("%s line kept but not run: adit never runs commands from a configuration.", hook))
	}
	if i := t.Config.Interface; i.Table != "" {
		warnings = append(warnings, fmt.Sprintf("Table = %s line kept but ignored: adit adds a route for every AllowedIPs entry.", i.Table))
	}
	if i := t.Config.Interface; i.SaveConfig || i.FwMark != 0 {
		warnings = append(warnings, "SaveConfig and FwMark lines are kept but ignored: they mean something only to wg-quick on Linux.")
	}
	return warnings, nil
}

// File returns a tunnel's file as imported, private key included: for export only.
func (m *Manager) File(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.File(name)
}

// Remove takes a tunnel down if it is up or coming up, then deletes it.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return err
	}
	m.down(t.Name)
	if err := m.store.Remove(t.Name); err != nil {
		return err
	}
	m.reapply() // its kill switch goes with it
	m.log.Info("tunnel removed", "tunnel", t.Name)
	m.notify()
	return nil
}

// Up brings a tunnel up and returns once it is, or has failed. One already up, or coming up, is
// left alone. It refuses a tunnel whose networks or DNS domains another tunnel has. The lock is
// not held while the tunnel starts, which may take as long as resolving its endpoint: status keeps
// answering, with the tunnel shown as connecting.
func (m *Manager) Up(ctx context.Context, name string) error {
	return m.up(ctx, name, nil)
}

// up is Up for a person (r is nil) or for the retry r of an autostart tunnel, which gives up if
// the tunnel was taken down since it began.
func (m *Manager) up(ctx context.Context, name string, r *retry) error {
	m.mu.Lock()
	t, err := m.store.Get(name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if r != nil && m.retrying[t.Name] != r {
		m.mu.Unlock()
		return errStopped
	}
	// A start that was taken down may still hold a device: wait for it to let go, so a tunnel never
	// has two.
	for stopping, ok := m.stopping[t.Name]; ok; stopping, ok = m.stopping[t.Name] {
		m.mu.Unlock()
		select {
		case <-stopping.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
	}
	_, up := m.running[t.Name]
	_, coming := m.starting[t.Name]
	if up || coming {
		m.mu.Unlock()
		return nil
	}
	shape, err := shapeOf(t)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	notes, err := m.check(t, shape)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	this := &attempt{cancel: cancel, config: t.Config, shape: shape, done: make(chan struct{})}
	m.starting[t.Name] = this
	m.notify()
	m.mu.Unlock()

	// Before the tunnel's routes go in, its endpoints get routes of their own when a full tunnel is
	// up or this is one: otherwise the full tunnel's routes would take the packets that carry it.
	beforeRoutes := func(endpoints []netip.AddrPort) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.starting[t.Name] != this {
			return fmt.Errorf("taken down while it was coming up")
		}
		this.endpoints = endpoints
		return m.apply()
	}
	dev, err := m.start(ctx, t.Config, beforeRoutes)

	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.notify()
	current := m.starting[t.Name] == this
	if current {
		delete(m.starting, t.Name)
	}
	defer func() {
		if m.stopping[t.Name] == this {
			delete(m.stopping, t.Name)
		}
		close(this.done)
	}()
	switch {
	case err != nil:
		m.reapply()
		return fmt.Errorf("%s did not come up: %w", t.Name, err)
	case !current:
		dev.Close()
		m.reapply()
		return fmt.Errorf("%s was taken down while it was coming up", t.Name)
	}
	i := t.Config.Interface
	if shape.full {
		err = m.dnsAll.Set(t.Name, i.DNS)
	} else {
		err = m.resolvers.Set(t.Name, i.DNS, domains(t.Config))
	}
	if err != nil {
		dev.Close()
		m.reapply()
		return fmt.Errorf("%s did not come up, since its DNS could not be set: %w", t.Name, err)
	}
	m.running[t.Name] = &running{dev: dev, config: t.Config, shape: shape, notes: notes}
	m.reapply()
	m.log.Info("tunnel up", "tunnel", t.Name, "interface", dev.Interface(), "full", shape.full)
	return nil
}

// shape is what kind of tunnel a configuration makes.
type shape struct {
	full bool // routes everything: all of IPv4, and maybe all of IPv6
	ipv6 bool // a full tunnel that carries IPv6 too; otherwise native IPv6 is blocked while it is up
}

// shapeOf tells a full tunnel from a split one, and refuses the shapes adit does not run: most of the
// internet but not all of it, all of IPv6 without IPv4, and a full tunnel with no DNS server, which
// would leave every name to the network's resolver, outside the tunnel.
func shapeOf(t *store.Tunnel) (shape, error) {
	full4, full6 := covers(t.Config)
	if !full4 {
		if route, wide := fullTunnel(t.Config); wide {
			return shape{}, fmt.Errorf("%s routes a large part of the internet (AllowedIPs %s) without routing all of it; adit runs a full tunnel as AllowedIPs = 0.0.0.0/0 (and ::/0 for IPv6), or a tunnel that routes only its own networks", t.Name, route)
		}
		return shape{}, nil
	}
	if len(t.Config.Interface.DNS) == 0 {
		return shape{}, fmt.Errorf("%s routes everything but names no DNS server, so names would still be looked up outside the tunnel; add a line such as DNS = 10.64.0.1 with the server its provider gives", t.Name)
	}
	return shape{full: true, ipv6: full6}, nil
}

// covers says whether a config's networks take all of IPv4, and all of IPv6, as a /0 or as pieces.
func covers(c *conf.Config) (all4, all6 bool) {
	var covered4 uint64
	halves6 := 0
	for _, network := range merged(networks(c)) {
		switch {
		case network.Addr().Is4():
			covered4 += 1 << (32 - network.Bits())
		case network.Bits() == 0:
			halves6 += 2
		case network.Bits() == 1:
			halves6++
		}
	}
	return covered4 == 1<<32, halves6 >= 2
}

// own are the networks a tunnel serves besides everything: a full tunnel's catch-all networks are
// left out, since every more specific route (the local network's, a split tunnel's) wins over them.
func own(c *conf.Config, s shape) []netip.Prefix {
	if !s.full {
		return networks(c)
	}
	var mine []netip.Prefix
	for _, network := range networks(c) {
		if network.Addr().Is4() && network.Bits() >= 8 || network.Addr().Is6() && network.Bits() >= 16 {
			mine = append(mine, network)
		}
	}
	return mine
}

// apply gives the Mac what adit's tunnels need beside their own routes, as they are now: the routes
// beside a full tunnel (or none), and the kill switch (on or off). Called with m.mu held.
func (m *Manager) apply() error {
	var plan bypass.Plan
	full := false
	var endpoints []netip.AddrPort
	var interfaces []string
	for _, r := range m.running {
		if r.shape.full {
			full, plan.BlockIPv6 = true, !r.shape.ipv6
		}
		interfaces = append(interfaces, r.dev.Interface())
		if status, err := r.dev.Status(); err == nil {
			endpoints = append(endpoints, status.Endpoints()...)
		}
	}
	for _, a := range m.starting {
		if a.shape.full {
			full, plan.BlockIPv6 = true, !a.shape.ipv6
		}
		endpoints = append(endpoints, a.endpoints...)
	}
	if full {
		for _, endpoint := range endpoints {
			plan.Endpoints = append(plan.Endpoints, endpoint.Addr())
		}
	}
	if err := m.bypass.Apply(plan); err != nil {
		return fmt.Errorf("adit could not keep the endpoints outside the full tunnel: %w", err)
	}

	guards, resume := m.guards()
	lanBlocked := m.lanBlocked(guards)
	if len(guards) == 0 && !lanBlocked || m.now().Before(m.pausedUntil) {
		if err := m.firewall.Release(); err != nil {
			return fmt.Errorf("adit could not turn the kill switch off: %w", err)
		}
		return nil
	}
	slices.Sort(interfaces)
	rules := firewall.Rules{Interfaces: interfaces, Servers: endpoints, BlockAll: len(guards) > 0, AllowLAN: !lanBlocked, Guards: resume}
	if err := m.firewall.Block(rules); err != nil {
		return fmt.Errorf("adit could not turn the kill switch on: %w", err)
	}
	return nil
}

// reapply is apply where a failure can only be logged. Called with m.mu held.
func (m *Manager) reapply() {
	if err := m.apply(); err != nil {
		m.log.Warn("the routes or the kill switch are not as they should be", "error", err)
	}
}

// guards are the full tunnels whose kill switch is on now: on-drop ones that are up, coming up or
// being retried, and always ones, up or not. resume are those of them that are wanted up, which a
// later aditd brings back. Called with m.mu held.
func (m *Manager) guards() (guards, resume []string) {
	tunnels, err := m.store.List()
	if err != nil {
		// Unreadable: keep blocking for what is known to be up rather than open the Mac.
		m.log.Warn("could not read the tunnels' kill switch settings", "error", err)
	}
	for _, t := range tunnels {
		mode := t.Settings.KillSwitchMode()
		if full4, _ := covers(t.Config); !full4 || mode == store.KillSwitchOff {
			continue
		}
		_, up := m.running[t.Name]
		_, coming := m.starting[t.Name]
		_, trying := m.retrying[t.Name]
		wanted := up || coming || trying
		if wanted || mode == store.KillSwitchAlways {
			guards = append(guards, t.Name)
		}
		if wanted {
			resume = append(resume, t.Name)
		}
	}
	return guards, resume
}

// minutes says a duration the way a person would: "2 minutes".
func minutes(d time.Duration) string {
	if n := int(d.Round(time.Minute) / time.Minute); n > 1 {
		return fmt.Sprintf("%d minutes", n)
	}
	return "a minute"
}

// lanBlocked says whether a full tunnel that is up, coming up or guarded by its kill switch blocks
// the local network. Called with m.mu held.
func (m *Manager) lanBlocked(guards []string) bool {
	tunnels, _ := m.store.List()
	for _, t := range tunnels {
		if t.Settings.LANMode() != store.LANBlock {
			continue
		}
		_, up := m.running[t.Name]
		_, coming := m.starting[t.Name]
		if full4, _ := covers(t.Config); full4 && (up || coming || slices.Contains(guards, t.Name)) {
			return true
		}
	}
	return false
}

// blockingNow are the full tunnels whose kill switch blocks now: none while it is lifted to sign
// in. Called with m.mu held.
func (m *Manager) blockingNow() []string {
	if m.now().Before(m.pausedUntil) {
		return nil
	}
	guards, _ := m.guards()
	return guards
}

// fullTunnel finds AllowedIPs that route everywhere, or a large part of it. It judges what the networks cover
// together, not one at a time: two /1 halves, four /2 networks or 2000::/3 are full tunnels too. A
// network wider than /8 (IPv4) or /16 (IPv6), or IPv4 networks covering half the space, count.
func fullTunnel(c *conf.Config) (netip.Prefix, bool) {
	var covered uint64
	for _, network := range networks(c) {
		if network.Addr().Is4() && network.Bits() < 8 || network.Addr().Is6() && network.Bits() < 16 {
			return network, true
		}
	}
	for _, network := range merged(networks(c)) {
		if network.Addr().Is4() {
			covered += 1 << (32 - network.Bits())
			if covered >= 1<<31 {
				return network, true
			}
		}
	}
	return netip.Prefix{}, false
}

// merged drops the networks another one in the list already contains, so each address counts once.
func merged(all []netip.Prefix) []netip.Prefix {
	var kept []netip.Prefix
	for i, p := range all {
		inside := false
		for j, q := range all {
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q.Bits() < p.Bits() || j < i) {
				inside = true
				break
			}
		}
		if !inside {
			kept = append(kept, p)
		}
	}
	return kept
}

// check refuses a tunnel whose networks or DNS domains another tunnel already has, adit's or
// another program's, and returns notes about what the tunnel shares. Called with m.mu held.
func (m *Manager) check(t *store.Tunnel, s shape) ([]string, error) {
	mine := own(t.Config, s)
	myDomains := domains(t.Config)
	if s.full {
		myDomains = nil // its servers answer every name, through dnsdefault
	}

	for name, sibling := range m.siblings(t.Name) {
		config := sibling.config
		if s.full && sibling.shape.full {
			return nil, conflict("%s routes everything already, and adit runs one full tunnel at a time; take %s down first", name, name)
		}
		// The full tunnel's DNS servers must stay inside it: a split tunnel taking one would answer
		// for every name.
		for _, pair := range []struct {
			full  *conf.Config
			fullS shape
			split *conf.Config
			name  string
		}{{t.Config, s, config, name}, {config, sibling.shape, t.Config, t.Name}} {
			if !pair.fullS.full {
				continue
			}
			for _, server := range pair.full.Interface.DNS {
				for _, b := range networks(pair.split) {
					if b.Contains(server) {
						return nil, conflict("the full tunnel's DNS server %s lies in %s's AllowedIPs %s, so every name would be looked up through %s; take one of them down first, or change AllowedIPs", server, pair.name, b, pair.name)
					}
				}
			}
		}
		for _, a := range mine {
			for _, b := range own(config, sibling.shape) {
				if a.Overlaps(b) {
					return nil, conflict("%s's AllowedIPs %s overlaps %s of %s, which is up; take %s down first, or change one of them", t.Name, a, b, name, name)
				}
			}
		}
		// A tunnel's own address inside another's networks would make the two answer for it.
		me, them := upTunnel{t.Config, s}, sibling
		for _, pair := range [][2]upTunnel{{me, them}, {them, me}} {
			for _, address := range pair[0].config.Interface.Addresses {
				for _, b := range own(pair[1].config, pair[1].shape) {
					if b.Contains(address.Addr()) {
						return nil, conflict("the address %s of one of %s and %s lies in the other's AllowedIPs %s; take %s down first, or change one of them", address.Addr(), t.Name, name, b, name)
					}
				}
			}
		}
		// A name looked up through another tunnel's DNS would let that tunnel's server choose where
		// this one connects. A full tunnel's servers answer every name, by design: that is the trust
		// a full tunnel asks for.
		for _, pair := range [][2]upTunnel{{me, them}, {them, me}} {
			if pair[1].shape.full {
				continue
			}
			for _, peer := range pair[0].config.Peers {
				if _, err := netip.ParseAddr(peer.Endpoint.Host); err == nil || peer.Endpoint.IsZero() {
					continue
				}
				for _, d := range domains(pair[1].config) {
					if sameDomain(peer.Endpoint.Host, d) {
						return nil, conflict("the endpoint %s is under the DNS domain %s that one of %s and %s resolves through its tunnel; take %s down first", peer.Endpoint.Host, d, t.Name, name, name)
					}
				}
			}
		}
		for _, d := range myDomains {
			if sibling.shape.full {
				break
			}
			for _, e := range domains(config) {
				if sameDomain(d, e) {
					return nil, conflict("%s's DNS domain %s is already resolved through %s, which is up; take %s down first", t.Name, d, name, name)
				}
			}
		}
	}

	system, err := m.routes()
	if err != nil {
		return nil, fmt.Errorf("adit could not read the routing table to check %s against other tunnels: %w", t.Name, err)
	}
	ours := map[string]bool{}
	for _, r := range m.running {
		ours[r.dev.Interface()] = true
	}
	var notes []string
	noted := map[string]bool{}
	for _, route := range system {
		if ours[route.Interface] {
			continue
		}
		if !routes.TunnelInterface(route.Interface) {
			if a, ok := localSteals(mine, route); ok {
				return nil, conflict("%s's AllowedIPs %s overlaps %s, which the local network routes through %s: that traffic would not use the tunnel; change AllowedIPs, or join another network", t.Name, a, route.Prefix, route.Interface)
			}
			continue
		}
		if routes.CatchAll(route.Prefix) {
			if s.full {
				return nil, conflict("%s routes everything already, and the Mac can follow only one full tunnel; take it down first", m.describe(route.Interface))
			}
			if note := endpointNote(t, route, m.describe(route.Interface)); note != "" && !noted[route.Interface] {
				noted[route.Interface] = true
				notes = append(notes, note)
			}
			continue
		}
		for _, a := range mine {
			if a.Overlaps(route.Prefix) {
				return nil, conflict("%s's AllowedIPs %s overlaps %s, which %s routes; take that tunnel down first, or change AllowedIPs", t.Name, a, route.Prefix, m.describe(route.Interface))
			}
		}
	}

	if err := m.resolvers.Check(t.Name, myDomains); err != nil {
		if errors.Is(err, dns.ErrNotOurs) {
			return nil, conflict("%s", err)
		}
		return nil, err
	}
	return notes, nil
}

// localSteals finds a network of mine that a route of the local network takes traffic from: one as
// specific as it, or more. A wider local route (a default route, a /16 around a /24) loses to the
// tunnel's own and is fine. Loopback routes are the Mac's own addresses.
func localSteals(mine []netip.Prefix, route routes.Route) (netip.Prefix, bool) {
	if route.Interface == "lo0" || routes.CatchAll(route.Prefix) {
		return netip.Prefix{}, false
	}
	for _, a := range mine {
		if a.Overlaps(route.Prefix) && route.Prefix.Bits() >= a.Bits() {
			return a, true
		}
	}
	return netip.Prefix{}, false
}

// Recheck looks again, for every tunnel that is up, at routes other software added since it came
// up: another VPN, or the local network, may now take some of its traffic. What it finds shows in
// status and the menu until it goes away. aditd calls it after network changes and every minute.
func (m *Manager) Recheck() {
	table, err := m.routes()
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ours := map[string]bool{}
	for _, r := range m.running {
		ours[r.dev.Interface()] = true
	}
	changed := false
	for name, r := range m.running {
		var live []string
		mine := own(r.config, r.shape)
		for _, route := range table {
			if ours[route.Interface] {
				continue
			}
			if r.shape.full && routes.TunnelInterface(route.Interface) && routes.CatchAll(route.Prefix) {
				note := fmt.Sprintf("%s now routes everything too, so traffic may not use %s", m.describe(route.Interface), name)
				if !slices.Contains(live, note) {
					live = append(live, note)
				}
				continue
			}
			if !routes.TunnelInterface(route.Interface) {
				if a, ok := localSteals(mine, route); ok {
					live = append(live, fmt.Sprintf("the local network now routes %s through %s, so traffic for that part of %s does not use %s", route.Prefix, route.Interface, a, name))
				}
				continue
			}
			if routes.CatchAll(route.Prefix) {
				continue
			}
			for _, a := range mine {
				if a.Overlaps(route.Prefix) && route.Prefix.Bits() >= a.Bits() {
					live = append(live, fmt.Sprintf("%s now routes %s, inside %s, so that traffic does not use %s", m.describe(route.Interface), route.Prefix, a, name))
				}
			}
		}
		if !slices.Equal(live, r.live) {
			r.live, changed = live, true
			for _, note := range live {
				m.log.Warn("another route takes part of a tunnel's traffic", "tunnel", name, "note", note)
			}
		}
	}
	if changed {
		m.notify()
	}
}

type upTunnel struct {
	config *conf.Config
	shape  shape
}

// siblings are adit's tunnels that are up or coming up, other than name.
func (m *Manager) siblings(name string) map[string]upTunnel {
	all := map[string]upTunnel{}
	for other, r := range m.running {
		all[other] = upTunnel{r.config, r.shape}
	}
	for other, a := range m.starting {
		all[other] = upTunnel{a.config, a.shape}
	}
	delete(all, name)
	return all
}

// endpointNote says when another program's full tunnel will probably carry this tunnel's own
// packets: it still works, but through that tunnel.
func endpointNote(t *store.Tunnel, catchAll routes.Route, owner string) string {
	for _, peer := range t.Config.Peers {
		if peer.Endpoint.IsZero() {
			continue
		}
		addr, err := netip.ParseAddr(peer.Endpoint.Host)
		if err == nil && (addr.IsLoopback() || addr.Is4() != catchAll.Prefix.Addr().Is4()) {
			continue
		}
		return fmt.Sprintf("the endpoint %s is probably reached through %s, which routes everything", peer.Endpoint.Host, owner)
	}
	return ""
}

// networks are a config's AllowedIPs, as the networks they route.
func networks(c *conf.Config) []netip.Prefix {
	var networks []netip.Prefix
	for _, peer := range c.Peers {
		for _, allowed := range peer.AllowedIPs {
			networks = append(networks, allowed.Masked())
		}
	}
	return networks
}

// domains are the DNS domains a config sends to its servers: none without a server.
func domains(c *conf.Config) []string {
	if len(c.Interface.DNS) == 0 {
		return nil
	}
	return c.Interface.DNSSearch
}

func sameDomain(a, b string) bool {
	return dns.Overlap(a, b)
}

// fullNotes say what a full tunnel does while it is up.
func fullNotes(s shape, killSwitch, lan string) []string {
	drop := "if it drops, traffic goes out directly (kill switch off)"
	switch killSwitch {
	case store.KillSwitchOnDrop:
		drop = "if it drops, the internet is blocked until it is back (kill switch)"
	case store.KillSwitchAlways:
		drop = "whenever it is down, the internet is blocked (kill switch: always)"
	}
	routes := "it routes all traffic but the local network's and adit's other tunnels'"
	if lan == store.LANBlock {
		routes = "it routes all traffic but adit's other tunnels', and the local network is blocked"
	}
	notes := []string{routes + ", and its DNS servers answer every name but the other tunnels' domains; " + drop}
	if !s.ipv6 {
		notes = append(notes, "IPv6 is blocked while it is up, since it carries only IPv4")
	}
	return notes
}

// dnsNotes say when a DNS line does nothing: adit scopes DNS to domains.
func dnsNotes(c *conf.Config) []string {
	if full4, _ := covers(c); full4 {
		return nil // its servers answer every name
	}
	i := c.Interface
	switch {
	case len(i.DNS) > 0 && len(i.DNSSearch) == 0:
		servers := make([]string, len(i.DNS))
		for n, server := range i.DNS {
			servers[n] = server.String()
		}
		return []string{fmt.Sprintf("DNS %s is not used: adit sends a tunnel's DNS queries only for the domains on its DNS line, and this line names none", strings.Join(servers, ", "))}
	case len(i.DNS) == 0 && len(i.DNSSearch) > 0:
		return []string{fmt.Sprintf("the DNS domains %s are not used: the DNS line names no server for them", strings.Join(i.DNSSearch, ", "))}
	}
	return nil
}

// Down takes a tunnel down, or stops it coming up; one already down is left alone.
func (m *Manager) Down(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return err
	}
	m.down(t.Name)
	m.notify()
	return nil
}

// down must be called with m.mu held.
func (m *Manager) down(name string) {
	if r, trying := m.retrying[name]; trying {
		r.cancel()
		delete(m.retrying, name)
	}
	if a, coming := m.starting[name]; coming {
		a.cancel()
		delete(m.starting, name)
		m.stopping[name] = a
	}
	if r, up := m.running[name]; up {
		// DNS goes first: names must not go on to the tunnel's servers once it cannot reach them.
		if err := m.clearDNS(name, r.shape); err != nil {
			m.log.Warn("DNS settings left behind", "tunnel", name, "error", err)
		}
		r.dev.Close()
		delete(m.running, name)
		m.log.Info("tunnel down", "tunnel", name)
	}
	m.reapply()
}

func (m *Manager) clearDNS(name string, s shape) error {
	if s.full {
		return m.dnsAll.Clear(name)
	}
	return m.resolvers.Clear(name)
}

// SetAutostart chooses whether a tunnel comes up when aditd starts.
func (m *Manager) SetAutostart(name string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return err
	}
	settings := t.Settings
	settings.Autostart = on
	if err := m.store.SetSettings(t.Name, settings); err != nil {
		return err
	}
	m.notify()
	return nil
}

// SetKillSwitch chooses when a full tunnel's kill switch blocks: KillSwitchOff, OnDrop or Always.
func (m *Manager) SetKillSwitch(name, mode string) error {
	if mode != store.KillSwitchOff && mode != store.KillSwitchOnDrop && mode != store.KillSwitchAlways {
		return fmt.Errorf("the kill switch is %s, %s or %s, not %q", store.KillSwitchOnDrop, store.KillSwitchAlways, store.KillSwitchOff, mode)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return err
	}
	if full4, _ := covers(t.Config); !full4 {
		return fmt.Errorf("%s routes only its own networks; the kill switch is for a full tunnel, which routes everything", t.Name)
	}
	settings := t.Settings
	settings.KillSwitch = mode
	if err := m.store.SetSettings(t.Name, settings); err != nil {
		return err
	}
	m.log.Info("kill switch set", "tunnel", t.Name, "mode", mode)
	err = m.apply()
	m.notify()
	return err
}

// SetLAN chooses whether a full tunnel lets the local network be reached: LANAllow or LANBlock.
func (m *Manager) SetLAN(name, mode string) error {
	if mode != store.LANAllow && mode != store.LANBlock {
		return fmt.Errorf("the local network is %s or %s, not %q", store.LANAllow, store.LANBlock, mode)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return err
	}
	if full4, _ := covers(t.Config); !full4 {
		return fmt.Errorf("%s routes only its own networks, so the local network is not its to block; the setting is for a full tunnel", t.Name)
	}
	settings := t.Settings
	settings.LAN = mode
	if err := m.store.SetSettings(t.Name, settings); err != nil {
		return err
	}
	m.log.Info("local network setting changed", "tunnel", t.Name, "lan", mode)
	err = m.apply()
	m.notify()
	return err
}

// SignIn lifts the kill switch for a short while, so a hotel's or an airport's sign-in page can be
// reached before the full tunnel can connect. It returns when the kill switch comes back.
func (m *Manager) SignIn() (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if guards, _ := m.guards(); len(guards) == 0 {
		return time.Time{}, fmt.Errorf("the kill switch is off, so nothing stops signing in to this network")
	}
	m.pausedUntil = m.now().Add(m.signIn)
	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
	}
	m.pauseTimer = time.AfterFunc(m.signIn, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.pausedUntil = time.Time{}
		m.reapply()
		m.log.Info("kill switch back on after signing in to the network")
		m.notify()
	})
	m.log.Info("kill switch lifted to sign in to the network", "until", m.pausedUntil)
	err := m.apply()
	m.notify()
	return m.pausedUntil, err
}

// List reports every tunnel adit holds, sorted by name.
func (m *Manager) List() ([]Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnels, err := m.store.List()
	if err != nil {
		return nil, err
	}
	blocking := m.blockingNow()
	statuses := make([]Status, 0, len(tunnels))
	for _, t := range tunnels {
		status, err := m.status(t, blocking)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// Status reports one tunnel.
func (m *Manager) Status(name string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, err := m.store.Get(name)
	if err != nil {
		return Status{}, err
	}
	return m.status(t, m.blockingNow())
}

func (m *Manager) status(t *store.Tunnel, blocking []string) (Status, error) {
	status := Status{Name: t.Name, Autostart: t.Settings.Autostart, State: StateDown, Notes: dnsNotes(t.Config), Source: "adit"}
	full4, _ := covers(t.Config)
	if full4 {
		status.KillSwitch = t.Settings.KillSwitchMode()
		status.LAN = t.Settings.LANMode()
	}
	_, up := m.running[t.Name]
	if full4 && !up && slices.Contains(blocking, t.Name) {
		status.Blocking = true
		lift := "adit down " + t.Name
		if status.KillSwitch == store.KillSwitchAlways {
			lift = "adit killswitch " + t.Name + " off"
		}
		status.Notes = append(status.Notes, fmt.Sprintf("the internet is blocked until %s is up (kill switch); %s lets it through, and adit signin lifts it for %s to sign in to a network", t.Name, lift, minutes(m.signIn)))
	}
	if full4 && m.now().Before(m.pausedUntil) {
		status.Notes = append(status.Notes, fmt.Sprintf("the kill switch is lifted until %s, to sign in to this network", m.pausedUntil.Local().Format("15:04:05")))
	}
	if _, coming := m.starting[t.Name]; coming {
		status.State = StateConnecting
		return status, nil
	}
	r, up := m.running[t.Name]
	if !up {
		if trying, ok := m.retrying[t.Name]; ok {
			status.State = StateConnecting
			if trying.last != "" {
				status.Notes = append(status.Notes, fmt.Sprintf("aditd is bringing it up and will try again in %s: %s",
					max(0, trying.next.Sub(m.now())).Round(time.Second), trying.last))
			}
		}
		return status, nil
	}
	if r.shape.full {
		status.Notes = append(fullNotes(r.shape, status.KillSwitch, status.LAN), status.Notes...)
	}
	status.Notes = append(status.Notes, r.notes...)
	status.Notes = append(status.Notes, r.live...)

	reported, err := r.dev.Status()
	if err != nil {
		return Status{}, err
	}
	status.Interface = reported.Interface
	status.LastHandshake, status.Received, status.Sent = sum(reported.Peers)
	status.State = m.stateOf(status.LastHandshake)
	return status, nil
}

// sum is a tunnel's latest handshake, of any peer, and its bytes over all of them.
func sum(peers []tunnel.PeerStatus) (handshake time.Time, received, sent uint64) {
	for _, peer := range peers {
		if peer.LastHandshake.After(handshake) {
			handshake = peer.LastHandshake
		}
		received += peer.Received
		sent += peer.Sent
	}
	return handshake, received, sent
}

// stateOf is a running tunnel's state from its latest handshake.
func (m *Manager) stateOf(handshake time.Time) State {
	switch {
	case handshake.IsZero():
		return StateConnecting
	case m.now().Sub(handshake) <= upWithin:
		return StateUp
	default:
		return StateIdle
	}
}

// Close takes every tunnel down, as aditd stops.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.retrying {
		r.cancel()
	}
	clear(m.retrying)
	for _, a := range m.starting {
		a.cancel()
	}
	clear(m.starting)
	var errs []error
	for name, r := range m.running {
		errs = append(errs, m.clearDNS(name, r.shape), r.dev.Close())
		delete(m.running, name)
	}
	// The kill switch stays as it is: aditd stopping (an upgrade, a restart) must not open the Mac.
	// The next aditd takes it over, and `adit uninstall` removes it.
	errs = append(errs, m.bypass.Apply(bypass.Plan{}))
	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
	}
	m.notify()
	return errors.Join(errs...)
}
