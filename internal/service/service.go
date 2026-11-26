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
	"strings"
	"sync"
	"time"

	"github.com/saulo-pro/adit/internal/conf"
	"github.com/saulo-pro/adit/internal/dns"
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

type starter func(ctx context.Context, c *conf.Config) (device, error)

// system is everything the Manager reaches outside itself: the Mac in aditd, fakes in tests.
type system struct {
	start     starter
	now       func() time.Time
	resolvers *dns.Resolvers
	routes    func() ([]routes.Route, error) // other software's tunnels
	others    func() []others.Tunnel         // other software's tunnels: the WireGuard app's, wg-quick's
	retryWait time.Duration                  // the first pause between tries of an autostart tunnel
}

type running struct {
	dev    device
	config *conf.Config
	notes  []string
}

// attempt is a tunnel coming up. Down and Remove cancel it; its own pointer tells Up whether the
// attempt it began is still the current one.
type attempt struct {
	cancel context.CancelFunc
	config *conf.Config
}

type Manager struct {
	system
	store *store.Store
	log   *slog.Logger

	mu       sync.Mutex
	running  map[string]*running // by stored name
	starting map[string]*attempt // by stored name
	retrying map[string]*retry   // autostart tunnels aditd keeps trying, by stored name
	watchers map[chan struct{}]struct{}

	othersSeen []others.Tunnel // other software's tunnels, as last read
	othersRead time.Time
}

func New(st *store.Store, log *slog.Logger) *Manager {
	return newManager(st, system{
		start: func(ctx context.Context, c *conf.Config) (device, error) {
			t, err := tunnel.Start(ctx, c, log)
			if err != nil {
				return nil, err // not t: a nil *Tunnel in an interface is not nil
			}
			return t, nil
		},
		now:       time.Now,
		resolvers: &dns.Resolvers{Dir: dns.DefaultDir},
		routes:    routes.Tunnels,
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
		watchers: map[chan struct{}]struct{}{},
	}
}

// CleanUp removes what an aditd that stopped without cleaning up left behind. At start no tunnel
// is up, so every resolver file adit wrote is stale; interfaces and routes die with the process.
func (m *Manager) CleanUp() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resolvers.ClearAll()
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
	_, up := m.running[t.Name]
	_, coming := m.starting[t.Name]
	if up || coming {
		m.mu.Unlock()
		return nil
	}
	if route, full := fullTunnel(t.Config); full {
		m.mu.Unlock()
		return fmt.Errorf("%s routes everything (AllowedIPs %s), and full tunnels come in a later version of adit; for now a tunnel must route only its own networks", t.Name, route)
	}
	notes, err := m.check(t)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	this := &attempt{cancel: cancel, config: t.Config}
	m.starting[t.Name] = this
	m.notify()
	m.mu.Unlock()

	dev, err := m.start(ctx, t.Config)

	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.notify()
	current := m.starting[t.Name] == this
	if current {
		delete(m.starting, t.Name)
	}
	switch {
	case err != nil:
		return fmt.Errorf("%s did not come up: %w", t.Name, err)
	case !current:
		dev.Close()
		return fmt.Errorf("%s was taken down while it was coming up", t.Name)
	}
	i := t.Config.Interface
	if err := m.resolvers.Set(t.Name, i.DNS, domains(t.Config)); err != nil {
		dev.Close()
		return fmt.Errorf("%s did not come up, since its DNS could not be set: %w", t.Name, err)
	}
	m.running[t.Name] = &running{dev: dev, config: t.Config, notes: notes}
	m.log.Info("tunnel up", "tunnel", t.Name, "interface", dev.Interface())
	return nil
}

// fullTunnel finds a route to everywhere, which needs the endpoint kept outside the tunnel across
// network changes: milestone 2.
func fullTunnel(c *conf.Config) (netip.Prefix, bool) {
	for _, network := range networks(c) {
		if routes.CatchAll(network) {
			return network, true
		}
	}
	return netip.Prefix{}, false
}

// check refuses a tunnel whose networks or DNS domains another tunnel already has, adit's or
// another program's, and returns notes about what the tunnel shares. Called with m.mu held.
func (m *Manager) check(t *store.Tunnel) ([]string, error) {
	mine := networks(t.Config)
	myDomains := domains(t.Config)

	for name, config := range m.siblings(t.Name) {
		for _, a := range mine {
			for _, b := range networks(config) {
				if a.Overlaps(b) {
					return nil, conflict("%s's AllowedIPs %s overlaps %s of %s, which is up; take %s down first, or change one of them", t.Name, a, b, name, name)
				}
			}
		}
		for _, d := range myDomains {
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
		if routes.CatchAll(route.Prefix) {
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

// siblings are the configs of adit's tunnels that are up or coming up, other than name.
func (m *Manager) siblings(name string) map[string]*conf.Config {
	configs := map[string]*conf.Config{}
	for other, r := range m.running {
		configs[other] = r.config
	}
	for other, a := range m.starting {
		configs[other] = a.config
	}
	delete(configs, name)
	return configs
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
	trim := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
	return trim(a) == trim(b)
}

// dnsNotes say when a DNS line does nothing: adit scopes DNS to domains.
func dnsNotes(c *conf.Config) []string {
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
	}
	if r, up := m.running[name]; up {
		r.dev.Close()
		delete(m.running, name)
		if err := m.resolvers.Clear(name); err != nil {
			m.log.Warn("resolver files left behind", "tunnel", name, "error", err)
		}
		m.log.Info("tunnel down", "tunnel", name)
	}
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

// List reports every tunnel adit holds, sorted by name.
func (m *Manager) List() ([]Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnels, err := m.store.List()
	if err != nil {
		return nil, err
	}
	statuses := make([]Status, 0, len(tunnels))
	for _, t := range tunnels {
		status, err := m.status(t)
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
	return m.status(t)
}

func (m *Manager) status(t *store.Tunnel) (Status, error) {
	status := Status{Name: t.Name, Autostart: t.Settings.Autostart, State: StateDown, Notes: dnsNotes(t.Config), Source: "adit"}
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
	status.Notes = append(status.Notes, r.notes...)

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
		errs = append(errs, r.dev.Close(), m.resolvers.Clear(name))
		delete(m.running, name)
	}
	m.notify()
	return errors.Join(errs...)
}
