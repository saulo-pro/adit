package tunnel

import (
	"context"
	"fmt"
	adroutes "github.com/saulo-pro/adit/internal/routes"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/saulo-pro/adit/internal/conf"
)

// Tunnel is one running tunnel: a wireguard-go device on a utun interface.
type Tunnel struct {
	iface  string
	device *device.Device
	config *conf.Config
}

// Start brings a tunnel up. Its addresses and routes are set the way wg-quick sets them on macOS,
// with /sbin/ifconfig and /sbin/route and arguments built only from parsed addresses. Closing the
// device removes the interface, and its routes with it.
func Start(ctx context.Context, c *conf.Config, log *slog.Logger) (*Tunnel, error) {
	endpoints, err := resolveEndpoints(ctx, net.DefaultResolver, c.Peers)
	if err != nil {
		return nil, err
	}
	if err := checkEndpointsOutside(c.Peers, endpoints); err != nil {
		return nil, err
	}

	mtu := c.Interface.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tunDevice, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("macOS did not create a utun interface: %w", err)
	}
	iface, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("macOS did not name the utun interface: %w", err)
	}

	t := &Tunnel{iface: iface, device: device.NewDevice(tunDevice, conn.NewDefaultBind(), deviceLogger(log, iface)), config: c}
	// A peer's endpoint stays where the configuration (or adit's own lookup of its name) puts it:
	// one authenticated packet from elsewhere must not move it.
	t.device.DisableSomeRoamingForBrokenMobileSemantics()
	if err := t.device.IpcSet(deviceConfig(c, endpoints)); err != nil {
		t.Close()
		return nil, fmt.Errorf("WireGuard refused the configuration: %w", err)
	}
	if err := t.device.Up(); err != nil {
		t.Close()
		return nil, fmt.Errorf("WireGuard did not start on %s: %w", iface, err)
	}
	if err := configure(iface, mtu, c); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *Tunnel) Interface() string {
	return t.iface
}

func (t *Tunnel) Status() (Status, error) {
	// The device reports its keys too; they are dropped line by line as they arrive, so the text
	// that is kept, parsed or logged never holds one.
	var text withoutKeys
	if err := t.device.IpcGetOperation(&text); err != nil {
		return Status{}, fmt.Errorf("the device on %s did not report its status: %w", t.iface, err)
	}
	return ParseStatus(t.iface, text.String())
}

// NetworkChanged moves the device's UDP socket to the Mac's new network, then looks endpoint names up
// again: after a move, a name may resolve elsewhere.
func (t *Tunnel) NetworkChanged(ctx context.Context) error {
	if err := t.device.BindUpdate(); err != nil {
		return fmt.Errorf("WireGuard could not move to the new network: %w", err)
	}
	return t.Reresolve(ctx)
}

// Reresolve looks up the endpoints given as names again, and points each peer whose name now
// resolves elsewhere at its new address. Peers given by address are left alone.
func (t *Tunnel) Reresolve(ctx context.Context) error {
	endpoints, err := resolveEndpoints(ctx, net.DefaultResolver, t.config.Peers)
	if err != nil {
		return err
	}
	if err := checkEndpointsOutside(t.config.Peers, endpoints); err != nil {
		return err
	}
	status, err := t.Status()
	if err != nil {
		return err
	}
	if update := endpointUpdates(t.config.Peers, endpoints, status); update != "" {
		return t.device.IpcSet(update)
	}
	return nil
}

// Close takes the tunnel down: the interface and its routes go with the device.
func (t *Tunnel) Close() error {
	t.device.Close()
	return nil
}

func configure(iface string, mtu int, c *conf.Config) error {
	var commands [][]string
	for _, address := range c.Interface.Addresses {
		if address.Addr().Is4() {
			commands = append(commands, []string{"/sbin/ifconfig", iface, "inet", address.String(), address.Addr().String(), "alias"})
		} else {
			commands = append(commands, []string{"/sbin/ifconfig", iface, "inet6", address.String(), "alias"})
		}
	}
	commands = append(commands, []string{"/sbin/ifconfig", iface, "mtu", strconv.Itoa(mtu), "up"})
	for _, route := range routes(c) {
		family := "-inet"
		if route.Addr().Is6() {
			family = "-inet6"
		}
		commands = append(commands, []string{"/sbin/route", "-q", "-n", "add", family, route.String(), "-interface", iface})
	}

	for _, args := range commands {
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
		}
	}
	// /sbin/route exits 0 even when the kernel refuses a route, as when the local network already
	// routes the same network: read the table back, so traffic never goes out in the clear while
	// the tunnel looks up.
	table, err := adroutes.All()
	if err != nil {
		return fmt.Errorf("adit could not read the routing table back: %w", err)
	}
	if missing := adroutes.Missing(table, iface, routes(c)); len(missing) > 0 {
		return fmt.Errorf("the route to %s did not go in, probably because another interface already routes it; that traffic would not use the tunnel", missing[0])
	}
	return nil
}

// routes is every peer's AllowedIPs, as networks, each once.
func routes(c *conf.Config) []netip.Prefix {
	var routes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, peer := range c.Peers {
		for _, allowed := range peer.AllowedIPs {
			if route := allowed.Masked(); !seen[route] {
				seen[route] = true
				routes = append(routes, route)
			}
		}
	}
	return routes
}

// deviceLogger passes wireguard-go's errors on; its verbose lines are dropped. Some errors come once
// per packet (a send that fails while the network is away), so each kind is logged at most once a
// minute, with a count of the ones left out: the log is root's and must not fill the disk.
func deviceLogger(log *slog.Logger, iface string) *device.Logger {
	log = log.With("interface", iface)
	limit := &rateLimit{every: time.Minute, now: time.Now, last: map[string]time.Time{}, held: map[string]int{}}
	return &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			if ok, skipped := limit.allow(format); ok {
				if skipped > 0 {
					log.Warn(fmt.Sprintf(format, args...), "similar_lines_not_logged", skipped)
				} else {
					log.Warn(fmt.Sprintf(format, args...))
				}
			}
		},
	}
}
