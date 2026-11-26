// Package tunnel brings one WireGuard tunnel up and down: a wireguard-go device on its own
// interface, with the addresses and routes of its configuration.
//
// The text sent to the device holds the private key, so it is never logged or put in an error.
package tunnel

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/saulo-pro/adit/internal/conf"
)

// Status is what the device itself reports: the honest part of a tunnel's state.
type Status struct {
	Interface string
	Peers     []PeerStatus
}

type PeerStatus struct {
	PublicKey     conf.Key
	Endpoint      netip.AddrPort
	LastHandshake time.Time // zero until the first handshake
	Received      uint64    // bytes
	Sent          uint64
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveEndpoints turns each peer's endpoint into an address, since the device takes only
// addresses. IPv4 is preferred: it works on more networks.
func resolveEndpoints(ctx context.Context, r resolver, peers []conf.Peer) ([]netip.AddrPort, error) {
	endpoints := make([]netip.AddrPort, len(peers))
	for n, peer := range peers {
		if peer.Endpoint.IsZero() {
			continue
		}
		addr, err := netip.ParseAddr(peer.Endpoint.Host)
		if err != nil {
			addrs, err := r.LookupNetIP(ctx, "ip", peer.Endpoint.Host)
			if err != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("the Endpoint %s does not resolve; check the network or the Endpoint line", peer.Endpoint.Host)
			}
			addr = preferIPv4(addrs)
		}
		endpoints[n] = netip.AddrPortFrom(addr.Unmap(), peer.Endpoint.Port)
	}
	return endpoints, nil
}

func preferIPv4(addrs []netip.Addr) netip.Addr {
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			return addr
		}
	}
	return addrs[0]
}

// checkEndpointsOutside refuses a tunnel whose own routes would carry the packets meant for its
// endpoint: they would go round inside the tunnel and never arrive.
func checkEndpointsOutside(peers []conf.Peer, endpoints []netip.AddrPort) error {
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() {
			continue
		}
		for _, peer := range peers {
			for _, allowed := range peer.AllowedIPs {
				if allowed.Masked().Contains(endpoint.Addr()) {
					return fmt.Errorf("the Endpoint %s is inside AllowedIPs %s, so packets to it would be sent into the tunnel itself", endpoint.Addr(), allowed)
				}
			}
		}
	}
	return nil
}

// deviceConfig writes c in WireGuard's own configuration protocol, which takes keys in hex. Its
// result holds the private key.
func deviceConfig(c *conf.Config, endpoints []netip.AddrPort) string {
	var b strings.Builder
	privateKey := c.Interface.PrivateKey.Reveal()
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	if c.Interface.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.Interface.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for n, peer := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		if !peer.PresharedKey.IsZero() {
			presharedKey := peer.PresharedKey.Reveal()
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(presharedKey[:]))
		}
		if endpoints[n].IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", endpoints[n])
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, allowed := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", allowed.Masked())
		}
	}
	return b.String()
}

// ParseStatus reads a device's answer to a get request, keeping only what status shows: its
// private_key line is skipped.
func ParseStatus(iface, text string) (Status, error) {
	status := Status{Interface: iface}
	var peer *PeerStatus
	var seconds, nanoseconds int64

	finishPeer := func() {
		if peer != nil && (seconds != 0 || nanoseconds != 0) {
			peer.LastHandshake = time.Unix(seconds, nanoseconds)
		}
		seconds, nanoseconds = 0, 0
	}

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		if key == "public_key" {
			finishPeer()
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != len(conf.Key{}) {
				return Status{}, fmt.Errorf("the device reported a malformed peer key")
			}
			status.Peers = append(status.Peers, PeerStatus{PublicKey: conf.Key(raw)})
			peer = &status.Peers[len(status.Peers)-1]
			continue
		}
		if peer == nil {
			continue
		}

		var err error
		switch key {
		case "endpoint":
			peer.Endpoint, err = netip.ParseAddrPort(value)
		case "last_handshake_time_sec":
			seconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			peer.Received, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			peer.Sent, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return Status{}, fmt.Errorf("the device reported a malformed %s", key)
		}
	}
	finishPeer()
	return status, scanner.Err()
}

// endpointUpdates writes, in the device's protocol, the peers whose endpoint name now resolves to
// another address than the device uses. Peers given by address, or not yet reported, are left out.
func endpointUpdates(peers []conf.Peer, resolved []netip.AddrPort, status Status) string {
	current := map[conf.Key]netip.AddrPort{}
	for _, peer := range status.Peers {
		current[peer.PublicKey] = peer.Endpoint
	}
	var b strings.Builder
	for n, peer := range peers {
		if _, err := netip.ParseAddr(peer.Endpoint.Host); err == nil || !resolved[n].IsValid() {
			continue
		}
		if now, known := current[peer.PublicKey]; known && now != resolved[n] {
			fmt.Fprintf(&b, "public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(peer.PublicKey[:]), resolved[n])
		}
	}
	return b.String()
}
