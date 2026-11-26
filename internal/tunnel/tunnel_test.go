package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/conf"
)

// Throwaway keys made for these tests; they guard nothing.
const (
	privateKeyHex   = "70bcd3de8c725334971d940f20e708d8b4a81b9981cd5ba761b5e94a89efd945"
	peerKeyHex      = "2f8a0d2e28c38b9cc9f203b266fd518f8b662d2ea35411965b05a837f8d80804"
	presharedKeyHex = "24a84d1926d3a6094a7ea3b52a6723da5e32c75dec5359dcd470d3b614be80ee"
)

const file = "[Interface]\n" +
	"PrivateKey = cLzT3oxyUzSXHZQPIOcI2LSoG5mBzVunYbXpSonv2UU=\n" +
	"ListenPort = 51900\n" +
	"Address = 10.99.1.2/24\n" +
	"\n" +
	"[Peer]\n" +
	"PublicKey = L4oNLijDi5zJ8gOyZv1Rj4tmLS6jVBGWWwWoN/jYCAQ=\n" +
	"PresharedKey = JKhNGSbTpglKfqO1Kmcj2l4yx13sU1nc1HDTthS+gO4=\n" +
	"AllowedIPs = 10.99.1.7/24, fd00:99:1::/64\n" +
	"Endpoint = vpn.example.com:51820\n" +
	"PersistentKeepalive = 25\n"

func TestDeviceConfig(t *testing.T) {
	config := parse(t, file)
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820")}

	want := "private_key=" + privateKeyHex + "\n" +
		"listen_port=51900\n" +
		"replace_peers=true\n" +
		"public_key=" + peerKeyHex + "\n" +
		"preshared_key=" + presharedKeyHex + "\n" +
		"endpoint=203.0.113.10:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.99.1.0/24\n" +
		"allowed_ip=fd00:99:1::/64\n"
	if got := deviceConfig(config, endpoints); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestEndpointsResolvePreferringIPv4(t *testing.T) {
	config := parse(t, file)
	r := fakeResolver{"vpn.example.com": {netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("203.0.113.10")}}

	endpoints, err := resolveEndpoints(context.Background(), r, config.Peers)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("203.0.113.10:51820"); endpoints[0] != want {
		t.Errorf("got %v, want %v", endpoints[0], want)
	}
}

func TestEndpointAddressNeedsNoLookup(t *testing.T) {
	config := parse(t, strings.Replace(file, "vpn.example.com", "[2001:db8::10]", 1))
	endpoints, err := resolveEndpoints(context.Background(), fakeResolver{}, config.Peers)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("[2001:db8::10]:51820"); endpoints[0] != want {
		t.Errorf("got %v, want %v", endpoints[0], want)
	}
}

func TestUnresolvableEndpointIsExplained(t *testing.T) {
	config := parse(t, file)
	_, err := resolveEndpoints(context.Background(), fakeResolver{}, config.Peers)
	want := "the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line"
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}

func TestEndpointInsideAllowedIPsIsRefused(t *testing.T) {
	config := parse(t, file)
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("10.99.1.1:51820")}
	err := checkEndpointsOutside(config.Peers, endpoints)
	if err == nil || !strings.Contains(err.Error(), "the Endpoint 10.99.1.1 is inside AllowedIPs 10.99.1.7/24") {
		t.Errorf("got %v", err)
	}

	endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820")}
	if err := checkEndpointsOutside(config.Peers, endpoints); err != nil {
		t.Errorf("an endpoint outside was refused: %v", err)
	}
}

func TestParseStatus(t *testing.T) {
	reported := "private_key=" + privateKeyHex + "\n" +
		"listen_port=51900\n" +
		"public_key=" + peerKeyHex + "\n" +
		"preshared_key=" + presharedKeyHex + "\n" +
		"protocol_version=1\n" +
		"endpoint=203.0.113.10:51820\n" +
		"last_handshake_time_sec=1795000000\n" +
		"last_handshake_time_nsec=500\n" +
		"tx_bytes=1032\n" +
		"rx_bytes=568\n" +
		"persistent_keepalive_interval=25\n" +
		"allowed_ip=10.99.1.0/24\n" +
		"public_key=" + strings.Repeat("ab", 32) + "\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n" +
		"tx_bytes=0\n" +
		"rx_bytes=0\n" +
		"errno=0\n"

	status, err := ParseStatus("utun14", reported)
	if err != nil {
		t.Fatal(err)
	}
	if status.Interface != "utun14" || len(status.Peers) != 2 {
		t.Fatalf("got %+v", status)
	}
	first, second := status.Peers[0], status.Peers[1]
	if first.PublicKey.String() != "L4oNLijDi5zJ8gOyZv1Rj4tmLS6jVBGWWwWoN/jYCAQ=" {
		t.Errorf("first peer key %s", first.PublicKey)
	}
	if !first.LastHandshake.Equal(time.Unix(1795000000, 500)) {
		t.Errorf("first handshake %v", first.LastHandshake)
	}
	if first.Received != 568 || first.Sent != 1032 {
		t.Errorf("first counters received %d, sent %d", first.Received, first.Sent)
	}
	if first.Endpoint != netip.MustParseAddrPort("203.0.113.10:51820") {
		t.Errorf("first endpoint %v", first.Endpoint)
	}
	if !second.LastHandshake.IsZero() {
		t.Errorf("a peer that never handshook reports %v", second.LastHandshake)
	}
}

func TestMalformedStatusNeverQuotesIt(t *testing.T) {
	_, err := ParseStatus("utun14", "private_key="+privateKeyHex+"\npublic_key=nothex\n")
	if err == nil || strings.Contains(err.Error(), privateKeyHex) {
		t.Errorf("got %v", err)
	}
}

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func parse(t *testing.T, text string) *conf.Config {
	t.Helper()
	config, err := conf.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestEndpointUpdatesOnlyForNamesThatMoved(t *testing.T) {
	config := parse(t, file+"\n[Peer]\nPublicKey = n/PmeCXSK3GEu+va0EBeZ7yE8+qsBPU/4Bht41oJzRQ=\nAllowedIPs = 10.99.2.0/24\nEndpoint = 203.0.113.20:51820\n")
	first, second := config.Peers[0].PublicKey, config.Peers[1].PublicKey
	status := Status{Peers: []PeerStatus{
		{PublicKey: first, Endpoint: netip.MustParseAddrPort("203.0.113.10:51820")},
		{PublicKey: second, Endpoint: netip.MustParseAddrPort("203.0.113.20:51820")},
	}}

	same := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820"), netip.MustParseAddrPort("203.0.113.20:51820")}
	if got := endpointUpdates(config.Peers, same, status); got != "" {
		t.Errorf("nothing moved, yet: %q", got)
	}

	moved := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820"), netip.MustParseAddrPort("198.51.100.8:51820")}
	want := "public_key=" + peerKeyHex + "\nupdate_only=true\nendpoint=198.51.100.7:51820\n"
	if got := endpointUpdates(config.Peers, moved, status); got != want {
		t.Errorf("got %q, want %q: the peer given by address must be left alone", got, want)
	}
}
