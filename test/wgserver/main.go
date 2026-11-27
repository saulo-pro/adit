// Command wgserver is a WireGuard server for adit's tests that needs neither root nor Docker. Its IP
// stack runs inside the process (gVisor's, through wireguard-go's netstack), so it answers ping and
// DNS at its tunnel address without touching the Mac's own network: a packet reaches it only through
// the tunnel.
//
// Its UDP port listens on every interface (wireguard-go's default bind) but answers only the one
// client key it made; nothing else of it is reachable from the network.
//
// It makes fresh keys on every start, or keeps them in -keys DIR across restarts (a server that comes
// back after a reboot), and writes the matching client file to OUT/NAME.conf, ready for adit to
// import, then serves until it is stopped.
//
//	wgserver -name test1 -address 10.99.1.1 -port 51821 -out test/servers/out
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func main() {
	name := flag.String("name", "test1", "the tunnel's name; it answers DNS for NAME.adit.test")
	address := flag.String("address", "10.99.1.1", "the server's address on the tunnel, in a /24")
	port := flag.Int("port", 51821, "the UDP port to listen on")
	out := flag.String("out", ".", "where to write the client file NAME.conf")
	keys := flag.String("keys", "", "a folder to keep the keys in across restarts; fresh keys each start without it")
	flag.Parse()

	server, err := netip.ParseAddr(*address)
	if err != nil || !server.Is4() {
		log.Fatalf("-address %q is not an IPv4 address", *address)
	}
	dev, err := start(*name, server, *port, *out, *keys)
	if err != nil {
		log.Fatal(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	dev.Close()
}

// start brings the server up and writes the client file; closing the device stops it.
func start(name string, server netip.Addr, port int, out, keys string) (*device.Device, error) {
	serverKey, err := key(keys, name+".server.key")
	if err != nil {
		return nil, err
	}
	clientKey, err := key(keys, name+".client.key")
	if err != nil {
		return nil, err
	}
	client := server.As4()
	client[3] = 2

	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{server}, nil, device.DefaultMTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, name+": "))
	config := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(serverKey.Bytes()), port, hex.EncodeToString(clientKey.PublicKey().Bytes()), netip.AddrFrom4(client))
	if err := dev.IpcSet(config); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	domain := name + ".adit.test."
	dns, err := network.ListenUDPAddrPort(netip.AddrPortFrom(server, 53))
	if err != nil {
		dev.Close()
		return nil, err
	}
	go serveDNS(dns, domain, server)

	prefix := netip.PrefixFrom(server, 24).Masked()
	file := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = %s, %s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = 127.0.0.1:%d
PersistentKeepalive = 25
`, base64.StdEncoding.EncodeToString(clientKey.Bytes()), netip.AddrFrom4(client), server, strings.TrimSuffix(domain, "."),
		base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), prefix, port)
	if err := writeFile(filepath.Join(out, name+".conf"), file); err != nil {
		dev.Close()
		return nil, err
	}
	log.Printf("%s answers ping and DNS for *.%s at %s, on 127.0.0.1:%d", name, strings.TrimSuffix(domain, "."), server, port)
	return dev, nil
}

// serveDNS answers A queries for every name under domain with the server's own address; any other
// name does not exist.
func serveDNS(conn *gonet.UDPConn, domain string, server netip.Addr) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if reply, err := answer(buf[:n], domain, server); err == nil {
			conn.WriteTo(reply, from)
		}
	}
}

func answer(query []byte, domain string, server netip.Addr) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(question.Name.String())
	ours := name == domain || strings.HasSuffix(name, "."+domain)

	reply := dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionDesired: header.RecursionDesired}
	if !ours {
		reply.RCode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, reply)
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if ours && question.Type == dnsmessage.TypeA {
		if err := builder.StartAnswers(); err != nil {
			return nil, err
		}
		resource := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
		if err := builder.AResource(resource, dnsmessage.AResource{A: server.As4()}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

// key reads a private key kept in dir, or makes one and keeps it there; with no dir, every key is
// fresh.
func key(dir, name string) (*ecdh.PrivateKey, error) {
	if dir == "" {
		return ecdh.X25519().GenerateKey(rand.Reader)
	}
	path := filepath.Join(dir, name)
	if raw, err := os.ReadFile(path); err == nil {
		return ecdh.X25519().NewPrivateKey(raw)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, k.Bytes(), 0o600)
}

// writeFile puts the client file in place whole, readable only by its owner: it holds a key.
func writeFile(path, content string) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
