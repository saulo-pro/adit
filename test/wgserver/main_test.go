package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A client peer with its own in-process network stack reaches the server through the tunnel: no
// root, no Docker, nothing on the Mac's own network.
func TestServerAnswersPingAndDNSThroughTheTunnel(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	server := netip.MustParseAddr("10.99.7.1")
	dev, err := start("probe", server, port, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	settings := readClientFile(t, filepath.Join(dir, "probe.conf"))
	if settings["DNS"] != "10.99.7.1, probe.adit.test" || settings["AllowedIPs"] != "10.99.7.0/24" {
		t.Fatalf("client file %v", settings)
	}
	client := clientPeer(t, settings, port)

	t.Run("ping", func(t *testing.T) {
		ping, err := client.DialPingAddr(netip.Addr{}, server)
		if err != nil {
			t.Fatal(err)
		}
		defer ping.Close()
		request, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("adit")}}).Marshal(nil)
		ping.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := ping.Write(request); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, err := ping.Read(buf)
		if err != nil {
			t.Fatalf("no echo reply: %v", err)
		}
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || reply.Type != ipv4.ICMPTypeEchoReply {
			t.Errorf("got %+v, %v", reply, err)
		}
	})

	t.Run("dns", func(t *testing.T) {
		for name, want := range map[string]dnsmessage.RCode{"server.probe.adit.test.": dnsmessage.RCodeSuccess, "elsewhere.example.": dnsmessage.RCodeNameError} {
			udp, err := client.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
			if err != nil {
				t.Fatal(err)
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9, RecursionDesired: true})
			builder.StartQuestions()
			builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
			query, _ := builder.Finish()
			udp.SetDeadline(time.Now().Add(5 * time.Second))
			udp.Write(query)
			buf := make([]byte, 1500)
			n, err := udp.Read(buf)
			udp.Close()
			if err != nil {
				t.Fatalf("%s: no answer: %v", name, err)
			}
			var reply dnsmessage.Message
			if err := reply.Unpack(buf[:n]); err != nil {
				t.Fatal(err)
			}
			if reply.RCode != want {
				t.Errorf("%s: rcode %v, want %v", name, reply.RCode, want)
			}
			if want == dnsmessage.RCodeSuccess {
				if len(reply.Answers) != 1 || reply.Answers[0].Body.(*dnsmessage.AResource).A != server.As4() {
					t.Errorf("%s: answers %+v", name, reply.Answers)
				}
			}
		}
	})
}

func freePort(t *testing.T) int {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func readClientFile(t *testing.T, path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	settings := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if key, value, ok := strings.Cut(scanner.Text(), " = "); ok {
			settings[key] = value
		}
	}
	return settings
}

func clientPeer(t *testing.T, settings map[string]string, port int) *netstack.Net {
	address, _ := strings.CutSuffix(settings["Address"], "/24")
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, device.DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(dev.Close)
	private, _ := base64.StdEncoding.DecodeString(settings["PrivateKey"])
	public, _ := base64.StdEncoding.DecodeString(settings["PublicKey"])
	config := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(private), hex.EncodeToString(public), port, settings["AllowedIPs"])
	if err := dev.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return network
}

func TestKeysKeptAcrossRestarts(t *testing.T) {
	dir, keys := t.TempDir(), t.TempDir()
	server := netip.MustParseAddr("10.99.8.1")
	first, err := start("kept", server, freePort(t), dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	firstFile, _ := os.ReadFile(filepath.Join(dir, "kept.conf"))
	first.Close()

	second, err := start("kept", server, freePort(t), dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondFile, _ := os.ReadFile(filepath.Join(dir, "kept.conf"))
	for _, setting := range []string{"PrivateKey", "PublicKey"} {
		a, b := readSetting(string(firstFile), setting), readSetting(string(secondFile), setting)
		if a == "" || a != b {
			t.Errorf("%s changed across a restart", setting)
		}
	}
}

func readSetting(file, name string) string {
	for line := range strings.Lines(file) {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), name+" = "); ok {
			return value
		}
	}
	return ""
}
