package conf

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Throwaway keys made for these tests; they guard nothing.
const (
	privateKey   = "cLzT3oxyUzSXHZQPIOcI2LSoG5mBzVunYbXpSonv2UU="
	peerKey      = "L4oNLijDi5zJ8gOyZv1Rj4tmLS6jVBGWWwWoN/jYCAQ="
	presharedKey = "JKhNGSbTpglKfqO1Kmcj2l4yx13sU1nc1HDTthS+gO4="
)

const untidy = "\uFEFF# exported by hand\r\n" +
	"[interface]\r\n" +
	"privatekey=" + privateKey + " # the key\r\n" +
	"address = 10.99.1.2/24\r\n" +
	"ADDRESS = fd00:99:1::2/64\r\n" +
	"\r\n" +
	"dns = corp.example,10.99.1.1\r\n" +
	"   mtu   =   1420   \r\n" +
	"\r\n" +
	"# first peer\r\n" +
	"[ Peer ]\r\n" +
	"publickey = " + peerKey + "\r\n" +
	"allowedips = 10.99.1.0/24\r\n" +
	"allowedips = 10.99.3.7\r\n" +
	"endpoint = vpn.example.com:51820\r\n" +
	"persistentkeepalive = off\r\n"

const untidyCanonical = "[Interface]\n" +
	"PrivateKey = " + privateKey + "\n" +
	"Address = 10.99.1.2/24, fd00:99:1::2/64\n" +
	"DNS = 10.99.1.1, corp.example\n" +
	"MTU = 1420\n" +
	"\n" +
	"[Peer]\n" +
	"PublicKey = " + peerKey + "\n" +
	"AllowedIPs = 10.99.1.0/24, 10.99.3.7/32\n" +
	"Endpoint = vpn.example.com:51820\n"

func TestCanonicalFilesRoundTripByteForByte(t *testing.T) {
	for _, name := range []string{"official-export.conf", "every-setting.conf"} {
		t.Run(name, func(t *testing.T) {
			data := readTestdata(t, name)
			if got := Format(mustParse(t, data)); !bytes.Equal(got, data) {
				t.Errorf("Format(Parse(file)) differs from the file:\n%s", got)
			}
		})
	}
}

func TestUntidyFileFormatsCanonically(t *testing.T) {
	if got := string(Format(mustParse(t, []byte(untidy)))); got != untidyCanonical {
		t.Errorf("got:\n%s\nwant:\n%s", got, untidyCanonical)
	}
}

func TestFormattedConfigParsesBackUnchanged(t *testing.T) {
	inputs := map[string][]byte{
		"official-export.conf": readTestdata(t, "official-export.conf"),
		"every-setting.conf":   readTestdata(t, "every-setting.conf"),
		"untidy":               []byte(untidy),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			config := mustParse(t, data)
			if again := mustParse(t, Format(config)); !reflect.DeepEqual(again, config) {
				t.Errorf("parsing the formatted file gave %+v, want %+v", again, config)
			}
		})
	}
}

func TestParseEverySetting(t *testing.T) {
	config := mustParse(t, readTestdata(t, "every-setting.conf"))
	i := config.Interface

	if i.PrivateKey.Reveal() != decodeKey(t, privateKey) {
		t.Error("PrivateKey was not read")
	}
	assertEqual(t, "ListenPort", i.ListenPort, uint16(51820))
	assertEqual(t, "FwMark", i.FwMark, uint32(51820))
	assertEqual(t, "Addresses", i.Addresses, []netip.Prefix{netip.MustParsePrefix("10.99.1.2/24"), netip.MustParsePrefix("fd00:99:1::2/64")})
	assertEqual(t, "DNS", i.DNS, []netip.Addr{netip.MustParseAddr("10.99.1.1"), netip.MustParseAddr("fd00:99:1::1")})
	assertEqual(t, "DNSSearch", i.DNSSearch, []string{"corp.example", "lab.example"})
	assertEqual(t, "MTU", i.MTU, 1420)
	assertEqual(t, "Table", i.Table, "off")
	assertEqual(t, "SaveConfig", i.SaveConfig, true)
	assertEqual(t, "PostUp", i.PostUp, []string{"echo post-up one", "echo post-up two"})

	if len(config.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(config.Peers))
	}
	first, second := config.Peers[0], config.Peers[1]
	assertEqual(t, "first PublicKey", first.PublicKey.String(), peerKey)
	if first.PresharedKey.Reveal() != decodeKey(t, presharedKey) {
		t.Error("PresharedKey was not read")
	}
	assertEqual(t, "first Endpoint", first.Endpoint, Endpoint{Host: "203.0.113.10", Port: 51820})
	assertEqual(t, "first PersistentKeepalive", first.PersistentKeepalive, uint16(25))
	assertEqual(t, "second Endpoint", second.Endpoint, Endpoint{Host: "2001:db8::10", Port: 51821})
	assertEqual(t, "second PersistentKeepalive", second.PersistentKeepalive, uint16(0))
	if !second.PresharedKey.IsZero() {
		t.Error("second peer has a PresharedKey it was never given")
	}
}

func TestHooksAreNamedForWarnings(t *testing.T) {
	everySetting := mustParse(t, readTestdata(t, "every-setting.conf"))
	assertEqual(t, "hooks", everySetting.Interface.Hooks(), []string{"PreUp", "PostUp", "PreDown", "PostDown"})

	official := mustParse(t, readTestdata(t, "official-export.conf"))
	if hooks := official.Interface.Hooks(); hooks != nil {
		t.Errorf("a file without hooks reports %v", hooks)
	}
}

func TestSecretsNeverPrinted(t *testing.T) {
	config := mustParse(t, readTestdata(t, "every-setting.conf"))
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{"JSON": string(encoded)}
	type holder struct{ config Config } // unexported: fmt cannot call Format through it
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%p", "%d", "%!"} {
		outputs[verb] = fmt.Sprintf(verb, config)
		outputs[verb+" of the value"] = fmt.Sprintf(verb, *config)
		outputs[verb+" of an unexported holder"] = fmt.Sprintf(verb, holder{*config})
		outputs[verb+" of the secret"] = fmt.Sprintf(verb, config.Interface.PrivateKey)
	}

	for _, secret := range []string{privateKey, presharedKey} {
		raw := decodeKey(t, secret)
		forms := []string{secret, hex.EncodeToString(raw[:]), strings.ToUpper(hex.EncodeToString(raw[:]))}
		for how, output := range outputs {
			for _, form := range forms {
				if strings.Contains(output, form) {
					t.Errorf("%s output shows a secret key: %s", how, output)
				}
			}
		}
	}
	if !strings.Contains(outputs["%v"], "(secret)") {
		t.Errorf("%%v output does not mark the secret: %s", outputs["%v"])
	}
}

func TestErrorsNeverQuoteSecrets(t *testing.T) {
	almostKey := privateKey[:40] + "!!!="
	for _, input := range []string{
		"[Interface]\nPrivateKey = " + almostKey + "\n",
		"[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + peerKey + "\nPresharedKey = " + almostKey + "\n",
	} {
		_, err := Parse([]byte(input))
		if err == nil {
			t.Fatalf("a broken key was accepted:\n%s", input)
		}
		if strings.Contains(err.Error(), almostKey[:40]) {
			t.Errorf("the error quotes the key: %v", err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	head := "[Interface]\nPrivateKey = " + privateKey + "\n"
	peer := "[Peer]\nPublicKey = " + peerKey + "\n"

	tests := []struct {
		name  string
		input string
		line  int
		says  string
	}{
		{"empty file", "", 0, "the file has no [Interface] section"},
		{"only a peer", peer, 0, "the file has no [Interface] section"},
		{"no private key", "[Interface]\nAddress = 10.99.1.2/24\n", 1, "[Interface] has no PrivateKey"},
		{"setting before any section", "Address = 10.99.1.2/24\n", 1, `"Address" comes before any section`},
		{"no equals sign", head + "Address 10.99.1.2/24\n", 3, "Key = value"},
		{"unknown section", head + "[Peers]\n", 3, `unknown section "[Peers]"`},
		{"control character", head + "DNS = 10.99.1.1\x1b[2K\n", 3, "control character"},
		{"bidirectional override", head + "DNS = 10.99.1.1 \u202e\n", 3, "control character"},
		{"unclosed header", head + "[Peer\n", 3, "must end with ]"},
		{"second interface", head + "[Interface]\n", 3, "a second [Interface] section; the first is on line 1"},
		{"unknown setting", head + "Jc = 4\n", 3, `unknown setting "Jc" in [Interface]`},
		{"peer setting under interface", head + "Endpoint = vpn.example.com:51820\n", 3, "Endpoint belongs in [Peer], not [Interface]"},
		{"interface setting under peer", head + peer + "mtu = 1420\n", 5, "MTU belongs in [Interface], not [Peer]"},
		{"setting twice", head + "MTU = 1420\nmtu = 1400\n", 4, "MTU appears twice in this section; it is already set on line 3"},
		{"private key twice", head + "PrivateKey = " + privateKey + "\n", 3, "PrivateKey appears twice"},
		{"no value", head + "DNS =\n", 3, "DNS has no value"},
		{"bad private key", "[Interface]\nPrivateKey = not-a-key\n", 2, "PrivateKey is not a WireGuard key"},
		{"short public key", head + "[Peer]\nPublicKey = AAAA\n", 4, "PublicKey is not a WireGuard key"},
		{"listen port too big", head + "ListenPort = 70000\n", 3, "ListenPort must be a port number"},
		{"fwmark not a number", head + "FwMark = mark\n", 3, "FwMark must be off or a number"},
		{"mtu too small", head + "MTU = 100\n", 3, "MTU must be a number from 576 to 65535"},
		{"save config not a boolean", head + "SaveConfig = yes\n", 3, "SaveConfig must be true or false"},
		{"bad address", head + "Address = 10.99.1.300/24\n", 3, `Address entry "10.99.1.300/24" is not an IP address`},
		{"two commas", head + "Address = 10.99.1.2/24,,10.99.1.3\n", 3, "Address has an empty entry"},
		{"trailing comma", head + peer + "AllowedIPs = 10.99.1.0/24,\n", 5, "AllowedIPs has an empty entry"},
		{"bad dns entry", head + "DNS = 10.99.1.1, -bad.example\n", 3, `DNS entry "-bad.example" is neither an IP address nor a domain name`},
		{"endpoint without port", head + peer + "Endpoint = vpn.example.com\n", 5, "Endpoint must be host:port"},
		{"endpoint port zero", head + peer + "Endpoint = vpn.example.com:0\n", 5, "the Endpoint port must be a number from 1 to 65535"},
		{"endpoint ipv6 without brackets", head + peer + "Endpoint = 2001:db8::1:51820\n", 5, "Endpoint must be host:port"},
		{"endpoint bad host", head + peer + "Endpoint = bad host:51820\n", 5, `the Endpoint host "bad host" is neither`},
		{"keepalive too big", head + peer + "PersistentKeepalive = 70000\n", 5, "PersistentKeepalive must be off or a number of seconds"},
		{"peer without public key", head + "[Peer]\nAllowedIPs = 10.99.1.0/24\n", 3, "this [Peer] has no PublicKey"},
		{"same peer twice", head + peer + peer, 5, "this [Peer] has the same PublicKey as the one on line 3"},
		{"not text", "[Interface]\n\xff\n", 0, "the file is not text"},
		{"too large", strings.Repeat("#", maxSize+1), 0, "larger than 1 MiB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.input))
			var confErr *Error
			if !errors.As(err, &confErr) {
				t.Fatalf("got %v, want a *conf.Error", err)
			}
			if confErr.Line != test.line {
				t.Errorf("error on line %d, want line %d: %v", confErr.Line, test.line, err)
			}
			if !strings.Contains(confErr.Msg, test.says) {
				t.Errorf("error %q does not say %q", confErr.Msg, test.says)
			}
			if strings.Count(strings.TrimSuffix(confErr.Msg, "."), ". ") > 0 {
				t.Errorf("error %q is more than one sentence", confErr.Msg)
			}
		})
	}
}

func TestAddressWithoutPrefixLengthIsOneHost(t *testing.T) {
	config := mustParse(t, []byte("[Interface]\nPrivateKey = "+privateKey+"\nAddress = 10.99.1.2, fd00::2\n"))
	assertEqual(t, "Addresses", config.Interface.Addresses, []netip.Prefix{netip.MustParsePrefix("10.99.1.2/32"), netip.MustParsePrefix("fd00::2/128")})
}

func TestOffMeansAbsent(t *testing.T) {
	config := mustParse(t, []byte("[Interface]\nPrivateKey = "+privateKey+"\nFwMark = off\n[Peer]\nPublicKey = "+peerKey+"\nPersistentKeepalive = OFF\n"))
	assertEqual(t, "FwMark", config.Interface.FwMark, uint32(0))
	assertEqual(t, "PersistentKeepalive", config.Peers[0].PersistentKeepalive, uint16(0))
}

func TestHexFwMark(t *testing.T) {
	config := mustParse(t, []byte("[Interface]\nPrivateKey = "+privateKey+"\nFwMark = 0xca6c\n"))
	assertEqual(t, "FwMark", config.Interface.FwMark, uint32(51820))
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustParse(t *testing.T, data []byte) *Config {
	t.Helper()
	config, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return config
}

func decodeKey(t *testing.T, s string) [keyLen]byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != keyLen {
		t.Fatalf("bad test key %q", s)
	}
	return [keyLen]byte(raw)
}

func assertEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// TestErrorsNeverQuoteKeys: a malformed key line (no =, a colon, a bare key, a key run onto another
// setting) must not put the key into the error, which reaches the terminal and aditd's log.
func TestErrorsNeverQuoteKeys(t *testing.T) {
	for _, line := range []string{
		"PrivateKey " + privateKey,
		"PrivateKey: " + privateKey,
		privateKey,
		"Address = 10.99.1.2/24 PrivateKey = " + privateKey,
		"DNS = " + privateKey,
		"[" + privateKey + "]",
	} {
		for _, input := range []string{"[Interface]\n" + line + "\n", line + "\n", "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPresharedKey " + presharedKey + "\n"} {
			_, err := Parse([]byte(input))
			if err == nil {
				continue
			}
			for _, key := range []string{privateKey, presharedKey, privateKey[:43], presharedKey[:43]} {
				if strings.Contains(err.Error(), key) {
					t.Errorf("%q: the error quotes a key: %v", line, err)
				}
			}
		}
	}
}
