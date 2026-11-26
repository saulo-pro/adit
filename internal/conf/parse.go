package conf

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxSize bounds what aditd, running as root, will read: real configurations are a few hundred
// bytes.
const maxSize = 1 << 20

// An Error is a problem in a configuration file, said in one sentence a person can act on. It never
// quotes a key.
type Error struct {
	Line int // 1-based; 0 when the problem is the file as a whole
	Msg  string
}

func (e *Error) Error() string {
	if e.Line == 0 {
		return e.Msg
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

func lineError(line int, format string, args ...any) *Error {
	return &Error{Line: line, Msg: fmt.Sprintf(format, args...)}
}

var (
	interfaceSettings = canonicalNames("PrivateKey", "ListenPort", "FwMark", "Address", "DNS", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig")
	peerSettings      = canonicalNames("PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive")
	repeatable        = []string{"Address", "DNS", "AllowedIPs", "PreUp", "PostUp", "PreDown", "PostDown"}
)

// canonicalNames maps each setting's lower-case spelling to its canonical one: names are
// case-insensitive, as in the official apps.
func canonicalNames(names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, name := range names {
		m[strings.ToLower(name)] = name
	}
	return m
}

// Parse reads a configuration file. It returns the first problem as an *Error.
func Parse(data []byte) (*Config, error) {
	if len(data) > maxSize {
		return nil, &Error{Msg: "the file is larger than 1 MiB, far beyond any WireGuard configuration"}
	}
	if !utf8.Valid(data) {
		return nil, &Error{Msg: "the file is not text: it is not valid UTF-8"}
	}
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))

	p := parser{config: &Config{}}
	for n, line := range strings.Split(string(data), "\n") {
		if err := p.line(n+1, line); err != nil {
			return nil, err
		}
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return p.config, nil
}

type parser struct {
	config        *Config
	section       string // "", "Interface" or "Peer"
	interfaceLine int
	peerLines     []int
	seen          map[string]int // setting name → line, within the current section
}

func (p *parser) line(n int, line string) error {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	switch {
	case line == "":
		return nil
	case strings.HasPrefix(line, "["):
		return p.header(n, line)
	}

	key, value, found := strings.Cut(line, "=")
	if !found {
		return lineError(n, "expected a setting written as Key = value")
	}
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	switch p.section {
	case "Interface":
		return p.interfaceSetting(n, key, value)
	case "Peer":
		return p.peerSetting(n, key, value)
	default:
		return lineError(n, "%q comes before any section; settings go under [Interface] or [Peer]", key)
	}
}

func (p *parser) header(n int, line string) error {
	if !strings.HasSuffix(line, "]") {
		return lineError(n, "a section header must end with ]")
	}
	switch strings.ToLower(strings.TrimSpace(line[1 : len(line)-1])) {
	case "interface":
		if p.interfaceLine != 0 {
			return lineError(n, "a second [Interface] section; the first is on line %d", p.interfaceLine)
		}
		p.section, p.interfaceLine = "Interface", n
	case "peer":
		p.section = "Peer"
		p.peerLines = append(p.peerLines, n)
		p.config.Peers = append(p.config.Peers, Peer{})
	default:
		return lineError(n, "unknown section %s; a WireGuard configuration has only [Interface] and [Peer]", line)
	}
	p.seen = map[string]int{}
	return nil
}

// setting resolves key to its canonical name in the current section and checks it may appear here.
func (p *parser) setting(n int, key, value string, own, other map[string]string, otherSection string) (string, error) {
	name, known := own[strings.ToLower(key)]
	if !known {
		if name, elsewhere := other[strings.ToLower(key)]; elsewhere {
			return "", lineError(n, "%s belongs in [%s], not [%s]", name, otherSection, p.section)
		}
		return "", lineError(n, "unknown setting %q in [%s]", key, p.section)
	}
	if first, twice := p.seen[name]; twice && !slices.Contains(repeatable, name) {
		return "", lineError(n, "%s appears twice in this section; it is already set on line %d", name, first)
	}
	p.seen[name] = n
	if value == "" {
		return "", lineError(n, "%s has no value", name)
	}
	return name, nil
}

func (p *parser) interfaceSetting(n int, key, value string) error {
	name, err := p.setting(n, key, value, interfaceSettings, peerSettings, "Peer")
	if err != nil {
		return err
	}

	i := &p.config.Interface
	switch name {
	case "PrivateKey":
		if i.PrivateKey, err = parseSecret(value); err != nil {
			return lineError(n, "PrivateKey is not a WireGuard key, which is 44 characters of base64 ending in =")
		}
	case "ListenPort":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return lineError(n, "ListenPort must be a port number from 0 to 65535")
		}
		i.ListenPort = uint16(port)
	case "FwMark":
		if strings.EqualFold(value, "off") {
			return nil
		}
		mark, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return lineError(n, "FwMark must be off or a number")
		}
		i.FwMark = uint32(mark)
	case "Address":
		addresses, err := parsePrefixes(n, name, value)
		if err != nil {
			return err
		}
		i.Addresses = append(i.Addresses, addresses...)
	case "DNS":
		return p.dns(n, value)
	case "MTU":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			return lineError(n, "MTU must be a number from 576 to 65535")
		}
		i.MTU = mtu
	case "Table":
		// off, auto, or a routing table's number or name (from /etc/iproute2/rt_tables), so
		// anything goes: only Linux reads it, and only as an argument to ip.
		i.Table = value
	case "SaveConfig":
		save, err := strconv.ParseBool(value)
		if err != nil {
			return lineError(n, "SaveConfig must be true or false")
		}
		i.SaveConfig = save
	case "PreUp":
		i.PreUp = append(i.PreUp, value)
	case "PostUp":
		i.PostUp = append(i.PostUp, value)
	case "PreDown":
		i.PreDown = append(i.PreDown, value)
	case "PostDown":
		i.PostDown = append(i.PostDown, value)
	}
	return nil
}

// dns sorts each entry into a server address or a search domain, as wg-quick does.
func (p *parser) dns(n int, value string) error {
	entries, err := splitList(n, "DNS", value)
	if err != nil {
		return err
	}
	i := &p.config.Interface
	for _, entry := range entries {
		if addr, err := netip.ParseAddr(entry); err == nil && addr.Zone() == "" {
			i.DNS = append(i.DNS, addr)
		} else if validHostname(entry) {
			i.DNSSearch = append(i.DNSSearch, entry)
		} else {
			return lineError(n, "DNS entry %q is neither an IP address nor a domain name", entry)
		}
	}
	return nil
}

func (p *parser) peerSetting(n int, key, value string) error {
	name, err := p.setting(n, key, value, peerSettings, interfaceSettings, "Interface")
	if err != nil {
		return err
	}

	peer := &p.config.Peers[len(p.config.Peers)-1]
	switch name {
	case "PublicKey":
		if peer.PublicKey, err = ParseKey(value); err != nil {
			return lineError(n, "PublicKey is not a WireGuard key, which is 44 characters of base64 ending in =")
		}
	case "PresharedKey":
		if peer.PresharedKey, err = parseSecret(value); err != nil {
			return lineError(n, "PresharedKey is not a WireGuard key, which is 44 characters of base64 ending in =")
		}
	case "AllowedIPs":
		allowed, err := parsePrefixes(n, name, value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, allowed...)
	case "Endpoint":
		if peer.Endpoint, err = parseEndpoint(n, value); err != nil {
			return err
		}
	case "PersistentKeepalive":
		if strings.EqualFold(value, "off") {
			return nil
		}
		seconds, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return lineError(n, "PersistentKeepalive must be off or a number of seconds from 1 to 65535")
		}
		peer.PersistentKeepalive = uint16(seconds)
	}
	return nil
}

func (p *parser) finish() error {
	if p.interfaceLine == 0 {
		return &Error{Msg: "the file has no [Interface] section"}
	}
	if p.config.Interface.PrivateKey.IsZero() {
		return lineError(p.interfaceLine, "[Interface] has no PrivateKey")
	}
	firstLine := map[Key]int{}
	for n, peer := range p.config.Peers {
		line := p.peerLines[n]
		if peer.PublicKey.IsZero() {
			return lineError(line, "this [Peer] has no PublicKey")
		}
		if first, ok := firstLine[peer.PublicKey]; ok {
			return lineError(line, "this [Peer] has the same PublicKey as the one on line %d", first)
		}
		firstLine[peer.PublicKey] = line
	}
	return nil
}

// splitList splits a comma-separated value, refusing empty entries.
func splitList(n int, name, value string) ([]string, error) {
	entries := strings.Split(value, ",")
	for e, entry := range entries {
		entries[e] = strings.TrimSpace(entry)
		if entries[e] == "" {
			return nil, lineError(n, "%s has an empty entry: two commas in a row, or one at the end", name)
		}
	}
	return entries, nil
}

// parsePrefixes reads addresses with optional prefix lengths. An address on its own means just
// that address (/32 or /128), as in wg-quick.
func parsePrefixes(n int, name, value string) ([]netip.Prefix, error) {
	entries, err := splitList(n, name, value)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, len(entries))
	for e, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil || addr.Zone() != "" {
				return nil, lineError(n, "%s entry %q is not an IP address with an optional prefix length, such as 10.99.1.2/24", name, entry)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes[e] = prefix
	}
	return prefixes, nil
}

func parseEndpoint(n int, value string) (Endpoint, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return Endpoint{}, lineError(n, "Endpoint must be host:port, such as vpn.example.com:51820 or [2001:db8::1]:51820")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, lineError(n, "the Endpoint port must be a number from 1 to 65535")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return Endpoint{}, lineError(n, "the Endpoint address must not name an interface zone (%%)")
		}
	} else if !validHostname(host) {
		return Endpoint{}, lineError(n, "the Endpoint host %q is neither an IP address nor a host name", host)
	}
	return Endpoint{Host: host, Port: uint16(port)}, nil
}

// validHostname accepts DNS names: dot-separated labels of letters, digits, hyphens and
// underscores, with an optional final dot.
func validHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}
