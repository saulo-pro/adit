package conf

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxSize bounds what aditd, running as root, will read: real configurations are a few hundred
// bytes. The other limits keep what one file can make aditd do (resolver files, routes, overlap
// checks) small.
const (
	maxSize       = 64 << 10
	maxDNSServers = 3 // macOS asks no more than three
	maxDNSDomains = 32
	maxPeers      = 64
	maxAllowedIPs = 1024
	maxAddresses  = 16
)

// special are address ranges a tunnel must not take: link-local, multicast and broadcast belong to
// the local network, the rest is never routed anywhere.
var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// reservedPorts are ports other software on a Mac needs for itself: IKE and IPsec NAT traversal,
// L2TP, NTP and mDNS.
var reservedPorts = []uint16{500, 4500, 1701, 123, 5353}

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

// keyLike matches text that may be a key: a WireGuard key is 43 characters of base64 and a final =,
// and a malformed line (a missing =, a colon, two settings run together) can put one where a name
// or an entry is expected.
var keyLike = regexp.MustCompile(`[A-Za-z0-9+/]{32,}`)

// shown quotes text from the file for an error message, escaping control characters, unless it is
// long or may hold a key: then it is left out, since errors reach the terminal and aditd's log.
func shown(s string) string {
	if len(s) > 100 || keyLike.MatchString(s) {
		return "(not shown: it may hold a key)"
	}
	return strconv.Quote(s)
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
		return nil, &Error{Msg: "the file is larger than 64 KiB, far beyond any WireGuard configuration"}
	}
	if !utf8.Valid(data) {
		return nil, &Error{Msg: "the file is not text: it is not valid UTF-8"}
	}
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	if n, ok := controlCharacter(data); ok {
		return nil, lineError(n, "the line holds a control character; a terminal could show it differently from what adit reads, so remove it")
	}

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

// controlCharacter finds the first line holding a character other than tab, CR and LF that a
// terminal would act on or hide: C0 and C1 controls, DEL, and Unicode format characters such as the
// bidirectional overrides.
func controlCharacter(data []byte) (int, bool) {
	line := 1
	for _, r := range string(data) {
		switch {
		case r == '\n':
			line++
		case r == '\t' || r == '\r':
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Cf, r):
			return line, true
		}
	}
	return 0, false
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
		return lineError(n, "%s comes before any section; settings go under [Interface] or [Peer]", shown(key))
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
		return lineError(n, "unknown section %s; a WireGuard configuration has only [Interface] and [Peer]", shown(line))
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
		return "", lineError(n, "unknown setting %s in [%s]", shown(key), p.section)
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

// privateTLDs are the top-level domains set aside for private networks, which a tunnel may take
// whole: .internal (ICANN, 2024) and home.arpa (RFC 8375). Any other top-level domain belongs to the
// internet.
var privateTLDs = []string{"internal", "home.arpa"}

// CheckDomain says whether a tunnel may resolve the names under domain: a host name, not a whole
// public top-level domain, and not mDNS's .local.
func CheckDomain(domain string) error {
	if !validHostname(domain) {
		return fmt.Errorf("%s is not a domain name", shown(domain))
	}
	folded := strings.TrimSuffix(strings.ToLower(domain), ".")
	switch {
	case slices.Contains(privateTLDs, folded):
	case !strings.Contains(folded, "."):
		return fmt.Errorf("the DNS domain %s is a whole top-level domain; a tunnel may resolve names under a domain of its own, such as corp.example, or the private .internal", shown(domain))
	case folded == "local" || strings.HasSuffix(folded, ".local"):
		return fmt.Errorf("the DNS domain %s is for the local network's own names (mDNS); a tunnel cannot resolve it", shown(domain))
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
			if !slices.Contains(i.DNS, addr) {
				i.DNS = append(i.DNS, addr)
			}
		} else if validHostname(entry) {
			folded := strings.TrimSuffix(strings.ToLower(entry), ".")
			if err := CheckDomain(entry); err != nil {
				return lineError(n, "%s", err)
			}
			if !slices.ContainsFunc(i.DNSSearch, func(d string) bool { return strings.TrimSuffix(strings.ToLower(d), ".") == folded }) {
				i.DNSSearch = append(i.DNSSearch, entry)
			}
		} else {
			return lineError(n, "DNS entry %s is neither an IP address nor a domain name", shown(entry))
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
	i := &p.config.Interface
	switch {
	case len(i.DNS) > maxDNSServers:
		return lineError(p.interfaceLine, "[Interface] lists %d DNS servers; macOS asks at most %d, so list no more", len(i.DNS), maxDNSServers)
	case len(i.DNSSearch) > maxDNSDomains:
		return lineError(p.interfaceLine, "[Interface] lists %d DNS domains; adit takes at most %d", len(i.DNSSearch), maxDNSDomains)
	case len(i.Addresses) > maxAddresses:
		return lineError(p.interfaceLine, "[Interface] lists %d addresses; adit takes at most %d", len(i.Addresses), maxAddresses)
	case len(p.config.Peers) > maxPeers:
		return &Error{Msg: fmt.Sprintf("the file has %d peers; adit takes at most %d", len(p.config.Peers), maxPeers)}
	}
	if slices.Contains(reservedPorts, i.ListenPort) || i.ListenPort > 0 && i.ListenPort < 1024 {
		return lineError(p.interfaceLine, "ListenPort %d belongs to other software or needs a privileged port; leave ListenPort out, and WireGuard picks a free one", i.ListenPort)
	}
	for _, address := range i.Addresses {
		if a := address.Addr(); a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsLoopback() || a.IsUnspecified() {
			return lineError(p.interfaceLine, "the Address %s is link-local, multicast or loopback, which belong to the Mac itself; give the tunnel an address of its own", a)
		}
	}
	allowed := 0
	for n, peer := range p.config.Peers {
		allowed += len(peer.AllowedIPs)
		for _, network := range peer.AllowedIPs {
			network = network.Masked()
			if network.Addr().Is4() && network.Bits() < 8 || network.Addr().Is6() && network.Bits() < 16 {
				continue // a full tunnel, or most of one: refused when it comes up, with its own reason
			}
			for _, s := range special {
				if network.Overlaps(s) {
					return lineError(p.peerLines[n], "AllowedIPs %s takes %s, which belongs to the local network or is never routed; leave it out", network, s)
				}
			}
		}
	}
	if allowed > maxAllowedIPs {
		return &Error{Msg: fmt.Sprintf("the file has %d AllowedIPs entries; adit takes at most %d", allowed, maxAllowedIPs)}
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
				return nil, lineError(n, "%s entry %s is not an IP address with an optional prefix length, such as 10.99.1.2/24", name, shown(entry))
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
		return Endpoint{}, lineError(n, "the Endpoint host %s is neither an IP address nor a host name", shown(host))
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
