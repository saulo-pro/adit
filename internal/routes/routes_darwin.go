package routes

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// Tunnels reads the kernel's routing table and returns the routes on tunnel interfaces, skipping
// the ones every tunnel has. Reading it needs no privilege.
//
// Interface-scoped routes are skipped too: they carry only traffic already bound to their
// interface. macOS gives every utun a scoped default route, which is not a full tunnel: the
// WireGuard app's tunnel has one while public traffic still leaves through Wi-Fi.
func Tunnels() ([]Route, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}

	names := map[int]string{}
	var routes []Route
	for _, message := range messages {
		m, ok := message.(*route.RouteMessage)
		if !ok || m.Flags&syscall.RTF_UP == 0 || m.Flags&syscall.RTF_IFSCOPE != 0 || len(m.Addrs) <= syscall.RTAX_DST {
			continue
		}
		name, known := names[m.Index]
		if !known {
			if iface, err := net.InterfaceByIndex(m.Index); err == nil {
				name = iface.Name
			}
			names[m.Index] = name
		}
		if !TunnelInterface(name) {
			continue
		}
		prefix, ok := destination(m)
		if !ok || ignored(prefix) {
			continue
		}
		routes = append(routes, Route{Prefix: prefix, Interface: name})
	}
	return routes, nil
}

func destination(m *route.RouteMessage) (netip.Prefix, bool) {
	var mask route.Addr
	if len(m.Addrs) > syscall.RTAX_NETMASK {
		mask = m.Addrs[syscall.RTAX_NETMASK]
	}
	host := m.Flags&syscall.RTF_HOST != 0

	switch dst := m.Addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		bits := 32
		if !host {
			bits = 0
			if m, ok := mask.(*route.Inet4Addr); ok {
				bits = maskBits(m.IP[:])
			}
		}
		return netip.PrefixFrom(netip.AddrFrom4(dst.IP), bits).Masked(), true
	case *route.Inet6Addr:
		bits := 128
		if !host {
			bits = 0
			if m, ok := mask.(*route.Inet6Addr); ok {
				bits = maskBits(m.IP[:])
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(dst.IP), bits).Masked(), true
	}
	return netip.Prefix{}, false
}
