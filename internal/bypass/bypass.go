// Package bypass keeps the routes a full tunnel needs beside its own: a host route for every adit
// tunnel's endpoint through the Mac's real gateway, so the packets that carry the tunnels never go
// into the full tunnel itself, and, when the full tunnel carries no IPv6, two routes that send all
// IPv6 nowhere, so it cannot leave around the tunnel.
//
// These routes are on the network interface or on lo0, so they outlive the tunnel's own interface:
// adit records each one it adds in a state file and removes only those. The file lives in /var/run,
// which macOS empties at boot, when the routes are gone too.
package bypass

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/saulo-pro/adit/internal/routes"
)

const DefaultStateFile = "/var/run/adit/routes.json"

// Plan is what the full tunnel needs right now. The zero Plan needs nothing: every route adit added
// goes.
type Plan struct {
	Endpoints []netip.Addr // addresses to reach outside the full tunnel
	BlockIPv6 bool         // send all IPv6 nowhere: the full tunnel carries IPv4 only
}

// Routes adds and removes the routes of a Plan.
type Routes struct {
	StateFile string
	Table     func() ([]routes.Route, error)       // the routing table: routes.All in aditd
	Run       func(args ...string) ([]byte, error) // runs /sbin/route with args
}

// entry is one route adit adds: a host route to an endpoint, through a gateway or an interface, or
// to nowhere (Blackhole) when the Mac has no route out for its family.
type entry struct {
	Destination netip.Prefix `json:"destination"`
	Gateway     netip.Addr   `json:"gateway,omitzero"`
	Interface   string       `json:"interface,omitempty"`
	Blackhole   bool         `json:"blackhole,omitempty"`
}

var ipv6Halves = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}

// Apply makes the routing table hold exactly the routes p needs, of the ones adit manages: it adds
// what is missing (again, if the network took it away), moves an endpoint's route to a new gateway,
// and removes what p no longer needs. It reads the table back, since /sbin/route exits 0 even when
// the kernel refuses a route.
func (r *Routes) Apply(p Plan) error {
	table, err := r.Table()
	if err != nil {
		return fmt.Errorf("adit could not read the routing table: %w", err)
	}
	want := wanted(table, p)
	ours, err := r.load()
	if err != nil {
		return err
	}

	var errs []error
	var kept []entry
	for _, e := range ours {
		if slices.Contains(want, e) && present(table, e) {
			kept = append(kept, e)
			continue
		}
		if present(table, e) {
			if err := r.run(deleteArgs(e)); err != nil {
				errs = append(errs, err)
				kept = append(kept, e) // still there: try again next time
				continue
			}
			table = slices.DeleteFunc(table, func(r routes.Route) bool { return r.Prefix == e.Destination })
		}
	}
	for _, e := range want {
		if slices.Contains(kept, e) {
			continue
		}
		if taken(table, e) {
			// Someone else routes this destination already: theirs wins, and adit does not own it.
			continue
		}
		if err := r.run(addArgs(e)); err != nil {
			errs = append(errs, err)
			continue
		}
		kept = append(kept, e)
	}
	if err := r.save(kept); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	after, err := r.Table()
	if err != nil {
		return fmt.Errorf("adit could not read the routing table back: %w", err)
	}
	for _, e := range kept {
		if !present(after, e) {
			return fmt.Errorf("the route to %s did not go in", e.Destination)
		}
	}
	return nil
}

// Clear removes every route adit added.
func (r *Routes) Clear() error {
	return r.Apply(Plan{})
}

// wanted are the routes p needs, given the table. Endpoints on the local network need none: the
// network's own route is more specific than the full tunnel's.
func wanted(table []routes.Route, p Plan) []entry {
	var want []entry
	for _, addr := range p.Endpoints {
		addr = addr.Unmap()
		if !addr.IsValid() || routes.Local(table, addr) {
			continue
		}
		e := entry{Destination: netip.PrefixFrom(addr, addr.BitLen())}
		if gw, ok := routes.Default(table, addr.Is4()); ok {
			e.Gateway, e.Interface = gw.Gateway, gw.Interface
			if gw.Gateway.IsValid() {
				e.Interface = ""
			}
		} else {
			// No way out for this family: the endpoint goes nowhere rather than round inside the
			// full tunnel. The route is moved once the network is back.
			e.Blackhole = true
		}
		if !slices.Contains(want, e) {
			want = append(want, e)
		}
	}
	if p.BlockIPv6 {
		for _, half := range ipv6Halves {
			want = append(want, entry{Destination: half, Blackhole: true})
		}
	}
	return want
}

// present says whether the table holds e as adit adds it.
func present(table []routes.Route, e entry) bool {
	for _, r := range table {
		if r.Prefix != e.Destination {
			continue
		}
		switch {
		case e.Blackhole:
			if r.Interface == "lo0" {
				return true
			}
		case e.Gateway.IsValid():
			if r.Gateway.WithZone("") == e.Gateway.WithZone("") {
				return true
			}
		case r.Interface == e.Interface && !r.Gateway.IsValid():
			return true
		}
	}
	return false
}

// taken says whether another route for exactly e's destination is in the table.
func taken(table []routes.Route, e entry) bool {
	for _, r := range table {
		if r.Prefix == e.Destination {
			return true
		}
	}
	return false
}

func family(e entry) string {
	if e.Destination.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

func target(e entry) []string {
	if e.Destination.IsSingleIP() {
		return []string{"-host", e.Destination.Addr().String()}
	}
	return []string{"-net", e.Destination.String()}
}

func addArgs(e entry) []string {
	args := append([]string{"-q", "-n", "add", family(e)}, target(e)...)
	switch {
	case e.Blackhole && e.Destination.Addr().Is4():
		return append(args, "127.0.0.1", "-blackhole")
	case e.Blackhole:
		return append(args, "::1", "-blackhole")
	case e.Gateway.IsValid():
		return append(args, e.Gateway.String())
	default:
		return append(args, "-interface", e.Interface)
	}
}

func deleteArgs(e entry) []string {
	return append([]string{"-q", "-n", "delete", family(e)}, target(e)...)
}

func (r *Routes) run(args []string) error {
	if output, err := r.Run(args...); err != nil {
		return fmt.Errorf("/sbin/route %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func (r *Routes) load() ([]entry, error) {
	content, err := os.ReadFile(r.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []entry
	if err := json.Unmarshal(content, &entries); err != nil {
		// Unreadable: adit cannot tell its routes, and leaves every route alone.
		return nil, nil
	}
	return entries, nil
}

func (r *Routes) save(entries []entry) error {
	if len(entries) == 0 {
		if err := os.Remove(r.StateFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	content, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.StateFile), 0o755); err != nil {
		return err
	}
	tmp := r.StateFile + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.StateFile)
}
