package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/saulo-pro/adit/internal/conf"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/saulo-pro/adit/internal/api"
)

func (c *CLI) list(ctx context.Context, out *output, args []string) error {
	if _, err := parse(out, newFlags("list"), args, 0, 0, ""); err != nil {
		return err
	}
	return c.printAll(ctx, out)
}

func (c *CLI) status(ctx context.Context, out *output, args []string) error {
	names, err := parse(out, newFlags("status"), args, 0, 1, "[NAME]")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return c.printAll(ctx, out)
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandStatus, Name: names[0]})
	if err != nil {
		return err
	}
	c.print(out, c.jsonTunnel(*resp.Tunnel), c.describe(*resp.Tunnel))
	return nil
}

func (c *CLI) printAll(ctx context.Context, out *output) error {
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandList})
	if err != nil {
		return err
	}
	c.print(out, map[string]any{"tunnels": c.jsonTunnels(resp.Tunnels), "others": c.jsonTunnels(resp.Others)},
		c.table(resp.Tunnels, resp.Others))
	return nil
}

// up returns once the tunnel has handshaken, or after upWait, so that what it reports is what is
// true: a tunnel with no handshake yet is connecting, not up.
func (c *CLI) up(ctx context.Context, out *output, args []string) error {
	names, err := parse(out, newFlags("up"), args, 1, 1, "NAME")
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandUp, Name: names[0]})
	if err != nil {
		return err
	}
	tunnel := *resp.Tunnel
	deadline := time.After(c.upWait)
	for tunnel.State == "connecting" {
		select {
		case <-deadline:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandStatus, Name: names[0]})
			if err != nil {
				return err
			}
			tunnel = *resp.Tunnel
			continue
		}
		break
	}

	words := fmt.Sprintf("%s is up on %s.\n", tunnel.Name, tunnel.Interface)
	if tunnel.State == "connecting" {
		words = fmt.Sprintf("%s is on %s but has had no handshake yet; adit status %s shows when it does.\n", tunnel.Name, tunnel.Interface, tunnel.Name)
	}
	c.print(out, c.jsonTunnel(tunnel), words+notes(tunnel))
	return nil
}

func (c *CLI) down(ctx context.Context, out *output, args []string) error {
	names, err := parse(out, newFlags("down"), args, 1, 1, "NAME")
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandDown, Name: names[0]})
	if err != nil {
		return err
	}
	c.print(out, c.jsonTunnel(*resp.Tunnel), fmt.Sprintf("%s is down.\n", resp.Tunnel.Name))
	return nil
}

func (c *CLI) killswitch(ctx context.Context, out *output, args []string) error {
	positional, err := parse(out, newFlags("killswitch"), args, 2, 2, "NAME on-drop|always|off")
	if err != nil {
		return err
	}
	mode := positional[1]
	if mode != "on-drop" && mode != "always" && mode != "off" {
		return usageError("usage: sudo adit killswitch NAME on-drop|always|off")
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandKillSwitch, Name: positional[0], Mode: mode})
	if err != nil {
		return err
	}
	name := resp.Tunnel.Name
	words := map[string]string{
		"on-drop": fmt.Sprintf("While %s is coming up or has dropped, the internet is blocked.\n", name),
		"always":  fmt.Sprintf("Whenever %s is not up, even when taken down, the internet is blocked.\n", name),
		"off":     fmt.Sprintf("If %s drops, traffic goes out directly.\n", name),
	}[mode]
	c.print(out, c.jsonTunnel(*resp.Tunnel), words)
	return nil
}

// signinPage is a page macOS itself uses to find a network's sign-in page: a captive network sends
// the browser to its own instead.
const signinPage = "http://captive.apple.com/"

func (c *CLI) signin(ctx context.Context, out *output, args []string) error {
	if _, err := parse(out, newFlags("signin"), args, 0, 0, ""); err != nil {
		return err
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandSignIn})
	if err != nil {
		return err
	}
	open := c.openURL
	if open == nil {
		open = func(url string) error { return exec.Command("/usr/bin/open", url).Run() }
	}
	words := fmt.Sprintf("The kill switch is lifted until %s: sign in to the network in your browser.\n", resp.Until.Local().Format("15:04:05"))
	if err := open(signinPage); err != nil {
		words += fmt.Sprintf("Open %s in your browser to reach the sign-in page.\n", signinPage)
	}
	c.print(out, map[string]any{"until": resp.Until}, words)
	return nil
}

func (c *CLI) autostart(ctx context.Context, out *output, args []string) error {
	positional, err := parse(out, newFlags("autostart"), args, 2, 2, "NAME on|off")
	if err != nil {
		return err
	}
	var on bool
	switch positional[1] {
	case "on":
		on = true
	case "off":
	default:
		return usageError("usage: adit autostart NAME on|off")
	}
	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandAutostart, Name: positional[0], On: &on})
	if err != nil {
		return err
	}
	words := fmt.Sprintf("%s comes up when the Mac starts.\n", resp.Tunnel.Name)
	if !on {
		words = fmt.Sprintf("%s no longer comes up when the Mac starts.\n", resp.Tunnel.Name)
	}
	c.print(out, c.jsonTunnel(*resp.Tunnel), words)
	return nil
}

// importFile reads the file here, as whoever runs adit, and sends its text: aditd never opens a
// path it is given.
func (c *CLI) importFile(ctx context.Context, out *output, args []string) error {
	flags := newFlags("import")
	name := flags.String("name", "", "")
	files, err := parse(out, flags, args, 1, 1, "FILE [--name NAME]")
	if err != nil {
		return err
	}

	var text []byte
	if files[0] == "-" {
		if *name == "" {
			return usageError("import - reads the file from standard input, so it needs --name NAME")
		}
		text, err = io.ReadAll(io.LimitReader(c.Stdin, api.MaxRequest))
	} else {
		text, err = readImport(files[0])
		if *name == "" {
			*name = strings.TrimSuffix(filepath.Base(files[0]), filepath.Ext(files[0]))
		}
	}
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", files[0], errors.Unwrap(err))
	}
	if !utf8.Valid(text) {
		return fmt.Errorf("%s is not text: it is not valid UTF-8", files[0])
	}

	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandImport, Name: *name, File: string(text)})
	if err != nil {
		return err
	}
	var words strings.Builder
	for _, warning := range resp.Warnings {
		fmt.Fprintf(c.Stderr, "adit: %s\n", safeForTerminal(warning))
	}
	fmt.Fprintf(&words, "Imported %s. Bring it up with: adit up %s\n", resp.Tunnel.Name, resp.Tunnel.Name)
	words.WriteString(whatItChanges(text))
	warnings := resp.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	c.print(out, map[string]any{"tunnel": c.jsonTunnel(*resp.Tunnel), "warnings": warnings}, words.String())
	return nil
}

// export writes the tunnel's file, which holds its private key, to a new file readable only by
// the person who ran sudo. It never prints the file: a key on a terminal ends up in scrollback,
// logs and transcripts.
func (c *CLI) export(ctx context.Context, out *output, args []string) error {
	flags := newFlags("export")
	path := flags.String("output", "", "")
	names, err := parse(out, flags, args, 1, 1, "NAME --output FILE")
	if err != nil {
		return err
	}
	switch *path {
	case "":
		return usageError("export needs --output FILE: it writes the file, and never prints it, since it holds the private key")
	case "-", "/dev/stdout":
		return usageError("export never prints the file, since it holds the private key; give --output FILE")
	}

	resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandExport, Name: names[0]})
	if err != nil {
		return err
	}
	if err := c.writePrivate(*path, []byte(resp.File)); err != nil {
		return err
	}
	absolute, _ := filepath.Abs(*path)
	c.print(out, map[string]any{"exported": names[0], "file": absolute},
		fmt.Sprintf("Exported %s to %s, readable only by you.\n", names[0], *path))
	return nil
}

// writePrivate creates path, never through a link and never over an existing file, hands it to the
// person who ran sudo through the open descriptor, and only then writes the key into it: no name is
// looked up again between creating the file and giving it away.
func (c *CLI) writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; adit will not overwrite it", path)
	}
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, errors.Unwrap(err))
	}
	err = c.giveToSudoUser(file)
	if err == nil {
		_, err = file.Write(data)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	return nil
}

// giveToSudoUser hands a file made under sudo to the person who typed sudo, so they can read it.
func (c *CLI) giveToSudoUser(file *os.File) error {
	uid, uidErr := strconv.Atoi(c.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(c.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil || c.euid() != 0 {
		return nil
	}
	return c.chown(file, uid, gid)
}

// readImport reads a configuration file to import: never through a link, only a regular file, and
// no more than aditd would accept. adit runs as root here, so the path must not lead it to read a
// device or another file.
func readImport(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errors.New("not a regular file")}
	}
	if info.Size() > maxImport {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errors.New("too large to be a WireGuard configuration")}
	}
	return io.ReadAll(io.LimitReader(file, maxImport))
}

// maxImport is the most aditd accepts in a configuration file.
const maxImport = 1 << 20

func (c *CLI) remove(ctx context.Context, out *output, args []string) error {
	names, err := parse(out, newFlags("remove"), args, 1, 1, "NAME")
	if err != nil {
		return err
	}
	if _, err := c.Client.Do(ctx, api.Request{Command: api.CommandRemove, Name: names[0]}); err != nil {
		return err
	}
	c.print(out, map[string]any{"removed": names[0]}, fmt.Sprintf("Removed %s.\n", names[0]))
	return nil
}

// version answers even without aditd: knowing which adit is installed helps most when it is not
// working.
func (c *CLI) version(ctx context.Context, out *output, args []string) error {
	if _, err := parse(out, newFlags("version"), args, 0, 0, ""); err != nil {
		return err
	}
	versions := map[string]any{"adit": c.Version, "aditd": nil}
	words := fmt.Sprintf("adit %s\n", c.Version)
	if resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandVersion}); err == nil {
		versions["aditd"] = resp.Version
		words += fmt.Sprintf("aditd %s\n", resp.Version)
		if resp.Version != c.Version {
			// After an upgrade, root keeps running the old aditd until it is installed again.
			words += fmt.Sprintf("aditd is %s but this adit is %s: run sudo adit install\n", resp.Version, c.Version)
		}
	} else {
		words += fmt.Sprintf("aditd: %v\n", err)
	}
	c.print(out, versions, words)
	return nil
}

// jsonTunnel is a tunnel as scripts see it: every key always present, null when it has no value.
type jsonTunnel struct {
	Name                string     `json:"name"`
	State               string     `json:"state"`
	Autostart           bool       `json:"autostart"`
	KillSwitch          *string    `json:"killswitch"` // a full tunnel's; null for a split tunnel
	Blocking            bool       `json:"blocking"`   // its kill switch blocks the internet now
	Interface           *string    `json:"interface"`
	LastHandshake       *time.Time `json:"last_handshake"`
	HandshakeAgeSeconds *int64     `json:"handshake_age_seconds"`
	ReceivedBytes       uint64     `json:"received_bytes"`
	SentBytes           uint64     `json:"sent_bytes"`
	Notes               []string   `json:"notes"`
	Source              string     `json:"source"`    // "adit", "wg-quick" or "WireGuard app"
	ReadOnly            bool       `json:"read_only"` // another program's: adit shows it and leaves it alone
}

func (c *CLI) jsonTunnels(tunnels []api.Tunnel) []jsonTunnel {
	result := make([]jsonTunnel, len(tunnels))
	for n, tunnel := range tunnels {
		result[n] = c.jsonTunnel(tunnel)
	}
	return result
}

func (c *CLI) jsonTunnel(t api.Tunnel) jsonTunnel {
	j := jsonTunnel{Name: t.Name, State: t.State, Autostart: t.Autostart, LastHandshake: t.LastHandshake,
		ReceivedBytes: t.ReceivedBytes, SentBytes: t.SentBytes}
	if t.KillSwitch != "" {
		j.KillSwitch = &t.KillSwitch
	}
	j.Blocking = t.Blocking
	j.Notes = t.Notes
	if j.Notes == nil {
		j.Notes = []string{}
	}
	j.Source, j.ReadOnly = t.Source, t.ReadOnly
	if j.Source == "" {
		j.Source = "adit"
	}
	if t.Interface != "" {
		j.Interface = &t.Interface
	}
	if t.LastHandshake != nil {
		age := int64(c.Now().Sub(*t.LastHandshake).Seconds())
		j.HandshakeAgeSeconds = &age
	}
	return j
}

// table lists adit's tunnels, then other software's, which adit shows but does not change.
func (c *CLI) table(tunnels, others []api.Tunnel) string {
	if len(tunnels) == 0 && len(others) == 0 {
		return "No tunnels yet. Add one with: sudo adit import FILE\n"
	}
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tINTERFACE\tHANDSHAKE\tRECEIVED\tSENT\tAUTOSTART\tBY")
	for _, t := range tunnels {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\tadit\n", t.Name, t.State, orDash(t.Interface), c.age(t),
			c.bytes(t, t.ReceivedBytes), c.bytes(t, t.SentBytes), onOff(t.Autostart))
	}
	for _, t := range others {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t-\t%s (read-only)\n", t.Name, t.State, orDash(t.Interface), c.age(t),
			c.bytes(t, t.ReceivedBytes), c.bytes(t, t.SentBytes), t.Source)
	}
	w.Flush()
	return b.String()
}

func (c *CLI) describe(t api.Tunnel) string {
	if t.Source == "WireGuard app" {
		return fmt.Sprintf("%s is %s on %s, run by the WireGuard app; adit shows it but does not change it.\n",
			t.Name, t.State, orDash(t.Interface)) + notes(t)
	}
	if t.ReadOnly {
		return fmt.Sprintf("%s is run by %s; adit shows it but does not change it.\n", t.Name, t.Source) + c.details(t)
	}
	if t.State == "down" {
		return fmt.Sprintf("%s is down. Autostart is %s.\n", t.Name, onOff(t.Autostart)) + notes(t)
	}
	return c.details(t)
}

// details are a running tunnel's state, handshake, counters and notes.
func (c *CLI) details(t api.Tunnel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is %s on %s.\n", t.Name, t.State, orDash(t.Interface))
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  last handshake\t%s\n", c.age(t))
	fmt.Fprintf(w, "  received\t%s\n", humanBytes(t.ReceivedBytes))
	fmt.Fprintf(w, "  sent\t%s\n", humanBytes(t.SentBytes))
	if !t.ReadOnly {
		fmt.Fprintf(w, "  autostart\t%s\n", onOff(t.Autostart))
	}
	if t.KillSwitch != "" {
		fmt.Fprintf(w, "  kill switch\t%s\n", t.KillSwitch)
	}
	w.Flush()
	if t.State == "idle" {
		b.WriteString("  Idle: no handshake for over 3 minutes; WireGuard sends nothing when nothing needs sending.\n")
	}
	return b.String() + notes(t)
}

func (c *CLI) age(t api.Tunnel) string {
	switch {
	case t.Source == "WireGuard app":
		return "-"
	case t.LastHandshake != nil:
		return humanAge(c.Now().Sub(*t.LastHandshake)) + " ago"
	case t.State == "down":
		return "-"
	default:
		return "never"
	}
}

func (c *CLI) bytes(t api.Tunnel, n uint64) string {
	if t.State == "down" || t.Source == "WireGuard app" {
		return "-"
	}
	return humanBytes(n)
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", max(0, int(d.Seconds())))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func humanBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value, unit := float64(n)/1024, "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if value < 1024 {
			break
		}
		value, unit = value/1024, next
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// notes are the things aditd says a person should know about a tunnel, one line each.
func notes(t api.Tunnel) string {
	var b strings.Builder
	for _, note := range t.Notes {
		fmt.Fprintf(&b, "  Note: %s.\n", note)
	}
	return b.String()
}

// whatItChanges says what a tunnel will change on the Mac once up, from its file: the administrator
// should know before any member of the adit group brings it up.
func whatItChanges(text []byte) string {
	c, err := conf.Parse(text)
	if err != nil {
		return ""
	}
	var routes, endpoints []string
	for _, peer := range c.Peers {
		for _, network := range peer.AllowedIPs {
			routes = append(routes, network.Masked().String())
		}
		if !peer.Endpoint.IsZero() {
			endpoints = append(endpoints, net.JoinHostPort(peer.Endpoint.Host, strconv.Itoa(int(peer.Endpoint.Port))))
		}
	}
	full := slices.Contains(routes, "0.0.0.0/0")
	i := c.Interface
	servers := make([]string, len(i.DNS))
	for n, server := range i.DNS {
		servers[n] = server.String()
	}
	var b strings.Builder
	switch {
	case full:
		fmt.Fprintf(&b, "When up, it routes everything (%s) but the local network and adit's other tunnels\n", strings.Join(routes, ", "))
		if len(servers) > 0 {
			fmt.Fprintf(&b, "and sends every name but the other tunnels' domains to %s\n", strings.Join(servers, ", "))
		} else {
			b.WriteString("but it needs a DNS line to come up: without one, names would be looked up outside it\n")
		}
	case len(routes) > 0:
		fmt.Fprintf(&b, "When up, it routes: %s\n", strings.Join(routes, ", "))
	}
	if !full && len(i.DNS) > 0 && len(i.DNSSearch) > 0 {
		fmt.Fprintf(&b, "and sends names under %s to %s\n", strings.Join(i.DNSSearch, ", "), strings.Join(servers, ", "))
	}
	if len(endpoints) > 0 {
		fmt.Fprintf(&b, "Its server: %s\n", strings.Join(endpoints, ", "))
	}
	return b.String()
}
