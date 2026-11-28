//go:build darwin

// Package install puts aditd on a Mac and takes it off again: a root-owned copy of the binary, a
// LaunchDaemon that starts it at boot, the adit group whose members may use it, and rotation for
// its log.
//
// The copy is the point: Homebrew's bin belongs to the user, so a LaunchDaemon running aditd from
// there would let any of the user's programs replace what root runs.
package install

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/dns"
	"github.com/saulo-pro/adit/internal/firewall"
)

const (
	Label = "pro.saulo.adit"
	Group = "adit"

	Binary = "/Library/PrivilegedHelperTools/" + Label
	// TrayBinary is the menu bar icon's own root-owned copy: the LaunchAgent starts it in every
	// account's session, so it must not be a file one account can change.
	TrayBinary = "/Library/PrivilegedHelperTools/" + Label + ".tray"
	Plist      = "/Library/LaunchDaemons/" + Label + ".plist"
	Newsyslog  = "/etc/newsyslog.d/" + Label + ".conf"
	Log        = "/var/log/aditd.log"
	PidFile    = "/var/run/aditd.pid"
	Store      = "/var/db/adit"
	StoreDir   = Store + "/tunnels"
	RunDir     = "/var/run/adit"

	TrayLabel = Label + ".tray"
	TrayAgent = "/Library/LaunchAgents/" + TrayLabel + ".plist"
)

// Options say what to install: aditd from Aditd, the menu bar icon from Tray if not empty, and User
// (UID) into the adit group with the icon started in their session now. ReuseGroup accepts a group
// named adit that adit did not create.
type Options struct {
	Aditd      string
	Tray       string
	User       string
	UID        int
	ReuseGroup bool
}

// groupRealName marks the adit group as adit's own: uninstall deletes only a group carrying it.
const groupRealName = "adit users: may switch tunnels without a password"

type Installer struct {
	Root  string                                            // prefixed to every path; tests use a scratch directory
	Run   func(name string, args ...string) ([]byte, error) // runs system tools: launchctl, dseditgroup
	Chown func(path string, uid, gid int) error
	Wait  time.Duration // how long to wait for aditd to stop
	// TrayWait is how long to keep trying to start the menu bar icon in the person's session: macOS
	// refuses it for a few seconds while it registers the changed login item.
	TrayWait time.Duration
}

func New() *Installer {
	return &Installer{
		Run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		Chown:    os.Chown,
		Wait:     30 * time.Second,
		TrayWait: 20 * time.Second,
	}
}

func (i *Installer) path(p string) string {
	return filepath.Join(i.Root, p)
}

// Install copies aditd from source into place and starts it, replacing an aditd already running:
// an upgrade takes adit's tunnels down, and aditd brings the autostart ones back up. When user is
// not empty, it joins the adit group. It reports what it did, one line each, to out.
func (i *Installer) Install(o Options, out io.Writer) error {
	if !i.groupExists() {
		args := []string{"-o", "create", "-r", groupRealName}
		if gid := i.freeGid(); gid != "" {
			args = append(args, "-i", gid)
		}
		if output, err := i.Run("/usr/sbin/dseditgroup", append(args, Group)...); err != nil {
			return fmt.Errorf("could not create the adit group: %s", clean(output))
		}
		fmt.Fprintln(out, "Created the adit group.")
	} else if !i.groupIsAdits() {
		// Its members would be able to switch every tunnel: say who they are, and go on only when
		// asked to.
		members := i.groupMembers()
		if !o.ReuseGroup {
			return fmt.Errorf("a group named adit already exists and adit did not create it (members: %s); remove it, or run install again with --reuse-group to let its members switch tunnels", members)
		}
		fmt.Fprintf(out, "Using the existing adit group; its members can switch tunnels: %s.\n", members)
	}
	if o.User != "" {
		if err := i.Allow(o.User); err != nil {
			return err
		}
		fmt.Fprintf(out, "Added %s to the adit group.\n", o.User)
	}

	if i.stop() {
		fmt.Fprintln(out, "Stopped the aditd that was running.")
	}
	binary, err := os.ReadFile(o.Aditd)
	if err != nil {
		return fmt.Errorf("could not read aditd at %s: %w", o.Aditd, errors.Unwrap(err))
	}
	var tray []byte
	if o.Tray != "" {
		if tray, err = os.ReadFile(o.Tray); err != nil {
			return fmt.Errorf("could not read adit-tray at %s: %w", o.Tray, errors.Unwrap(err))
		}
	}
	for _, file := range []struct {
		path    string
		content []byte
		mode    fs.FileMode
	}{
		{Binary, binary, 0o755},
		{Plist, []byte(plist()), 0o644},
		{Newsyslog, []byte(newsyslog), 0o644},
	} {
		if err := i.writeRoot(file.path, file.content, file.mode); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Installed aditd at %s, and %s.\n", Binary, Plist)
	// Logs an earlier version left are readable by everyone; aditd keeps the current one 0600.
	if logs, _ := filepath.Glob(i.path(Log) + "*"); len(logs) > 0 {
		for _, log := range logs {
			os.Chmod(log, 0o600)
		}
	}

	if output, err := i.Run("/bin/launchctl", "bootstrap", "system", i.path(Plist)); err != nil {
		return fmt.Errorf("launchctl could not start aditd: %s", clean(output))
	}

	if o.Tray == "" {
		return nil
	}
	if err := i.writeRoot(TrayBinary, tray, 0o755); err != nil {
		return err
	}
	if err := i.writeRoot(TrayAgent, []byte(trayAgent()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "The menu bar icon starts at every login (%s).\n", TrayAgent)
	if o.UID > 0 {
		if err := i.startTray(o.UID); err != nil {
			fmt.Fprintf(out, "The menu bar icon did not start now (%s); it will at the next login, or now with: launchctl bootstrap gui/%d %s\n", err, o.UID, TrayAgent)
		}
	}
	return nil
}

// startTray restarts the menu bar icon in the person's session, so an upgrade shows at once. The old
// one must be gone before the new one is loaded, and macOS refuses the load (an input/output error)
// while it registers the changed login item and tells the person it may run in the background: keep
// trying for TrayWait.
func (i *Installer) startTray(uid int) error {
	domain, service := fmt.Sprintf("gui/%d", uid), fmt.Sprintf("gui/%d/%s", uid, TrayLabel)
	i.Run("/bin/launchctl", "bootout", service)
	deadline := time.Now().Add(i.TrayWait)
	for {
		if _, err := i.Run("/bin/launchctl", "print", service); err != nil {
			break // gone
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for {
		output, err := i.Run("/bin/launchctl", "bootstrap", domain, i.path(TrayAgent))
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New(clean(output))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Uninstall stops aditd, which takes its tunnels down, and removes everything Install made, the
// tunnels and their keys too unless keepTunnels. It reports what it removed to out.
func (i *Installer) Uninstall(keepTunnels bool, uid int, out io.Writer) error {
	if uid > 0 {
		i.Run("/bin/launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, TrayLabel))
	}
	if i.stop() {
		fmt.Fprintln(out, "Stopped aditd; its tunnels are down.")
	}
	var errs []error
	remove := func(path, what string) {
		if _, err := os.Lstat(i.path(path)); err != nil {
			return
		}
		if err := os.RemoveAll(i.path(path)); err != nil {
			errs = append(errs, err)
			return
		}
		fmt.Fprintf(out, "Removed %s (%s).\n", what, path)
	}
	remove(Plist, "the LaunchDaemon")
	remove(TrayAgent, "the menu bar icon's LaunchAgent")
	remove(Binary, "aditd")
	remove(TrayBinary, "the menu bar icon")
	remove(Newsyslog, "log rotation")
	logs, _ := filepath.Glob(i.path(Log) + "*")
	for _, log := range logs {
		remove(strings.TrimPrefix(log, i.Root), "the log")
	}
	// A stopped aditd leaves its kill switch blocking, on purpose: uninstalling turns it off.
	pf := &firewall.Firewall{Anchor: firewall.DefaultAnchor, StateFile: i.path(firewall.DefaultStateFile),
		Run: func(_ string, args ...string) ([]byte, error) { return i.Run("/sbin/pfctl", args...) }}
	_, statErr := os.Stat(pf.StateFile)
	if err := pf.Release(); err != nil {
		errs = append(errs, err)
	} else if statErr == nil {
		fmt.Fprintln(out, "Turned the kill switch off.")
	}
	remove(RunDir, "the socket's folder")
	if err := (&dns.Resolvers{Dir: i.path(dns.DefaultDir)}).ClearAll(); err != nil {
		errs = append(errs, err)
	}
	if keepTunnels {
		fmt.Fprintf(out, "Kept the tunnels and their keys in %s.\n", Store)
	} else {
		remove(Store, "every tunnel and its keys")
	}
	switch {
	case !i.groupExists():
	case !i.groupIsAdits():
		fmt.Fprintln(out, "Kept the adit group: adit did not create it.")
	default:
		if output, err := i.Run("/usr/sbin/dseditgroup", "-o", "delete", Group); err != nil {
			errs = append(errs, fmt.Errorf("could not delete the adit group: %s", clean(output)))
		} else {
			fmt.Fprintln(out, "Deleted the adit group.")
		}
	}
	return errors.Join(errs...)
}

// Allow adds user to the adit group, and Disallow takes them out.
func (i *Installer) Allow(user string) error {
	return i.membership("-a", user)
}

func (i *Installer) Disallow(user string) error {
	return i.membership("-d", user)
}

func (i *Installer) membership(flag, user string) error {
	if !i.groupExists() {
		return errors.New("the adit group does not exist; install adit first with sudo adit install")
	}
	if output, err := i.Run("/usr/sbin/dseditgroup", "-o", "edit", flag, user, "-t", "user", Group); err != nil {
		return fmt.Errorf("could not change the adit group: %s", clean(output))
	}
	// The directory cache would otherwise keep the old membership for a while.
	i.Run("/usr/bin/dscacheutil", "-flushcache")
	return nil
}

// Installed says whether aditd's LaunchDaemon is in place.
func (i *Installer) Installed() bool {
	_, err := os.Stat(i.path(Plist))
	return err == nil
}

func (i *Installer) groupExists() bool {
	_, err := i.Run("/usr/bin/dscl", ".", "-read", "/Groups/"+Group, "PrimaryGroupID")
	return err == nil
}

// groupIsAdits says whether the adit group is the one adit created, by the name it gave it.
func (i *Installer) groupIsAdits() bool {
	output, err := i.Run("/usr/bin/dscl", ".", "-read", "/Groups/"+Group, "RealName")
	return err == nil && strings.Contains(string(output), groupRealName)
}

// groupMembers lists who the adit group admits, directly and through nested groups.
func (i *Installer) groupMembers() string {
	output, err := i.Run("/usr/bin/dscl", ".", "-read", "/Groups/"+Group, "GroupMembership", "NestedGroups")
	members := strings.Join(strings.Fields(strings.NewReplacer("GroupMembership:", "", "NestedGroups:", "nested groups").Replace(string(output))), " ")
	if err != nil || members == "" {
		return "none"
	}
	return members
}

// freeGid picks a group id below 500, where macOS keeps groups out of sight, that no group uses in
// any directory the Mac searches: a gid shared with another group would let its members in.
func (i *Installer) freeGid() string {
	output, err := i.Run("/usr/bin/dscl", "/Search", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return ""
	}
	used := map[string]bool{}
	for line := range strings.Lines(string(output)) {
		if fields := strings.Fields(line); len(fields) == 2 {
			used[fields[1]] = true
		}
	}
	for gid := 499; gid >= 400; gid-- {
		if id := fmt.Sprint(gid); !used[id] {
			return id
		}
	}
	return ""
}

// stop takes aditd out of launchd, which stops it, and waits until it has let go of its socket:
// it takes its tunnels down on the way out. It says whether one was running.
func (i *Installer) stop() bool {
	if _, err := i.Run("/bin/launchctl", "bootout", "system/"+Label); err != nil {
		return false
	}
	socket := i.path(api.DefaultSocket)
	for deadline := time.Now().Add(i.Wait); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(socket); errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	return true
}

// writeRoot puts a file in place atomically, owned by root:wheel.
func (i *Installer) writeRoot(path string, content []byte, mode fs.FileMode) error {
	path = i.path(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".adit-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), mode); err != nil {
		return err
	}
	if err := i.Chown(temp.Name(), 0, 0); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func plist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + Label + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + Binary + `</string>
    <string>-store</string>
    <string>` + StoreDir + `</string>
    <string>-log</string>
    <string>` + Log + `</string>
    <string>-pidfile</string>
    <string>` + PidFile + `</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ExitTimeOut</key>
  <integer>30</integer>
</dict>
</plist>
`
}

// trayAgent starts the menu bar icon at every login, and again if it crashes, but not after the
// person quits it.
func trayAgent() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + TrayLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + TrayBinary + `</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
`
}

// newsyslog rotates aditd's log at 1 MiB, keeping five, compressed and readable by root alone, and
// sends aditd SIGHUP so it writes to the new file.
const newsyslog = "# logfilename        [owner:group]  mode  count  size  when  flags  [pid_file]\n" +
	Log + "  root:wheel     600   5      1024  *     J      " + PidFile + "\n"

func clean(output []byte) string {
	if s := strings.TrimSpace(string(output)); s != "" {
		return s
	}
	return "no reason given"
}
