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
)

const (
	Label = "pro.saulo.adit"
	Group = "adit"

	Binary    = "/Library/PrivilegedHelperTools/" + Label
	Plist     = "/Library/LaunchDaemons/" + Label + ".plist"
	Newsyslog = "/etc/newsyslog.d/" + Label + ".conf"
	Log       = "/var/log/aditd.log"
	Store     = "/var/db/adit"
	StoreDir  = Store + "/tunnels"
	RunDir    = "/var/run/adit"

	TrayLabel = Label + ".tray"
	TrayAgent = "/Library/LaunchAgents/" + TrayLabel + ".plist"
)

// Options say what to install: aditd from Aditd, the menu bar icon from Tray if not empty, and User
// (UID) into the adit group with the icon started in their session now.
type Options struct {
	Aditd string
	Tray  string
	User  string
	UID   int
}

type Installer struct {
	Root  string                                            // prefixed to every path; tests use a scratch directory
	Run   func(name string, args ...string) ([]byte, error) // runs system tools: launchctl, dseditgroup
	Chown func(path string, uid, gid int) error
	Wait  time.Duration // how long to wait for aditd to stop
}

func New() *Installer {
	return &Installer{
		Run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		Chown: os.Chown,
		Wait:  30 * time.Second,
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
		if output, err := i.Run("/usr/sbin/dseditgroup", "-o", "create", "-r", "adit users: may switch tunnels without a password", Group); err != nil {
			return fmt.Errorf("could not create the adit group: %s", clean(output))
		}
		fmt.Fprintln(out, "Created the adit group.")
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

	if output, err := i.Run("/bin/launchctl", "bootstrap", "system", i.path(Plist)); err != nil {
		return fmt.Errorf("launchctl could not start aditd: %s", clean(output))
	}

	if o.Tray == "" {
		return nil
	}
	if err := i.writeRoot(TrayAgent, []byte(trayAgent(o.Tray)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "The menu bar icon starts at every login (%s).\n", TrayAgent)
	if o.UID > 0 {
		// Restart it in this session too, so an upgrade shows at once.
		i.Run("/bin/launchctl", "bootout", fmt.Sprintf("gui/%d/%s", o.UID, TrayLabel))
		if output, err := i.Run("/bin/launchctl", "bootstrap", fmt.Sprintf("gui/%d", o.UID), i.path(TrayAgent)); err != nil {
			fmt.Fprintf(out, "The menu bar icon did not start now (%s); it will at the next login.\n", clean(output))
		}
	}
	return nil
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
	remove(Newsyslog, "log rotation")
	logs, _ := filepath.Glob(i.path(Log) + "*")
	for _, log := range logs {
		remove(strings.TrimPrefix(log, i.Root), "the log")
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
	if i.groupExists() {
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
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ExitTimeOut</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>` + Log + `</string>
  <key>StandardErrorPath</key>
  <string>` + Log + `</string>
</dict>
</plist>
`
}

// trayAgent starts the menu bar icon at every login, and again if it crashes, but not after the
// person quits it.
func trayAgent(tray string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + TrayLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + tray + `</string>
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

// newsyslog rotates aditd's log at 1 MiB, keeping five, compressed.
const newsyslog = "# logfilename        [owner:group]  mode  count  size  when  flags\n" +
	Log + "  root:wheel     644   5      1024  *     J\n"

func clean(output []byte) string {
	if s := strings.TrimSpace(string(output)); s != "" {
		return s
	}
	return "no reason given"
}
