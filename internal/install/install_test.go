//go:build darwin

package install

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saulo-pro/adit/internal/dns"
)

func TestInstallPutsEverythingInPlaceAndStartsAditd(t *testing.T) {
	i, sys := newInstaller(t)
	source := filepath.Join(t.TempDir(), "aditd")
	os.WriteFile(source, []byte("the aditd binary"), 0o700)

	var out strings.Builder
	if err := i.Install(Options{Aditd: source, Tray: "/opt/homebrew/bin/adit-tray", User: "dwight", UID: 501}, &out); err != nil {
		t.Fatal(err)
	}

	if lint, err := exec.Command("/usr/bin/plutil", "-lint", i.path(TrayAgent)).CombinedOutput(); err != nil {
		t.Errorf("the tray's LaunchAgent is not a valid property list: %s", lint)
	}
	if agent, _ := os.ReadFile(i.path(TrayAgent)); !strings.Contains(string(agent), "<string>/opt/homebrew/bin/adit-tray</string>") {
		t.Errorf("the LaunchAgent does not start the tray: %s", agent)
	}
	if binary, _ := os.ReadFile(i.path(Binary)); string(binary) != "the aditd binary" {
		t.Errorf("installed binary holds %q", binary)
	}
	assertMode(t, i.path(Binary), 0o755)
	assertMode(t, i.path(Plist), 0o644)
	if lint, err := exec.Command("/usr/bin/plutil", "-lint", i.path(Plist)).CombinedOutput(); err != nil {
		t.Errorf("the LaunchDaemon is not a valid property list: %s", lint)
	}
	plist, _ := os.ReadFile(i.path(Plist))
	for _, want := range []string{"<string>" + Label + "</string>", "<string>" + Binary + "</string>", "<key>RunAtLoad</key>", "<key>KeepAlive</key>"} {
		if !strings.Contains(string(plist), want) {
			t.Errorf("the LaunchDaemon lacks %s", want)
		}
	}
	if _, err := os.Stat(i.path(Newsyslog)); err != nil {
		t.Error("no log rotation")
	}

	sys.expect(t,
		"/usr/sbin/dseditgroup -o create -r adit users: may switch tunnels without a password adit",
		"/usr/sbin/dseditgroup -o edit -a dwight -t user adit",
		"/bin/launchctl bootstrap system "+i.path(Plist),
		"/bin/launchctl bootstrap gui/501 "+i.path(TrayAgent),
	)
	if !strings.Contains(out.String(), "Created the adit group.\nAdded dwight to the adit group.\n") {
		t.Errorf("reported:\n%s", out.String())
	}
}

func TestInstallAgainStopsTheOldAditdFirst(t *testing.T) {
	i, sys := newInstaller(t)
	sys.group, sys.loaded = true, true
	source := filepath.Join(t.TempDir(), "aditd")
	os.WriteFile(source, []byte("v2"), 0o700)

	var out strings.Builder
	if err := i.Install(Options{Aditd: source}, &out); err != nil {
		t.Fatal(err)
	}
	bootout := slices.Index(sys.ran, "/bin/launchctl bootout system/"+Label)
	bootstrap := slices.Index(sys.ran, "/bin/launchctl bootstrap system "+i.path(Plist))
	if bootout < 0 || bootstrap < bootout {
		t.Errorf("commands: %q", sys.ran)
	}
	if strings.Contains(strings.Join(sys.ran, "\n"), "create") {
		t.Error("the group was created again")
	}
	if !strings.Contains(out.String(), "Stopped the aditd that was running.") {
		t.Errorf("reported:\n%s", out.String())
	}
}

func TestUninstallRemovesEverything(t *testing.T) {
	i, sys := newInstaller(t)
	source := filepath.Join(t.TempDir(), "aditd")
	os.WriteFile(source, []byte("aditd"), 0o700)
	if err := i.Install(Options{Aditd: source, Tray: "/opt/homebrew/bin/adit-tray", User: "dwight", UID: 501}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(i.path(StoreDir), 0o700)
	os.WriteFile(i.path(StoreDir+"/work.conf"), []byte("[Interface]\n"), 0o600)
	os.WriteFile(i.path(Log), []byte("log\n"), 0o644)
	os.WriteFile(i.path(Log+".0.bz2"), []byte("old log\n"), 0o644)
	resolvers := &dns.Resolvers{Dir: i.path(dns.DefaultDir)}
	resolvers.Set("work", []netip.Addr{netip.MustParseAddr("10.99.1.1")}, []string{"corp.example"})
	foreign := filepath.Join(resolvers.Dir, "other.example")
	os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0o644)
	sys.loaded = true

	var out strings.Builder
	if err := i.Uninstall(false, 501, &out); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{Plist, TrayAgent, Binary, Newsyslog, Log, Log + ".0.bz2", Store, dns.DefaultDir + "/corp.example"} {
		if _, err := os.Stat(i.path(path)); err == nil {
			t.Errorf("%s is still there", path)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("a resolver file adit did not write was removed")
	}
	if !slices.Contains(sys.ran, "/usr/sbin/dseditgroup -o delete adit") {
		t.Errorf("the group was not deleted: %q", sys.ran)
	}
	for _, want := range []string{"Stopped aditd", "every tunnel and its keys", "Deleted the adit group."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestUninstallCanKeepTheTunnels(t *testing.T) {
	i, _ := newInstaller(t)
	os.MkdirAll(i.path(StoreDir), 0o700)
	var out strings.Builder
	if err := i.Uninstall(true, 0, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(i.path(StoreDir)); err != nil {
		t.Error("the tunnels were removed")
	}
}

func TestAllowNeedsTheGroup(t *testing.T) {
	i, _ := newInstaller(t)
	if err := i.Allow("dwight"); err == nil || !strings.Contains(err.Error(), "install adit first") {
		t.Errorf("got %v", err)
	}
}

// fakeSystem stands in for launchctl, dscl and dseditgroup.
type fakeSystem struct {
	group  bool // the adit group exists
	loaded bool // aditd is in launchd
	ran    []string
}

func (s *fakeSystem) run(name string, args ...string) ([]byte, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	switch {
	case name == "/usr/bin/dscl":
		if !s.group {
			return []byte("eDSRecordNotFound"), errors.New("exit status 56")
		}
		return nil, nil
	case strings.Contains(command, "dseditgroup -o create"):
		s.group = true
	case strings.Contains(command, "dseditgroup -o delete"):
		s.group = false
	case strings.Contains(command, "launchctl bootout system/"):
		if !s.loaded {
			return []byte("Boot-out failed: 3: No such process"), errors.New("exit status 3")
		}
		s.loaded = false
	case strings.Contains(command, "launchctl bootstrap system"):
		s.loaded = true
	case name == "/usr/bin/dscacheutil":
		return nil, nil
	}
	s.ran = append(s.ran, command)
	return nil, nil
}

func (s *fakeSystem) expect(t *testing.T, commands ...string) {
	t.Helper()
	for _, command := range commands {
		if !slices.Contains(s.ran, command) {
			t.Errorf("did not run %q; ran %q", command, s.ran)
		}
	}
}

func newInstaller(t *testing.T) (*Installer, *fakeSystem) {
	sys := &fakeSystem{}
	return &Installer{
		Root:  t.TempDir(),
		Run:   sys.run,
		Chown: func(string, int, int) error { return nil },
	}, sys
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %o, want %o", filepath.Base(path), got, want)
	}
}
