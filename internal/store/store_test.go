package store

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A throwaway key made for these tests; it guards nothing.
const file = "# work VPN, from the admin\n" +
	"[Interface]\n" +
	"PrivateKey = cLzT3oxyUzSXHZQPIOcI2LSoG5mBzVunYbXpSonv2UU=\n" +
	"Address = 10.99.1.2/24\n" +
	"\n" +
	"[Peer]\n" +
	"PublicKey = L4oNLijDi5zJ8gOyZv1Rj4tmLS6jVBGWWwWoN/jYCAQ=\n" +
	"AllowedIPs = 10.99.1.0/24\n"

func TestAddedFileComesBackUnchanged(t *testing.T) {
	s := openStore(t)
	if _, err := s.Add("work", []byte(file)); err != nil {
		t.Fatal(err)
	}
	got, err := s.File("work")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(file)) {
		t.Errorf("File gave back:\n%s\nwant the file as imported, comment included", got)
	}
}

func TestGetParsesTheTunnel(t *testing.T) {
	s := openStore(t)
	mustAdd(t, s, "work")

	tunnel, err := s.Get("WORK")
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Name != "work" {
		t.Errorf("Name = %q, want the stored spelling %q", tunnel.Name, "work")
	}
	if len(tunnel.Config.Peers) != 1 {
		t.Errorf("got %d peers, want 1", len(tunnel.Config.Peers))
	}
	if tunnel.Settings.Autostart {
		t.Error("a new tunnel starts automatically, want off by default")
	}
}

func TestNamesAreUniqueRegardlessOfCase(t *testing.T) {
	s := openStore(t)
	mustAdd(t, s, "Work")
	_, err := s.Add("work", []byte(file))
	if !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
	if !strings.Contains(err.Error(), "a tunnel named Work already exists") {
		t.Errorf("error %q does not name the existing tunnel", err)
	}
}

func TestAddRefusesWhatDoesNotParse(t *testing.T) {
	s := openStore(t)
	if _, err := s.Add("broken", []byte("[Interface]\n")); err == nil {
		t.Fatal("a file without a PrivateKey was stored")
	}
	if names, _ := s.names(); len(names) != 0 {
		t.Errorf("something was stored anyway: %v", names)
	}
}

func TestInvalidNames(t *testing.T) {
	for _, name := range []string{"", "../escape", "a/b", ".hidden", "-flag", "with space", "naïve", strings.Repeat("a", 33)} {
		if err := ValidName(name); err == nil {
			t.Errorf("%q was accepted as a tunnel name", name)
		}
	}
	for _, name := range []string{"work", "Home-2", "client.vpn", "a_b", "9", strings.Repeat("a", 32)} {
		if err := ValidName(name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
}

func TestListIsSortedByName(t *testing.T) {
	s := openStore(t)
	for _, name := range []string{"zeta", "Alpha", "mid"} {
		mustAdd(t, s, name)
	}
	tunnels, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tunnel := range tunnels {
		names = append(names, tunnel.Name)
	}
	if strings.Join(names, " ") != "Alpha mid zeta" {
		t.Errorf("List gave %v", names)
	}
}

func TestSettingsPersist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunnels")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, "work")
	if err := s.SetSettings("work", Settings{Autostart: true}); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := reopened.Get("work")
	if err != nil {
		t.Fatal(err)
	}
	if !tunnel.Settings.Autostart {
		t.Error("autostart was not kept")
	}
}

func TestRemove(t *testing.T) {
	s := openStore(t)
	mustAdd(t, s, "work")
	if err := s.SetSettings("work", Settings{Autostart: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("work"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Remove, Get gave %v, want ErrNotFound", err)
	}
	if entries, _ := os.ReadDir(s.dir); len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
	if err := s.Remove("work"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing it again gave %v, want ErrNotFound", err)
	}
}

func TestMissingTunnelIsNamed(t *testing.T) {
	s := openStore(t)
	_, err := s.Get("nowhere")
	if !errors.Is(err, ErrNotFound) || err.Error() != "there is no tunnel named nowhere" {
		t.Errorf("got %v", err)
	}
}

func TestOnlyTheOwnerCanRead(t *testing.T) {
	s := openStore(t)
	mustAdd(t, s, "work")
	if err := s.SetSettings("work", Settings{Autostart: true}); err != nil {
		t.Fatal(err)
	}

	assertMode(t, s.dir, 0o700)
	assertMode(t, filepath.Join(s.dir, "work.conf"), 0o600)
	assertMode(t, filepath.Join(s.dir, "work.json"), 0o600)
}

func TestOpenRefusesAReadableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "can be read by other users") {
		t.Errorf("got %v, want a refusal", err)
	}
}

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "tunnels"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustAdd(t *testing.T, s *Store, name string) {
	t.Helper()
	if _, err := s.Add(name, []byte(file)); err != nil {
		t.Fatal(err)
	}
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

func TestOpenRemovesWhatACrashLeft(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunnels")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".write-123"), []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".write-123")); !os.IsNotExist(err) {
		t.Errorf("the leftover is still there: %v", err)
	}
}

func TestOpenKeepsTheStoreOutOfBackups(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Time Machine is macOS only")
	}
	dir := filepath.Join(t.TempDir(), "tunnels")
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/tmutil", "isexcluded", dir).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "[Excluded]") {
		t.Errorf("tmutil isexcluded: %s %v", out, err)
	}
}
