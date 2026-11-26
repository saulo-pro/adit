package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/install"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// Throwaway key made for these tests; it guards nothing.
const exportedFile = "[Interface]\nPrivateKey = cLzT3oxyUzSXHZQPIOcI2LSoG5mBzVunYbXpSonv2UU=\n"

func tunnels() []api.Tunnel {
	handshake := now.Add(-12 * time.Second)
	return []api.Tunnel{
		{Name: "home", State: "down"},
		{Name: "work", State: "up", Autostart: true, Interface: "utun9", LastHandshake: &handshake, ReceivedBytes: 476, SentBytes: 3 << 20},
	}
}

func TestListTable(t *testing.T) {
	run := newRun(t, answerWith(tunnels()))
	code := run.cli("list")
	want := "NAME  STATE  INTERFACE  HANDSHAKE  RECEIVED  SENT     AUTOSTART  BY\n" +
		"home  down   -          -          -         -        off        adit\n" +
		"work  up     utun9      12s ago    476 B     3.0 MiB  on         adit\n"
	if code != 0 || run.stdout.String() != want {
		t.Errorf("exit %d, output:\n%s\nwant:\n%s", code, run.stdout, want)
	}
}

func TestListJSON(t *testing.T) {
	run := newRun(t, answerWith(tunnels()))
	if code := run.cli("list", "--json"); code != 0 {
		t.Fatalf("exit %d: %s", code, run.stderr)
	}
	var got struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal(run.stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	home, work := got.Tunnels[0], got.Tunnels[1]
	if home["interface"] != nil || home["last_handshake"] != nil || home["handshake_age_seconds"] != nil {
		t.Errorf("a tunnel that is down: %v", home)
	}
	if work["handshake_age_seconds"] != float64(12) || work["interface"] != "utun9" || work["sent_bytes"] != float64(3<<20) {
		t.Errorf("a tunnel that is up: %v", work)
	}
	for _, key := range []string{"name", "state", "autostart", "interface", "last_handshake", "handshake_age_seconds", "received_bytes", "sent_bytes"} {
		if _, ok := home[key]; !ok {
			t.Errorf("key %s is missing; scripts expect every key, null when empty", key)
		}
	}
}

func TestStatusOfOneTunnel(t *testing.T) {
	run := newRun(t, answerWith(tunnels()))
	run.cli("status", "work")
	want := "work is up on utun9.\n" +
		"  last handshake  12s ago\n" +
		"  received        476 B\n" +
		"  sent            3.0 MiB\n" +
		"  autostart       on\n"
	if run.stdout.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", run.stdout, want)
	}
}

func TestFlagsGoAnywhere(t *testing.T) {
	for _, args := range [][]string{{"status", "work", "--json"}, {"status", "--json", "work"}} {
		run := newRun(t, answerWith(tunnels()))
		if code := run.cli(args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, run.stderr)
		}
		var got map[string]any
		if err := json.Unmarshal(run.stdout.Bytes(), &got); err != nil || got["name"] != "work" {
			t.Errorf("%v gave %s", args, run.stdout)
		}
	}
}

func TestUpWaitsForTheFirstHandshake(t *testing.T) {
	statusCalls := 0
	run := newRun(t, func(req api.Request) api.Response {
		tunnel := api.Tunnel{Name: "work", State: "connecting", Interface: "utun9"}
		if req.Command == api.CommandStatus {
			statusCalls++
			if statusCalls >= 2 {
				handshake := now
				tunnel.State, tunnel.LastHandshake = "up", &handshake
			}
		}
		return api.Response{OK: true, Tunnel: &tunnel}
	})
	if code := run.cli("up", "work"); code != 0 || run.stdout.String() != "work is up on utun9.\n" {
		t.Errorf("exit %d: %s%s", code, run.stdout, run.stderr)
	}
}

func TestUpWithoutAHandshakeSaysSo(t *testing.T) {
	run := newRun(t, func(req api.Request) api.Response {
		return api.Response{OK: true, Tunnel: &api.Tunnel{Name: "work", State: "connecting", Interface: "utun9"}}
	})
	run.c.upWait = 300 * time.Millisecond
	if code := run.cli("up", "work"); code != 0 || !strings.Contains(run.stdout.String(), "work is on utun9 but has had no handshake yet") {
		t.Errorf("exit %d: %s", code, run.stdout)
	}
}

func TestRefusalsBecomeExitCodes(t *testing.T) {
	for code, exit := range map[api.Code]int{api.CodeFailed: 1, api.CodeBadRequest: 2, api.CodeNotAllowed: 4, api.CodeNotFound: 5, api.CodeConflict: 6} {
		refuse := func(api.Request) api.Response {
			return api.Response{Error: &api.Error{Code: code, Message: "a sentence about " + string(code)}}
		}

		run := newRun(t, refuse)
		if got := run.cli("down", "work"); got != exit || run.stderr.String() != "adit: a sentence about "+string(code)+"\n" {
			t.Errorf("%s: exit %d, stderr %q", code, got, run.stderr)
		}

		run = newRun(t, refuse)
		run.cli("down", "work", "--json")
		var got struct{ Error api.Error }
		if err := json.Unmarshal(run.stdout.Bytes(), &got); err != nil || got.Error.Code != code {
			t.Errorf("%s in JSON: %s", code, run.stdout)
		}
	}
}

func TestUsageMistakes(t *testing.T) {
	for _, args := range [][]string{{}, {"up"}, {"up", "a", "b"}, {"autostart", "work", "maybe"}, {"frobnicate"}, {"list", "--colour"}} {
		run := newRun(t, answerWith(tunnels()))
		if code := run.cli(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if len(run.requests) != 0 {
			t.Errorf("%v reached aditd", args)
		}
	}

	run := newRun(t, answerWith(tunnels()))
	if code := run.cli("help"); code != 0 || !strings.Contains(run.stdout.String(), "Exit status: 0 done") {
		t.Errorf("help: exit %d", code)
	}
}

func TestImportSendsTheFileTextNotItsPath(t *testing.T) {
	run := newRun(t, func(req api.Request) api.Response {
		return api.Response{OK: true, Tunnel: &api.Tunnel{Name: req.Name, State: "down"},
			Warnings: []string{"PostUp line kept but not run: adit never runs commands from a configuration."}}
	})
	path := filepath.Join(t.TempDir(), "work.conf")
	os.WriteFile(path, []byte("[Interface]\nPostUp = echo hi\n"), 0o600)

	if code := run.cli("import", path); code != 0 {
		t.Fatalf("exit %d: %s", code, run.stderr)
	}
	req := run.requests[0]
	if req.Name != "work" || req.File != "[Interface]\nPostUp = echo hi\n" || strings.Contains(req.File, path) {
		t.Errorf("sent %+v", req)
	}
	if !strings.Contains(run.stderr.String(), "PostUp line kept but not run") {
		t.Errorf("the warning was not shown: %s", run.stderr)
	}

	run.cli("import", path, "--name", "office")
	if run.requests[1].Name != "office" {
		t.Errorf("--name was ignored: %+v", run.requests[1])
	}
}

func TestImportFromStandardInputNeedsAName(t *testing.T) {
	run := newRun(t, answerWith(tunnels()))
	if code := run.cli("import", "-"); code != 2 {
		t.Errorf("exit %d", code)
	}
	run.c.Stdin = strings.NewReader("[Interface]\n")
	run.handle = func(req api.Request) api.Response {
		return api.Response{OK: true, Tunnel: &api.Tunnel{Name: req.Name, State: "down"}}
	}
	if code := run.cli("import", "-", "--name", "piped"); code != 0 || run.requests[0].File != "[Interface]\n" {
		t.Errorf("exit %d, sent %+v", code, run.requests)
	}
}

func TestExportWritesAFileOnlyItsOwnerCanRead(t *testing.T) {
	run := newRun(t, func(api.Request) api.Response { return api.Response{OK: true, File: exportedFile} })
	path := filepath.Join(t.TempDir(), "work.conf")

	if code := run.cli("export", "work", "--output", path); code != 0 {
		t.Fatalf("exit %d: %s", code, run.stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != exportedFile {
		t.Errorf("file holds %q (%v)", data, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
	if strings.Contains(run.stdout.String()+run.stderr.String(), "PrivateKey") {
		t.Error("the key was printed")
	}

	if code := run.cli("export", "work", "--output", path); code != 1 || !strings.Contains(run.stderr.String(), "will not overwrite it") {
		t.Errorf("over an existing file: exit %d, %s", code, run.stderr)
	}
	for _, output := range []string{"-", "/dev/stdout", ""} {
		args := []string{"export", "work"}
		if output != "" {
			args = append(args, "--output", output)
		}
		if code := run.cli(args...); code != 2 {
			t.Errorf("--output %q: exit %d", output, code)
		}
	}
}

func TestExportUnderSudoHandsTheFileToTheUser(t *testing.T) {
	run := newRun(t, func(api.Request) api.Response { return api.Response{OK: true, File: exportedFile} })
	var owner []int
	run.c.euid = func() int { return 0 }
	run.c.Getenv = func(key string) string { return map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}[key] }
	run.c.chown = func(path string, uid, gid int) error {
		owner = []int{uid, gid}
		return nil
	}
	if code := run.cli("export", "work", "--output", filepath.Join(t.TempDir(), "work.conf")); code != 0 {
		t.Fatalf("exit %d: %s", code, run.stderr)
	}
	if len(owner) != 2 || owner[0] != 501 || owner[1] != 20 {
		t.Errorf("chown to %v, want 501:20", owner)
	}
}

func TestVersionAnswersWithoutAditd(t *testing.T) {
	run := newRun(t, answerWith(nil))
	run.c.Client = &api.Client{Socket: filepath.Join(t.TempDir(), "nowhere")}
	if code := run.cli("version"); code != 0 || !strings.HasPrefix(run.stdout.String(), "adit test\naditd: aditd is not running") {
		t.Errorf("exit %d: %s", code, run.stdout)
	}
}

func TestAutostart(t *testing.T) {
	run := newRun(t, func(req api.Request) api.Response {
		return api.Response{OK: true, Tunnel: &api.Tunnel{Name: "work", State: "down", Autostart: *req.On}}
	})
	if code := run.cli("autostart", "work", "on"); code != 0 || !*run.requests[0].On || run.stdout.String() != "work comes up when the Mac starts.\n" {
		t.Errorf("exit %d: %s", code, run.stdout)
	}
}

func TestHumanSizes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d bytes: %s, want %s", n, got, want)
		}
	}
	for d, want := range map[time.Duration]string{12 * time.Second: "12s", 3 * time.Minute: "3m", 5 * time.Hour: "5h", 72 * time.Hour: "3d"} {
		if got := humanAge(d); got != want {
			t.Errorf("%s: %s, want %s", d, got, want)
		}
	}
}

// run is one command line talking to a fake aditd that answers with handle.
type run struct {
	c        *CLI
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	handle   func(api.Request) api.Response
	mu       sync.Mutex
	requests []api.Request
}

func newRun(t *testing.T, handle func(api.Request) api.Response) *run {
	t.Helper()
	dir, err := os.MkdirTemp("", "adit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	r := &run{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, handle: handle}
	r.c = &CLI{
		Client:  &api.Client{Socket: socket},
		Version: "test",
		Stdin:   strings.NewReader(""),
		Stdout:  r.stdout,
		Stderr:  r.stderr,
		Getenv:  func(string) string { return "" },
		Now:     func() time.Time { return now },
		upWait:  3 * time.Second,
		chown:   func(string, int, int) error { return nil },
		euid:    func() int { return 501 },
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			var req api.Request
			if json.NewDecoder(conn).Decode(&req) == nil {
				r.mu.Lock()
				r.requests = append(r.requests, req)
				handle := r.handle
				r.mu.Unlock()
				json.NewEncoder(conn).Encode(handle(req))
			}
			conn.Close()
		}
	}()
	return r
}

func (r *run) cli(args ...string) int {
	r.stdout.Reset()
	r.stderr.Reset()
	return r.c.Run(context.Background(), args)
}

func answerWith(tunnels []api.Tunnel) func(api.Request) api.Response {
	return func(req api.Request) api.Response {
		if req.Command == api.CommandList {
			return api.Response{OK: true, Tunnels: tunnels}
		}
		for _, tunnel := range tunnels {
			if tunnel.Name == req.Name {
				return api.Response{OK: true, Tunnel: &tunnel}
			}
		}
		return api.Response{Error: &api.Error{Code: api.CodeNotFound, Message: "there is no tunnel named " + req.Name}}
	}
}

func TestNotesAreShown(t *testing.T) {
	note := "DNS 10.99.1.1 is not used: adit sends a tunnel's DNS queries only for the domains on its DNS line, and this line names none"
	run := newRun(t, answerWith([]api.Tunnel{{Name: "work", State: "down", Notes: []string{note}}}))
	run.cli("status", "work")
	if want := "work is down. Autostart is off.\n  Note: " + note + ".\n"; run.stdout.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", run.stdout, want)
	}

	run.cli("status", "work", "--json")
	var got struct{ Notes []string }
	json.Unmarshal(run.stdout.Bytes(), &got)
	if len(got.Notes) != 1 || got.Notes[0] != note {
		t.Errorf("JSON notes %q", got.Notes)
	}
}

func TestNoNotesIsAnEmptyList(t *testing.T) {
	run := newRun(t, answerWith(tunnels()))
	run.cli("status", "work", "--json")
	if !strings.Contains(run.stdout.String(), `"notes": []`) {
		t.Errorf("got %s", run.stdout)
	}
}

type fakeInstaller struct {
	installed   []string // aditd, tray, user
	uninstalled *bool    // keepTunnels
	allowed     []string
	disallowed  []string
	report      string
}

func (f *fakeInstaller) Install(o install.Options, out io.Writer) error {
	f.installed = []string{o.Aditd, o.Tray, o.User}
	io.WriteString(out, f.report)
	return nil
}
func (f *fakeInstaller) Uninstall(keep bool, uid int, out io.Writer) error {
	f.uninstalled = &keep
	io.WriteString(out, f.report)
	return nil
}
func (f *fakeInstaller) Allow(user string) error { f.allowed = append(f.allowed, user); return nil }
func (f *fakeInstaller) Disallow(user string) error {
	f.disallowed = append(f.disallowed, user)
	return nil
}
func (f *fakeInstaller) Installed() bool { return true }

func withSystem(run *run, root bool) *fakeInstaller {
	f := &fakeInstaller{report: "Installed aditd.\n"}
	run.c.installer = f
	run.c.euid = func() int {
		if root {
			return 0
		}
		return 501
	}
	run.c.Getenv = func(key string) string { return map[string]string{"SUDO_USER": "max"}[key] }
	run.c.executable = func() (string, error) { return "/opt/homebrew/Cellar/adit/1.0/bin/adit", nil }
	run.c.runVersion = func(string) (string, error) { return "test", nil }
	run.c.lookupUser = func(name string) error {
		if name == "nosuchuser" {
			return errors.New("unknown user")
		}
		return nil
	}
	run.c.isTerminal = func() bool { return false }
	run.c.exists = func(path string) bool { return path == "/opt/homebrew/Cellar/adit/1.0/bin/adit-tray" }
	run.c.aditdWait = time.Second
	return f
}

func TestInstallUsesTheAditdBesideAdit(t *testing.T) {
	run := newRun(t, func(api.Request) api.Response { return api.Response{OK: true, Version: "test"} })
	f := withSystem(run, true)
	if code := run.cli("install"); code != 0 {
		t.Fatalf("exit %d: %s", code, run.stderr)
	}
	if f.installed[0] != "/opt/homebrew/Cellar/adit/1.0/bin/aditd" || f.installed[1] != "/opt/homebrew/Cellar/adit/1.0/bin/adit-tray" || f.installed[2] != "max" {
		t.Errorf("installed %v", f.installed)
	}
	for _, want := range []string{"Installed aditd.\n", "aditd test is running, and starts whenever the Mac does.", "max can now use adit without sudo"} {
		if !strings.Contains(run.stdout.String(), want) {
			t.Errorf("the output lacks %q:\n%s", want, run.stdout)
		}
	}
}

func TestInstallRefusesAMismatchedAditd(t *testing.T) {
	run := newRun(t, answerWith(nil))
	f := withSystem(run, true)
	run.c.runVersion = func(string) (string, error) { return "0.9", nil }
	if code := run.cli("install"); code != 1 || !strings.Contains(run.stderr.String(), "is version 0.9 but this adit is test") {
		t.Errorf("exit %d: %s", code, run.stderr)
	}
	if f.installed != nil {
		t.Error("it installed anyway")
	}
}

func TestSystemCommandsNeedRoot(t *testing.T) {
	for _, args := range [][]string{{"install"}, {"uninstall", "--yes"}, {"allow", "max"}, {"disallow", "max"}} {
		run := newRun(t, answerWith(nil))
		withSystem(run, false)
		if code := run.cli(args...); code != 4 || !strings.Contains(run.stderr.String(), args[0]+" needs root: run it with sudo") {
			t.Errorf("%v: exit %d: %s", args, code, run.stderr)
		}
	}
}

func TestUninstallNeedsConfirmation(t *testing.T) {
	run := newRun(t, answerWith(nil))
	f := withSystem(run, true)
	if code := run.cli("uninstall"); code != 2 || f.uninstalled != nil {
		t.Errorf("without a terminal or --yes: exit %d, uninstalled %v", code, f.uninstalled)
	}

	run.c.isTerminal = func() bool { return true }
	run.c.Stdin = strings.NewReader("no\n")
	if code := run.cli("uninstall"); code != 1 || f.uninstalled != nil {
		t.Errorf("answered no: exit %d", code)
	}

	run.c.Stdin = strings.NewReader("yes\n")
	if code := run.cli("uninstall", "--keep-tunnels"); code != 0 || f.uninstalled == nil || !*f.uninstalled {
		t.Errorf("answered yes: exit %d, keep %v", code, f.uninstalled)
	}

	f.uninstalled = nil
	if code := run.cli("uninstall", "--yes"); code != 0 || f.uninstalled == nil || *f.uninstalled {
		t.Errorf("--yes: exit %d", code)
	}
}

func TestAllowAndDisallow(t *testing.T) {
	run := newRun(t, answerWith(nil))
	f := withSystem(run, true)
	if code := run.cli("allow", "caroline"); code != 0 || len(f.allowed) != 1 || f.allowed[0] != "caroline" {
		t.Errorf("allow: exit %d, %v", code, f.allowed)
	}
	if code := run.cli("disallow", "caroline"); code != 0 || len(f.disallowed) != 1 {
		t.Errorf("disallow: exit %d, %v", code, f.disallowed)
	}
	if code := run.cli("allow", "nosuchuser"); code != 1 || !strings.Contains(run.stderr.String(), "there is no user named nosuchuser") {
		t.Errorf("unknown user: exit %d, %s", code, run.stderr)
	}
}

func TestOtherSoftwaresTunnelsAreListedReadOnly(t *testing.T) {
	handshake := now.Add(-time.Minute)
	others := []api.Tunnel{
		{Name: "williamsburg", State: "connected", Interface: "utun7", Source: "WireGuard app", ReadOnly: true},
		{Name: "diner", State: "up", Interface: "utun8", Source: "wg-quick", ReadOnly: true, LastHandshake: &handshake, ReceivedBytes: 92},
	}
	run := newRun(t, func(req api.Request) api.Response {
		return api.Response{OK: true, Tunnels: tunnels()[1:], Others: others}
	})
	run.cli("list")
	want := "NAME          STATE      INTERFACE  HANDSHAKE  RECEIVED  SENT     AUTOSTART  BY\n" +
		"work          up         utun9      12s ago    476 B     3.0 MiB  on         adit\n" +
		"williamsburg  connected  utun7      -          -         -        -          WireGuard app (read-only)\n" +
		"diner         up         utun8      1m ago     92 B      0 B      -          wg-quick (read-only)\n"
	if run.stdout.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", run.stdout, want)
	}

	run.cli("list", "--json")
	var got struct{ Others []map[string]any }
	json.Unmarshal(run.stdout.Bytes(), &got)
	if len(got.Others) != 2 || got.Others[0]["read_only"] != true || got.Others[1]["source"] != "wg-quick" {
		t.Errorf("JSON others %v", got.Others)
	}
}
