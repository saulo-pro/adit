//go:build darwin || linux

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/service"
	"github.com/saulo-pro/adit/internal/store"
)

func TestMembersSwitchTunnels(t *testing.T) {
	client, _ := serve(t, roleMember)

	up := do(t, client, api.Request{Command: api.CommandUp, Name: "work"})
	if up.Tunnel == nil || up.Tunnel.State != "up" || up.Tunnel.Interface != "utun9" {
		t.Errorf("up answered %+v", up.Tunnel)
	}
	on := true
	autostart := do(t, client, api.Request{Command: api.CommandAutostart, Name: "work", On: &on})
	if !autostart.Tunnel.Autostart {
		t.Error("autostart was not set")
	}
	down := do(t, client, api.Request{Command: api.CommandDown, Name: "work"})
	if down.Tunnel.State != "down" {
		t.Errorf("down answered %+v", down.Tunnel)
	}
	list := do(t, client, api.Request{Command: api.CommandList})
	if len(list.Tunnels) != 1 || list.Tunnels[0].Name != "work" {
		t.Errorf("list answered %+v", list.Tunnels)
	}
}

func TestMembersMayNotImportRemoveOrExport(t *testing.T) {
	client, tunnels := serve(t, roleMember)
	for _, command := range []string{api.CommandImport, api.CommandRemove, api.CommandExport} {
		err := refusal(t, client, api.Request{Command: command, Name: "work", File: "[Interface]\n"})
		if err.Code != api.CodeNotAllowed || err.Message != command+" needs root: run it with sudo" {
			t.Errorf("%s: got %+v", command, err)
		}
		if err.Code.ExitCode() != 4 {
			t.Errorf("exit code %d, want 4", err.Code.ExitCode())
		}
	}
	if tunnels.calls != 0 {
		t.Errorf("the refused requests reached the tunnels %d times", tunnels.calls)
	}
}

func TestRootImportsExportsAndRemoves(t *testing.T) {
	client, _ := serve(t, roleRoot)

	imported := do(t, client, api.Request{Command: api.CommandImport, Name: "home", File: "[Interface]\nPostUp = echo hi\n"})
	if len(imported.Warnings) != 1 || imported.Tunnel.Name != "home" {
		t.Errorf("import answered %+v", imported)
	}
	exported := do(t, client, api.Request{Command: api.CommandExport, Name: "home"})
	if exported.File != "[Interface]\nPostUp = echo hi\n" {
		t.Errorf("export gave %q", exported.File)
	}
	do(t, client, api.Request{Command: api.CommandRemove, Name: "home"})
	if err := refusal(t, client, api.Request{Command: api.CommandStatus, Name: "home"}); err.Code != api.CodeNotFound || err.Code.ExitCode() != 5 {
		t.Errorf("status of a removed tunnel: %+v", err)
	}
}

func TestStrangersAreRefused(t *testing.T) {
	client, tunnels := serve(t, roleNone)
	err := refusal(t, client, api.Request{Command: api.CommandList})
	if err.Code != api.CodeNotAllowed || !strings.Contains(err.Message, "you are not in the adit group") {
		t.Errorf("got %+v", err)
	}
	if tunnels.calls != 0 {
		t.Error("a stranger's request reached the tunnels")
	}
}

func TestBadRequests(t *testing.T) {
	client, _ := serve(t, roleRoot)
	tests := []struct {
		req  api.Request
		says string
	}{
		{api.Request{Command: "reboot"}, "aditd does not know that command"},
		{api.Request{Command: api.CommandStatus, Name: strings.Repeat("x", 200)}, "that name is too long to be a tunnel's"},
		{api.Request{Command: api.CommandUp}, "up needs a tunnel name"},
		{api.Request{Command: api.CommandAutostart, Name: "work"}, "autostart needs on or off"},
	}
	for _, test := range tests {
		err := refusal(t, client, test.req)
		if err.Code != api.CodeBadRequest || err.Message != test.says || err.Code.ExitCode() != 2 {
			t.Errorf("%+v: got %+v", test.req, err)
		}
	}
}

func TestNotJSONIsABadRequest(t *testing.T) {
	client, _ := serve(t, roleRoot)
	conn, err := net.Dial("unix", client.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "up work\n")
	var resp api.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error.Code != api.CodeBadRequest {
		t.Errorf("got %+v", resp)
	}
}

func TestVersion(t *testing.T) {
	client, _ := serve(t, roleMember)
	if resp := do(t, client, api.Request{Command: api.CommandVersion}); resp.Version != "test" {
		t.Errorf("version %q", resp.Version)
	}
}

func TestWatchFollowsChanges(t *testing.T) {
	client, _ := serve(t, roleMember) // polls once an hour: what arrives came from a signal
	ctx, cancel := context.WithCancel(context.Background())
	seen := make(chan []api.Tunnel, 10)
	done := make(chan error)
	go func() {
		done <- client.Watch(ctx, func(tunnels, _ []api.Tunnel) error {
			seen <- tunnels
			return nil
		})
	}()

	if first := next(t, seen); len(first) != 1 || first[0].State != "down" {
		t.Fatalf("first view %+v", first)
	}
	do(t, client, api.Request{Command: api.CommandUp, Name: "work"})
	if view := next(t, seen); view[0].State != "up" {
		t.Errorf("after up the watcher saw %+v", view)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Watch ended with %v", err)
	}
}

func TestCountersAloneAreNotAChange(t *testing.T) {
	handshake := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	a := []api.Tunnel{{Name: "work", State: "up", LastHandshake: &handshake, ReceivedBytes: 1}}
	b := []api.Tunnel{{Name: "work", State: "up", LastHandshake: &handshake, ReceivedBytes: 9000}}
	if !sameView(a, b) {
		t.Error("a change of counters alone counted as a change")
	}
	later := handshake.Add(2 * time.Minute)
	b[0].LastHandshake = &later
	if sameView(a, b) {
		t.Error("a new handshake did not count as a change")
	}
}

func TestPeerUIDIsTheCaller(t *testing.T) {
	path := socketPath(t)
	l, err := Listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go net.Dial("unix", path)
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	uid, err := peerUID(conn)
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() {
		t.Errorf("peer uid %d, want %d", uid, os.Getuid())
	}
	if r, _, _ := authorize(conn, primaryGroup(t)); r != roleMember {
		t.Errorf("a member of the group got role %d", r)
	}
	if r, _, _ := authorize(conn, "adit-no-such-group"); r != roleNone {
		t.Errorf("a missing group gave role %d", r)
	}
}

func TestListenOpensTheSocketToTheGroupOnly(t *testing.T) {
	rootOnly := socketPath(t)
	l, err := Listen(rootOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	assertSocketMode(t, rootOnly, 0o600)

	group := primaryGroup(t)
	shared := socketPath(t)
	l2, err := Listen(shared, group)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	assertSocketMode(t, shared, 0o660)
	g, _ := user.LookupGroup(group)
	info, _ := os.Stat(shared)
	if gid := strconv.Itoa(int(info.Sys().(*syscall.Stat_t).Gid)); gid != g.Gid {
		t.Errorf("socket group %s, want %s", gid, g.Gid)
	}
}

func TestListenReplacesOnlyAStaleSocket(t *testing.T) {
	path := socketPath(t)
	l, err := Listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, ""); err == nil || !strings.Contains(err.Error(), "another aditd is already answering") {
		t.Errorf("a second Listen gave %v", err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	l, err = Listen(path, "")
	if err != nil {
		t.Errorf("a stale socket was not replaced: %v", err)
	} else {
		l.Close()
	}

	file := socketPath(t)
	os.WriteFile(file, []byte("not a socket"), 0o600)
	if _, err := Listen(file, ""); err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Errorf("Listen over a file gave %v", err)
	}
	if _, err := Listen(socketPath(t), "adit-no-such-group"); err == nil || !strings.Contains(err.Error(), "sudo adit install creates it") {
		t.Errorf("a missing group gave %v", err)
	}
}

func TestClientExplainsWhyItCannotConnect(t *testing.T) {
	client := &api.Client{Socket: socketPath(t)}
	_, err := client.Do(context.Background(), api.Request{Command: api.CommandList})
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Code != api.CodeUnreachable || apiErr.Code.ExitCode() != 3 {
		t.Errorf("no aditd: got %v", err)
	}

	l, err := Listen(client.Socket, "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	os.Chmod(client.Socket, 0)
	_, err = client.Do(context.Background(), api.Request{Command: api.CommandList})
	if !errors.As(err, &apiErr) || apiErr.Code != api.CodeNotAllowed || !strings.Contains(apiErr.Message, "sudo adit allow") {
		t.Errorf("no permission: got %v", err)
	}
}

// serve runs a server on a fresh socket, with every caller taken to have role r.
func serve(t *testing.T, r role) (*api.Client, *fakeTunnels) {
	t.Helper()
	path := socketPath(t)
	l, err := Listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	tunnels := newFakeTunnels()
	s := New(tunnels, "", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.authorize = func(*net.UnixConn) (role, int, error) { return r, 501, nil }
	s.poll = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return &api.Client{Socket: path}, tunnels
}

// socketPath is short: a Unix socket's path must fit in 104 bytes on macOS.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "adit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func do(t *testing.T, client *api.Client, req api.Request) *api.Response {
	t.Helper()
	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("%s: %v", req.Command, err)
	}
	return resp
}

func refusal(t *testing.T, client *api.Client, req api.Request) *api.Error {
	t.Helper()
	_, err := client.Do(context.Background(), req)
	var apiErr *api.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("%s: got %v, want a refusal", req.Command, err)
	}
	return apiErr
}

func next(t *testing.T, seen chan []api.Tunnel) []api.Tunnel {
	t.Helper()
	select {
	case tunnels := <-seen:
		return tunnels
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher saw nothing")
		return nil
	}
}

func primaryGroup(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return g.Name
}

func assertSocketMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("socket mode %o, want %o", got, want)
	}
}

// fakeTunnels starts with one tunnel, work, down.
type fakeTunnels struct {
	mu      sync.Mutex
	status  map[string]*service.Status
	files   map[string][]byte
	changes chan struct{}
	calls   int
}

func newFakeTunnels() *fakeTunnels {
	return &fakeTunnels{
		status:  map[string]*service.Status{"work": {Name: "work", State: service.StateDown}},
		files:   map[string][]byte{"work": []byte("[Interface]\n")},
		changes: make(chan struct{}, 1),
	}
}

type notFound string

func (n notFound) Error() string        { return "there is no tunnel named " + string(n) }
func (n notFound) Is(target error) bool { return target == store.ErrNotFound }

func (f *fakeTunnels) get(name string) (*service.Status, error) {
	f.calls++
	if status, ok := f.status[name]; ok {
		return status, nil
	}
	return nil, notFound(name)
}

func (f *fakeTunnels) changed() {
	select {
	case f.changes <- struct{}{}:
	default:
	}
}

func (f *fakeTunnels) Import(name string, text []byte) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.status[name] = &service.Status{Name: name, State: service.StateDown}
	f.files[name] = text
	f.changed()
	if strings.Contains(string(text), "PostUp") {
		return []string{"PostUp line kept but not run: adit never runs commands from a configuration."}, nil
	}
	return nil, nil
}

func (f *fakeTunnels) File(name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.get(name); err != nil {
		return nil, err
	}
	return f.files[name], nil
}

func (f *fakeTunnels) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.get(name); err != nil {
		return err
	}
	delete(f.status, name)
	f.changed()
	return nil
}

func (f *fakeTunnels) Up(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, err := f.get(name)
	if err != nil {
		return err
	}
	status.State, status.Interface = service.StateUp, "utun9"
	f.changed()
	return nil
}

func (f *fakeTunnels) Down(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, err := f.get(name)
	if err != nil {
		return err
	}
	status.State, status.Interface = service.StateDown, ""
	f.changed()
	return nil
}

func (f *fakeTunnels) SetKillSwitch(name, mode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, err := f.get(name)
	if err != nil {
		return err
	}
	status.KillSwitch = mode
	f.changed()
	return nil
}

// signInUntil is when the fake's kill switch comes back.
var signInUntil = time.Date(2026, 11, 27, 18, 2, 0, 0, time.UTC)

func (f *fakeTunnels) SignIn() (time.Time, error) {
	return signInUntil, nil
}

func (f *fakeTunnels) SetAutostart(name string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, err := f.get(name)
	if err != nil {
		return err
	}
	status.Autostart = on
	f.changed()
	return nil
}

func (f *fakeTunnels) List() ([]service.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var statuses []service.Status
	for _, status := range f.status {
		statuses = append(statuses, *status)
	}
	slices.SortFunc(statuses, func(a, b service.Status) int { return strings.Compare(a.Name, b.Name) })
	return statuses, nil
}

func (f *fakeTunnels) Status(name string) (service.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status, err := f.get(name)
	if err != nil {
		return service.Status{}, err
	}
	return *status, nil
}

func (f *fakeTunnels) Others(bool) []service.Status {
	return []service.Status{{Name: "williamsburg", Source: "WireGuard app", State: "connected", Interface: "utun7", ReadOnly: true}}
}

func (f *fakeTunnels) Other(name string) (service.Status, bool) {
	for _, other := range f.Others(true) {
		if other.Name == name {
			return other, true
		}
	}
	return service.Status{}, false
}

func (f *fakeTunnels) Changes() (<-chan struct{}, func()) {
	return f.changes, func() {}
}

type clash struct{}

func (clash) Error() string {
	return "two's AllowedIPs 10.99.1.0/24 overlaps 10.99.0.0/16 of one, which is up"
}
func (clash) Is(target error) bool { return target == service.ErrConflict }

type clashingTunnels struct{ *fakeTunnels }

func (clashingTunnels) Up(context.Context, string) error { return clash{} }

func TestConflictsAreExitCodeSix(t *testing.T) {
	path := socketPath(t)
	l, err := Listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	s := New(clashingTunnels{newFakeTunnels()}, "", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.authorize = func(*net.UnixConn) (role, int, error) { return roleMember, 501, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, l)

	refused := refusal(t, &api.Client{Socket: path}, api.Request{Command: api.CommandUp, Name: "work"})
	if refused.Code != api.CodeConflict || refused.Code.ExitCode() != 6 || refused.Message != (clash{}).Error() {
		t.Errorf("got %+v", refused)
	}
}

func TestOtherSoftwaresTunnelsAreShownNotChanged(t *testing.T) {
	client, _ := serve(t, roleRoot)
	list := do(t, client, api.Request{Command: api.CommandList})
	if len(list.Others) != 1 || list.Others[0].Name != "williamsburg" || !list.Others[0].ReadOnly {
		t.Errorf("others %+v", list.Others)
	}
	if status := do(t, client, api.Request{Command: api.CommandStatus, Name: "williamsburg"}); status.Tunnel.Source != "WireGuard app" {
		t.Errorf("status %+v", status.Tunnel)
	}
	for _, command := range []string{api.CommandUp, api.CommandDown, api.CommandRemove, api.CommandExport} {
		err := refusal(t, client, api.Request{Command: command, Name: "williamsburg"})
		if err.Code != api.CodeFailed || err.Message != "williamsburg is the WireGuard app's tunnel: adit shows it but does not change it; use the WireGuard app" {
			t.Errorf("%s: %+v", command, err)
		}
	}
}

func TestAMemberCannotSendALargeRequest(t *testing.T) {
	client, _ := serve(t, roleMember)
	// aditd stops reading at the limit and answers: the client sees a refusal or a closed connection.
	if _, err := client.Do(context.Background(), api.Request{Command: api.CommandStatus, Name: "work", File: strings.Repeat("x", maxMemberRequest)}); err == nil {
		t.Error("a member's oversized request was served")
	}
}
