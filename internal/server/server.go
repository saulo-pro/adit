// Package server is aditd's socket: it checks who is calling, answers requests and keeps watchers
// up to date.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/service"
	"github.com/saulo-pro/adit/internal/store"
)

// upTimeout bounds bringing one tunnel up, endpoint lookup included. It does not depend on the
// caller staying connected: a tray that quits mid-click does not leave a tunnel half up.
const upTimeout = 30 * time.Second

// Tunnels is what the server serves: service.Manager in aditd.
type Tunnels interface {
	Import(name string, text []byte) ([]string, error)
	File(name string) ([]byte, error)
	Remove(name string) error
	Up(ctx context.Context, name string) error
	Down(name string) error
	SetAutostart(name string, on bool) error
	SetKillSwitch(name, mode string) error
	SetLAN(name, mode string) error
	SignIn() (time.Time, error)
	List() ([]service.Status, error)
	Status(name string) (service.Status, error)
	Others(fresh bool) []service.Status
	Other(name string) (service.Status, bool)
	Changes() (<-chan struct{}, func())
}

type role int

const (
	roleNone   role = iota
	roleMember      // in the adit group: the daily commands
	roleRoot        // everything
)

// rootOnly are the commands a member of the group may not use: they add routes, delete tunnels,
// hand out private keys or choose when the Mac is protected by a kill switch.
var rootOnly = map[string]bool{api.CommandImport: true, api.CommandRemove: true, api.CommandExport: true, api.CommandKillSwitch: true, api.CommandLAN: true}

var needsName = map[string]bool{
	api.CommandStatus: true, api.CommandUp: true, api.CommandDown: true, api.CommandAutostart: true,
	api.CommandImport: true, api.CommandRemove: true, api.CommandExport: true, api.CommandKillSwitch: true, api.CommandLAN: true,
}

var known = map[string]bool{api.CommandList: true, api.CommandWatch: true, api.CommandVersion: true, api.CommandSignIn: true}

// readOnly requests are logged at debug level only: the tray asks often.
var readOnly = map[string]bool{api.CommandList: true, api.CommandStatus: true, api.CommandVersion: true, api.CommandWatch: true}

// Limits on what callers may hold, so a member of the group cannot exhaust aditd: connections at
// once, watchers per account, and the size of a request from anyone but root (whose imports carry
// a whole file).
const (
	maxConnections    = 64
	maxWatchersPerUID = 8
	maxMemberRequest  = 16 << 10
)

type Server struct {
	tunnels Tunnels
	version string
	log     *slog.Logger

	// authorize says who is calling; it asks the kernel in aditd and is replaced in tests.
	authorize func(conn *net.UnixConn) (role, int, error)
	// poll is how often a watch looks again for changes that come without a signal: handshakes.
	poll time.Duration
	// member says again whether a uid is in the adit group, for watches that last.
	member func(uid int) (bool, error)

	watchMu  sync.Mutex
	watchers map[int]int // uid → watches open
}

// New serves tunnels to root and to members of group; an empty group means root only.
func New(tunnels Tunnels, group, version string, log *slog.Logger) *Server {
	return &Server{
		tunnels:   tunnels,
		version:   version,
		log:       log,
		authorize: func(conn *net.UnixConn) (role, int, error) { return authorize(conn, group) },
		poll:      time.Second,
		member:    func(uid int) (bool, error) { return inGroup(uid, group) },
	}
}

func authorize(conn *net.UnixConn, group string) (role, int, error) {
	uid, err := peerUID(conn)
	if err != nil {
		return roleNone, -1, err
	}
	if uid == 0 {
		return roleRoot, uid, nil
	}
	member, err := inGroup(uid, group)
	if err != nil {
		return roleNone, uid, err
	}
	if member {
		return roleMember, uid, nil
	}
	return roleNone, uid, nil
}

// Serve answers connections until ctx ends, then waits for the ones in progress. An error that may
// pass (too many open files, a client that hung up) waits and tries again; any other ends Serve, so
// aditd exits and launchd starts it again, rather than living on deaf.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()

	slots := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	wait := 5 * time.Millisecond
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if temporary(err) {
				s.log.Warn("could not accept a connection; trying again", "error", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(wait):
				}
				wait = min(2*wait, time.Second)
				continue
			}
			return err
		}
		wait = 5 * time.Millisecond
		select {
		case slots <- struct{}{}:
			wg.Go(func() {
				defer func() { <-slots }()
				s.handle(ctx, conn)
			})
		default:
			s.reply(conn, json.NewEncoder(conn), failure(api.CodeFailed, "aditd is busy with too many connections; try again"))
			conn.Close()
		}
	}
}

func temporary(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.ECONNABORTED)
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	encoder := json.NewEncoder(conn)

	role, uid, err := s.authorize(conn)
	if err != nil {
		s.log.Warn("could not tell who is calling", "error", err)
		s.reply(conn, encoder, failure(api.CodeFailed, "aditd could not tell who is calling, so it refuses"))
		return
	}

	if role == roleNone {
		// Nothing is read from someone who may not use adit.
		s.log.Info("refused a caller outside the adit group", "uid", uid)
		s.reply(conn, encoder, failure(api.CodeNotAllowed, "you may not use adit: you are not in the adit group; an administrator can add you with sudo adit allow "+username(uid)))
		return
	}
	limit := int64(maxMemberRequest)
	if role == roleRoot {
		limit = api.MaxRequest
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req api.Request
	if err := json.NewDecoder(io.LimitReader(conn, limit)).Decode(&req); err != nil {
		s.reply(conn, encoder, failure(api.CodeBadRequest, "the request is not a JSON object aditd understands"))
		return
	}
	conn.SetReadDeadline(time.Time{})

	// Refuse what aditd does not know before logging it: a caller's strings go into root's log only
	// when they are a known command and a name short enough to be one.
	if !known[req.Command] && !needsName[req.Command] {
		s.reply(conn, encoder, failure(api.CodeBadRequest, "aditd does not know that command"))
		return
	}
	if len(req.Name) > 128 {
		s.reply(conn, encoder, failure(api.CodeBadRequest, "that name is too long to be a tunnel's"))
		return
	}
	log := s.log.With("command", req.Command, "uid", uid)
	if req.Name != "" {
		log = log.With("tunnel", req.Name)
	}
	var resp api.Response
	switch {
	case rootOnly[req.Command] && role != roleRoot:
		resp = failure(api.CodeNotAllowed, fmt.Sprintf("%s needs root: run it with sudo", req.Command))
	case req.Command == api.CommandWatch:
		if !s.startWatch(uid) {
			resp = failure(api.CodeFailed, fmt.Sprintf("this account already has %d watchers; close one first", maxWatchersPerUID))
			break
		}
		defer s.endWatch(uid)
		log.Debug("watching")
		s.watch(ctx, conn, encoder, uid, role)
		return
	default:
		resp = s.dispatch(ctx, req)
		resp = s.otherSoftware(req, resp)
	}

	switch {
	case resp.OK && readOnly[req.Command]:
		log.Debug("done")
	case resp.OK:
		log.Info("done")
	default:
		log.Info("refused", "code", resp.Error.Code, "reason", resp.Error.Message)
	}
	s.reply(conn, encoder, resp)
}

func (s *Server) dispatch(ctx context.Context, req api.Request) api.Response {
	switch {
	case !known[req.Command] && !needsName[req.Command]:
		return failure(api.CodeBadRequest, fmt.Sprintf("aditd does not know the command %q", req.Command))
	case needsName[req.Command] && req.Name == "":
		return failure(api.CodeBadRequest, fmt.Sprintf("%s needs a tunnel name", req.Command))
	}

	switch req.Command {
	case api.CommandVersion:
		return api.Response{OK: true, Version: s.version}

	case api.CommandList:
		statuses, err := s.tunnels.List()
		if err != nil {
			return fail(err)
		}
		return api.Response{OK: true, Tunnels: toAPI(statuses), Others: toAPI(s.tunnels.Others(true))}

	case api.CommandStatus:
		return s.tunnel(req.Name)

	case api.CommandUp:
		ctx, cancel := context.WithTimeout(ctx, upTimeout)
		defer cancel()
		if err := s.tunnels.Up(ctx, req.Name); err != nil {
			return fail(err)
		}
		return s.tunnel(req.Name)

	case api.CommandDown:
		if err := s.tunnels.Down(req.Name); err != nil {
			return fail(err)
		}
		return s.tunnel(req.Name)

	case api.CommandAutostart:
		if req.On == nil {
			return failure(api.CodeBadRequest, "autostart needs on or off")
		}
		if err := s.tunnels.SetAutostart(req.Name, *req.On); err != nil {
			return fail(err)
		}
		return s.tunnel(req.Name)

	case api.CommandKillSwitch:
		if err := s.tunnels.SetKillSwitch(req.Name, req.Mode); err != nil {
			return fail(err)
		}
		return s.tunnel(req.Name)

	case api.CommandLAN:
		if err := s.tunnels.SetLAN(req.Name, req.Mode); err != nil {
			return fail(err)
		}
		return s.tunnel(req.Name)

	case api.CommandSignIn:
		until, err := s.tunnels.SignIn()
		if err != nil {
			return fail(err)
		}
		until = until.UTC()
		return api.Response{OK: true, Until: &until}

	case api.CommandImport:
		warnings, err := s.tunnels.Import(req.Name, []byte(req.File))
		if err != nil {
			return fail(err)
		}
		resp := s.tunnel(req.Name)
		resp.Warnings = warnings
		return resp

	case api.CommandRemove:
		if err := s.tunnels.Remove(req.Name); err != nil {
			return fail(err)
		}
		return api.Response{OK: true}

	case api.CommandExport:
		file, err := s.tunnels.File(req.Name)
		if err != nil {
			return fail(err)
		}
		return api.Response{OK: true, File: string(file)}

	default:
		return failure(api.CodeBadRequest, "aditd does not know that command")
	}
}

// otherSoftware answers for another program's tunnel when the name is not adit's: status shows
// it, and every change is refused with the program to use instead.
func (s *Server) otherSoftware(req api.Request, resp api.Response) api.Response {
	if resp.OK || resp.Error.Code != api.CodeNotFound {
		return resp
	}
	other, found := s.tunnels.Other(req.Name)
	if !found {
		return resp
	}
	if req.Command == api.CommandStatus {
		tunnel := toAPI([]service.Status{other})[0]
		return api.Response{OK: true, Tunnel: &tunnel}
	}
	owner, use := "wg-quick's", "wg-quick"
	if other.Source == "WireGuard app" {
		owner, use = "the WireGuard app's", "the WireGuard app"
	}
	return failure(api.CodeFailed, fmt.Sprintf("%s is %s tunnel: adit shows it but does not change it; use %s", req.Name, owner, use))
}

func (s *Server) tunnel(name string) api.Response {
	status, err := s.tunnels.Status(name)
	if err != nil {
		return fail(err)
	}
	tunnel := toAPI([]service.Status{status})[0]
	return api.Response{OK: true, Tunnel: &tunnel}
}

// watch sends every tunnel now and again whenever something a person would see changes: byte
// counters alone do not count, or a busy tunnel would send every second.
func (s *Server) watch(ctx context.Context, conn *net.UnixConn, encoder *json.Encoder, uid int, role role) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		io.Copy(io.Discard, conn) // returns when the watcher hangs up
		cancel()
	}()

	changes, stop := s.tunnels.Changes()
	defer stop()
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()

	// A caller taken out of the adit group stops being served within a minute.
	recheck := time.NewTicker(time.Minute)
	defer recheck.Stop()

	var last, lastOthers []api.Tunnel
	for first := true; ; first = false {
		statuses, err := s.tunnels.List()
		if err != nil {
			s.reply(conn, encoder, fail(err))
			return
		}
		tunnels, others := toAPI(statuses), toAPI(s.tunnels.Others(false))
		if first || !sameView(last, tunnels) || !sameView(lastOthers, others) {
			if err := s.reply(conn, encoder, api.Response{OK: true, Tunnels: tunnels, Others: others}); err != nil {
				return
			}
			last, lastOthers = tunnels, others
		}

		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-ticker.C:
		case <-recheck.C:
			if role != roleRoot {
				if member, err := s.member(uid); err != nil || !member {
					s.reply(conn, encoder, failure(api.CodeNotAllowed, "you are no longer in the adit group"))
					return
				}
			}
		}
	}
}

// startWatch counts a watcher for uid, and says whether it may have one more.
func (s *Server) startWatch(uid int) bool {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watchers[uid] >= maxWatchersPerUID {
		return false
	}
	if s.watchers == nil {
		s.watchers = map[int]int{}
	}
	s.watchers[uid]++
	return true
}

func (s *Server) endWatch(uid int) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watchers[uid]--; s.watchers[uid] <= 0 {
		delete(s.watchers, uid)
	}
}

func sameView(a, b []api.Tunnel) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		x, y := a[n], b[n]
		if x.Name != y.Name || x.State != y.State || x.Autostart != y.Autostart || x.KillSwitch != y.KillSwitch || x.Blocking != y.Blocking || x.LAN != y.LAN || x.Interface != y.Interface ||
			!slices.Equal(x.Notes, y.Notes) ||
			(x.LastHandshake == nil) != (y.LastHandshake == nil) ||
			(x.LastHandshake != nil && !x.LastHandshake.Equal(*y.LastHandshake)) {
			return false
		}
	}
	return true
}

func (s *Server) reply(conn *net.UnixConn, encoder *json.Encoder, resp api.Response) error {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return encoder.Encode(resp)
}

func toAPI(statuses []service.Status) []api.Tunnel {
	tunnels := make([]api.Tunnel, len(statuses))
	for n, status := range statuses {
		tunnels[n] = api.Tunnel{
			Name:          status.Name,
			State:         string(status.State),
			Autostart:     status.Autostart,
			KillSwitch:    status.KillSwitch,
			Blocking:      status.Blocking,
			LAN:           status.LAN,
			Interface:     status.Interface,
			ReceivedBytes: status.Received,
			SentBytes:     status.Sent,
			Notes:         status.Notes,
			Source:        status.Source,
			ReadOnly:      status.ReadOnly,
		}
		if !status.LastHandshake.IsZero() {
			handshake := status.LastHandshake.UTC()
			tunnels[n].LastHandshake = &handshake
		}
	}
	return tunnels
}

func failure(code api.Code, message string) api.Response {
	return api.Response{Error: &api.Error{Code: code, Message: message}}
}

func fail(err error) api.Response {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return failure(api.CodeNotFound, err.Error())
	case errors.Is(err, service.ErrConflict):
		return failure(api.CodeConflict, err.Error())
	}
	return failure(api.CodeFailed, err.Error())
}
