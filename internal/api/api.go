// Package api is how the command line and the tray talk to aditd: over a Unix socket, one JSON
// request per connection and one JSON response per line. A watch request keeps the connection
// open and gets a new response, with every tunnel, whenever something a person would see changes.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

const DefaultSocket = "/var/run/adit/aditd.sock"

// Commands. The first group is open to members of the adit group; the second needs root.
const (
	CommandList      = "list"
	CommandStatus    = "status"
	CommandUp        = "up"
	CommandDown      = "down"
	CommandAutostart = "autostart"
	CommandWatch     = "watch"
	CommandVersion   = "version"

	CommandImport = "import"
	CommandRemove = "remove"
	CommandExport = "export"
)

// MaxRequest bounds what aditd reads from one caller: an imported file is at most 1 MiB, and JSON
// may double it.
const MaxRequest = 4 << 20

type Request struct {
	Command string `json:"command"`
	Name    string `json:"name,omitempty"`
	File    string `json:"file,omitempty"` // import: the file's text, never a path
	On      *bool  `json:"on,omitempty"`   // autostart
}

type Response struct {
	OK       bool     `json:"ok"`
	Error    *Error   `json:"error,omitempty"`
	Tunnels  []Tunnel `json:"tunnels,omitempty"`  // list and watch
	Others   []Tunnel `json:"others,omitempty"`   // list and watch: other software's tunnels, read-only
	Tunnel   *Tunnel  `json:"tunnel,omitempty"`   // status, up, down, autostart, import
	Warnings []string `json:"warnings,omitempty"` // import
	File     string   `json:"file,omitempty"`     // export: holds the private key
	Version  string   `json:"version,omitempty"`
}

type Tunnel struct {
	Name          string     `json:"name"`
	State         string     `json:"state"` // down, connecting, up or idle
	Autostart     bool       `json:"autostart"`
	Interface     string     `json:"interface,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	ReceivedBytes uint64     `json:"received_bytes"`
	SentBytes     uint64     `json:"sent_bytes"`
	Notes         []string   `json:"notes,omitempty"`     // what a person should know, one sentence each
	Source        string     `json:"source,omitempty"`    // "adit", "wg-quick" or "WireGuard app"
	ReadOnly      bool       `json:"read_only,omitempty"` // another program's: adit shows it and leaves it alone
}

type Code string

const (
	CodeFailed      Code = "failed"
	CodeBadRequest  Code = "bad_request"
	CodeUnreachable Code = "unreachable"
	CodeNotAllowed  Code = "not_allowed"
	CodeNotFound    Code = "not_found"
	CodeConflict    Code = "conflict"
)

// ExitCode is the command line's exit status for an error of this kind.
func (c Code) ExitCode() int {
	switch c {
	case CodeBadRequest:
		return 2
	case CodeUnreachable:
		return 3
	case CodeNotAllowed:
		return 4
	case CodeNotFound:
		return 5
	case CodeConflict:
		return 6
	default:
		return 1
	}
}

// Error is a refusal or failure, said in one sentence a person can act on.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

// Client talks to aditd.
type Client struct {
	Socket string
}

// Do sends one request and returns its response, or an *Error.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, unreachable(err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, unreachable(err)
	}
	if !resp.OK {
		return nil, resp.err()
	}
	return &resp, nil
}

// Watch calls seen with every tunnel, adit's and other software's, now and again whenever something
// changes, until ctx ends, seen returns an error, or aditd goes away.
func (c *Client) Watch(ctx context.Context, seen func(tunnels, others []Tunnel) error) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := json.NewEncoder(conn).Encode(Request{Command: CommandWatch}); err != nil {
		return unreachable(err)
	}
	decoder := json.NewDecoder(bufio.NewReader(conn))
	for {
		var resp Response
		if err := decoder.Decode(&resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return unreachable(err)
		}
		if !resp.OK {
			return resp.err()
		}
		if err := seen(resp.Tunnels, resp.Others); err != nil {
			return err
		}
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	socket := c.Socket
	if socket == "" {
		socket = DefaultSocket
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	switch {
	case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		return nil, &Error{CodeNotAllowed, "you may not use adit: you are not in the adit group; an administrator can add you with sudo adit allow " + currentUser()}
	case err != nil:
		return nil, &Error{CodeUnreachable, "aditd is not running or not installed; install it with sudo adit install"}
	}
	return conn, nil
}

func unreachable(err error) error {
	if errors.Is(err, io.EOF) {
		return &Error{CodeUnreachable, "aditd closed the connection without answering"}
	}
	return &Error{CodeUnreachable, fmt.Sprintf("the connection to aditd failed: %v", err)}
}

func (r *Response) err() error {
	if r.Error == nil {
		return &Error{CodeFailed, "aditd refused the request without saying why"}
	}
	return r.Error
}
