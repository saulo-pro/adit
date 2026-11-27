// Package cli is the adit command: a client of aditd for people and for scripts. Every command
// answers in plain words, or in JSON with --json, and its exit status says what happened:
// 0 done, 1 failed, 2 wrong usage, 3 aditd not reachable, 4 not allowed, 5 no such tunnel,
// 6 refused because of a conflict.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
	"unicode"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/install"
)

const usage = `adit keeps several WireGuard tunnels up at once.

Usage:
  adit list                        every tunnel and its state
  adit status [NAME]               state, last handshake, bytes received and sent
  adit up NAME                     bring a tunnel up
  adit down NAME                   take a tunnel down
  adit autostart NAME on|off       whether it comes up when the Mac starts
  sudo adit import FILE [--name NAME]
                                   add a tunnel from a WireGuard .conf file
  sudo adit export NAME --output FILE
                                   write a tunnel's file, readable only by you
  sudo adit remove NAME            delete a tunnel
  sudo adit install [--aditd PATH] install aditd, start it now and at every boot,
                                   and let you use adit without a password
  sudo adit uninstall [--keep-tunnels] [--yes]
                                   remove aditd, the adit group and, unless kept,
                                   every tunnel and its keys
  sudo adit allow USER             let USER use adit without a password
  sudo adit disallow USER
  adit version

Every command takes --json, for scripts.

Exit status: 0 done, 1 failed, 2 wrong usage, 3 aditd not reachable,
4 not allowed, 5 no such tunnel, 6 refused because of a conflict.
`

const exitUsage = 2

type CLI struct {
	Client  *api.Client
	Version string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Now     func() time.Time

	// upWait is how long up waits for a first handshake before answering.
	upWait time.Duration
	// chown hands an exported file to the person who ran sudo; euid says whether adit runs as root.
	chown func(file *os.File, uid, gid int) error
	euid  func() int

	// The system around adit, for install and friends; fakes in tests.
	installer  installer
	executable func() (string, error)
	runVersion func(aditd string) (string, error)
	lookupUser func(name string) error
	isTerminal func() bool
	exists     func(path string) bool
	// stage copies aditd and the tray (if any) into a folder only root can change, for checking
	// and installing; writableByOthers names a file or folder on a path that an account other than
	// root may change, or "".
	stage            func(aditd, tray string) ([2]string, func(), error)
	writableByOthers func(path string) string
	aditdWait        time.Duration
}

type command func(c *CLI, ctx context.Context, out *output, args []string) error

var commands = map[string]command{
	"list":      (*CLI).list,
	"status":    (*CLI).status,
	"up":        (*CLI).up,
	"down":      (*CLI).down,
	"autostart": (*CLI).autostart,
	"import":    (*CLI).importFile,
	"export":    (*CLI).export,
	"remove":    (*CLI).remove,
	"version":   (*CLI).version,
	"install":   (*CLI).install,
	"uninstall": (*CLI).uninstall,
	"allow":     (*CLI).allow,
	"disallow":  (*CLI).disallow,
}

// Run runs one command and returns its exit status.
func (c *CLI) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		io.WriteString(c.Stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		io.WriteString(c.Stdout, usage)
		return 0
	}

	run, known := commands[args[0]]
	if !known {
		return c.fail(&output{}, usageError("adit has no command %q", args[0]))
	}
	out := &output{name: args[0]}
	if err := run(c, ctx, out, args[1:]); err != nil {
		return c.fail(out, err)
	}
	return 0
}

// output is how one command answers: in words, or in JSON when asked.
type output struct {
	name string
	json bool
}

func (c *CLI) print(out *output, value any, words string) {
	if out.json {
		encoder := json.NewEncoder(c.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(value)
		return
	}
	io.WriteString(c.Stdout, safeForTerminal(words))
}

// safeForTerminal escapes characters a terminal would act on or hide (C0 and C1 controls but tab and
// newline, DEL, Unicode format characters), so text from aditd, from a configuration file or from
// another program cannot move the cursor, rewrite a line or hide a word.
func safeForTerminal(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafeRune(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Cf, r))
}

// fail reports err and returns the exit status for it. In JSON mode the error goes to standard
// output as {"error": {"code", "message"}}, where a script is already reading.
func (c *CLI) fail(out *output, err error) int {
	var usage *usageErr
	isUsage := errors.As(err, &usage)
	var apiErr *api.Error
	switch {
	case isUsage:
		apiErr = &api.Error{Code: api.CodeBadRequest, Message: usage.message}
	case !errors.As(err, &apiErr):
		apiErr = &api.Error{Code: api.CodeFailed, Message: err.Error()}
	}

	if out.json {
		c.print(out, map[string]any{"error": apiErr}, "")
	} else {
		fmt.Fprintf(c.Stderr, "adit: %s\n", safeForTerminal(apiErr.Message))
		if isUsage {
			fmt.Fprintln(c.Stderr, "Run adit help for usage.")
		}
	}
	return apiErr.Code.ExitCode()
}

// usageErr is a command typed wrong: exit status 2, with a pointer to the usage.
type usageErr struct {
	message string
}

func (e *usageErr) Error() string {
	return e.message
}

func usageError(format string, args ...any) error {
	return &usageErr{message: fmt.Sprintf(format, args...)}
}

// parse reads flags wherever they are among the arguments, as people type them (adit status work
// --json), and checks the number of the rest.
func parse(out *output, flags *flag.FlagSet, args []string, min, max int, shape string) ([]string, error) {
	flags.SetOutput(io.Discard)
	flags.BoolVar(&out.json, "json", false, "")
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, usageError("%s: %v", out.name, err)
		}
		args = flags.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	if len(positional) < min || len(positional) > max {
		return nil, usageError("usage: adit %s %s", out.name, shape)
	}
	return positional, nil
}

func newFlags(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// New is the command line as people run it. ADIT_SOCKET points it at another aditd, for testing;
// under sudo adit talks only to an aditd running as root, wherever the socket is.
func New(version string, stdin io.Reader, stdout, stderr io.Writer) *CLI {
	return &CLI{
		Client:  &api.Client{Socket: os.Getenv("ADIT_SOCKET"), RootPeer: os.Geteuid() == 0},
		Version: version,
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
		Getenv:  os.Getenv,
		Now:     time.Now,
		upWait:  3 * time.Second,
		chown:   (*os.File).Chown,
		euid:    os.Geteuid,

		installer:  install.New(),
		executable: os.Executable,
		runVersion: func(aditd string) (string, error) {
			output, err := exec.Command(aditd, "-version").Output()
			return strings.TrimSpace(string(output)), err
		},
		lookupUser: func(name string) error {
			_, err := user.Lookup(name)
			return err
		},
		isTerminal: func() bool {
			info, err := os.Stdin.Stat()
			return err == nil && info.Mode()&os.ModeCharDevice != 0
		},
		aditdWait: 15 * time.Second,
		exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		stage:            stageCopies,
		writableByOthers: writableByOthers,
	}
}
