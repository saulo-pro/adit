package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/install"
)

// installer puts aditd on the Mac and takes it off: install.Installer, a fake in tests.
type installer interface {
	Install(o install.Options, out io.Writer) error
	Uninstall(keepTunnels bool, uid int, out io.Writer) error
	Allow(user string) error
	Disallow(user string) error
	Installed() bool
}

func needsRoot(c *CLI, command string) error {
	if c.euid() != 0 {
		return &api.Error{Code: api.CodeNotAllowed, Message: command + " needs root: run it with sudo"}
	}
	return nil
}

// install copies the aditd that came with this adit into a place only root can change, and starts
// it, now and at every boot. The person who ran sudo joins the adit group.
func (c *CLI) install(ctx context.Context, out *output, args []string) error {
	flags := newFlags("install")
	source := flags.String("aditd", "", "")
	if _, err := parse(out, flags, args, 0, 0, "[--aditd PATH]"); err != nil {
		return err
	}
	if err := needsRoot(c, "install"); err != nil {
		return err
	}
	self, err := c.executable()
	if err != nil {
		return err
	}
	resolved := self
	if r, err := filepath.EvalSymlinks(self); err == nil {
		resolved = r // Homebrew links bin/adit into the Cellar, where aditd sits beside it
	}
	if *source == "" {
		*source = filepath.Join(filepath.Dir(resolved), "aditd")
	}
	// The icon runs as the person, so it may stay in Homebrew's bin: its link there survives upgrades.
	tray := ""
	for _, dir := range []string{filepath.Dir(self), filepath.Dir(resolved)} {
		if c.exists(filepath.Join(dir, "adit-tray")) {
			tray = filepath.Join(dir, "adit-tray")
			break
		}
	}
	version, err := c.runVersion(*source)
	if err != nil {
		return fmt.Errorf("there is no aditd to install at %s; give its path with --aditd", *source)
	}
	if version != c.Version {
		return fmt.Errorf("the aditd at %s is version %s but this adit is %s; install the pair from one build", *source, version, c.Version)
	}

	var progress strings.Builder
	user := c.Getenv("SUDO_USER")
	uid, _ := strconv.Atoi(c.Getenv("SUDO_UID"))
	if tray == "" {
		progress.WriteString("No adit-tray beside adit, so no menu bar icon.\n")
	}
	if err := c.installer.Install(install.Options{Aditd: *source, Tray: tray, User: user, UID: uid}, &progress); err != nil {
		return err
	}
	running, err := c.waitForAditd(ctx)
	if err != nil {
		return fmt.Errorf("aditd was installed but does not answer; its log is %s", install.Log)
	}

	words := progress.String() + fmt.Sprintf("aditd %s is running, and starts whenever the Mac does.\n", running)
	if user != "" {
		words += fmt.Sprintf("%s can now use adit without sudo, except to import, export and remove tunnels.\n", user)
	}
	c.print(out, map[string]any{"installed": install.Binary, "aditd": running, "group_member": user, "done": lines(progress.String())}, words)
	return nil
}

func (c *CLI) waitForAditd(ctx context.Context) (string, error) {
	deadline := time.Now().Add(c.aditdWait)
	for {
		resp, err := c.Client.Do(ctx, api.Request{Command: api.CommandVersion})
		if err == nil {
			return resp.Version, nil
		}
		if time.Now().After(deadline) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// uninstall removes everything install made. Every tunnel and its keys go too, unless
// --keep-tunnels: the brief's uninstall leaves no key behind. It asks first, or takes --yes.
func (c *CLI) uninstall(ctx context.Context, out *output, args []string) error {
	flags := newFlags("uninstall")
	yes := flags.Bool("yes", false, "")
	keep := flags.Bool("keep-tunnels", false, "")
	if _, err := parse(out, flags, args, 0, 0, "[--keep-tunnels] [--yes]"); err != nil {
		return err
	}
	if err := needsRoot(c, "uninstall"); err != nil {
		return err
	}

	if !*yes {
		what := "every tunnel and its keys"
		if *keep {
			what = "nothing else: the tunnels and their keys stay"
		}
		if !c.isTerminal() {
			return usageError("uninstall removes aditd, the adit group and %s; confirm with --yes", what)
		}
		fmt.Fprintf(c.Stderr, "This stops aditd and removes it, its LaunchDaemon, the adit group and %s.\nType yes to go on: ", what)
		answer, _ := bufio.NewReader(c.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("nothing was removed")
		}
	}

	var progress strings.Builder
	uid, _ := strconv.Atoi(c.Getenv("SUDO_UID"))
	if err := c.installer.Uninstall(*keep, uid, &progress); err != nil {
		return err
	}
	words := progress.String() + "adit is uninstalled.\n"
	if progress.Len() == 0 {
		words = "adit was not installed; there was nothing to remove.\n"
	}
	c.print(out, map[string]any{"removed": lines(progress.String())}, words)
	return nil
}

func (c *CLI) allow(ctx context.Context, out *output, args []string) error {
	return c.membership(out, args, "allow", (installer).Allow, "%s can now use adit without sudo, except to import, export and remove tunnels.\n")
}

func (c *CLI) disallow(ctx context.Context, out *output, args []string) error {
	return c.membership(out, args, "disallow", (installer).Disallow, "%s can no longer use adit without sudo.\n")
}

func (c *CLI) membership(out *output, args []string, command string, change func(installer, string) error, words string) error {
	names, err := parse(out, newFlags(command), args, 1, 1, "USER")
	if err != nil {
		return err
	}
	if err := needsRoot(c, command); err != nil {
		return err
	}
	if err := c.lookupUser(names[0]); err != nil {
		return fmt.Errorf("there is no user named %s on this Mac", names[0])
	}
	if err := change(c.installer, names[0]); err != nil {
		return err
	}
	c.print(out, map[string]any{command: names[0]}, fmt.Sprintf(words, names[0]))
	return nil
}

func lines(s string) []string {
	result := []string{}
	for line := range strings.Lines(s) {
		result = append(result, strings.TrimSuffix(line, "\n"))
	}
	return result
}
