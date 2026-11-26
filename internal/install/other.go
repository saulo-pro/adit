//go:build !darwin

// Package install puts aditd on the system; only macOS is done so far.
package install

import (
	"errors"
	"io"
	"time"
)

const (
	Store  = "/var/db/adit"
	Binary = ""
	Log    = ""
)

var errUnsupported = errors.New("adit installs only on macOS for now")

type Installer struct {
	Root string
	Wait time.Duration
}

func New() *Installer { return &Installer{} }

type Options struct {
	Aditd, Tray, User string
	UID               int
}

func (i *Installer) Install(o Options, out io.Writer) error                   { return errUnsupported }
func (i *Installer) Uninstall(keepTunnels bool, uid int, out io.Writer) error { return errUnsupported }
func (i *Installer) Allow(user string) error                                  { return errUnsupported }
func (i *Installer) Disallow(user string) error                               { return errUnsupported }
func (i *Installer) Installed() bool                                          { return false }
