// Package store keeps adit's tunnels on disk, in a directory only its owner can read: aditd runs as
// root, so only root can read the private keys.
//
// Each tunnel is NAME.conf, the file exactly as imported, so that export gives it back unchanged,
// comments included; and NAME.json, adit's own settings for it, absent while they are the defaults.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/saulo-pro/adit/internal/conf"
)

// ErrNotFound and ErrExists are matched with errors.Is; the errors carrying them name the tunnel.
var (
	ErrNotFound = errors.New("no such tunnel")
	ErrExists   = errors.New("tunnel already exists")
)

type tunnelError struct {
	kind error
	msg  string
}

func (e *tunnelError) Error() string { return e.msg }
func (e *tunnelError) Unwrap() error { return e.kind }

func notFound(name string) error {
	return &tunnelError{ErrNotFound, fmt.Sprintf("there is no tunnel named %s", name)}
}

// Settings are adit's own, kept beside the WireGuard file.
type Settings struct {
	Autostart bool `json:"autostart"`
}

// Tunnel is a stored tunnel. Its file's text stays on disk; File reads it for export.
type Tunnel struct {
	Name     string
	Config   *conf.Config
	Settings Settings
}

type Store struct {
	dir string
}

// Open opens the store at dir, creating it if needed. It refuses a directory other users can read
// or that someone else owns, since it holds private keys.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("the tunnel store %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the tunnel store %s can be read by other users; it must be mode 0700", dir)
	}
	if !ownedByMe(info) {
		return nil, fmt.Errorf("the tunnel store %s belongs to another user", dir)
	}
	return &Store{dir: dir}, nil
}

// ValidName checks a tunnel name: it becomes a file name, and is shown in the menu bar.
func ValidName(name string) error {
	valid := len(name) >= 1 && len(name) <= 32 && isAlphanumeric(rune(name[0]))
	for _, r := range name {
		valid = valid && (isAlphanumeric(r) || r == '.' || r == '-' || r == '_')
	}
	if !valid {
		return fmt.Errorf("%q is not a valid tunnel name: use 1 to 32 letters, digits, dots, hyphens and underscores, starting with a letter or digit", name)
	}
	return nil
}

func isAlphanumeric(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// Add stores a tunnel from a file's text, which must parse. Names are unique regardless of case,
// as file names are on macOS.
func (s *Store) Add(name string, text []byte) (*Tunnel, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	config, err := conf.Parse(text)
	if err != nil {
		return nil, err
	}
	if existing, err := s.find(name); err != nil {
		return nil, err
	} else if existing != "" {
		return nil, &tunnelError{ErrExists, fmt.Sprintf("a tunnel named %s already exists", existing)}
	}
	if err := s.write(name+".conf", text, false); err != nil {
		return nil, err
	}
	return &Tunnel{Name: name, Config: config}, nil
}

// List returns every stored tunnel, sorted by name.
func (s *Store) List() ([]*Tunnel, error) {
	names, err := s.names()
	if err != nil {
		return nil, err
	}
	tunnels := make([]*Tunnel, 0, len(names))
	for _, name := range names {
		tunnel, err := s.load(name)
		if err != nil {
			return nil, err
		}
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, nil
}

// Get returns one tunnel; the name matches regardless of case.
func (s *Store) Get(name string) (*Tunnel, error) {
	stored, err := s.find(name)
	if err != nil {
		return nil, err
	}
	if stored == "" {
		return nil, notFound(name)
	}
	return s.load(stored)
}

// File returns the tunnel's file as it was imported, private key included: for export only.
func (s *Store) File(name string) ([]byte, error) {
	stored, err := s.find(name)
	if err != nil {
		return nil, err
	}
	if stored == "" {
		return nil, notFound(name)
	}
	return os.ReadFile(filepath.Join(s.dir, stored+".conf"))
}

// SetSettings replaces a tunnel's settings.
func (s *Store) SetSettings(name string, settings Settings) error {
	stored, err := s.find(name)
	if err != nil {
		return err
	}
	if stored == "" {
		return notFound(name)
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return s.write(stored+".json", append(data, '\n'), true)
}

// Remove deletes a tunnel's file and settings.
func (s *Store) Remove(name string) error {
	stored, err := s.find(name)
	if err != nil {
		return err
	}
	if stored == "" {
		return notFound(name)
	}
	if err := os.Remove(filepath.Join(s.dir, stored+".json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Remove(filepath.Join(s.dir, stored+".conf"))
}

func (s *Store) names() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".conf"); ok && entry.Type().IsRegular() && ValidName(name) == nil {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return names, nil
}

// find returns the stored spelling of name, or "" when there is no such tunnel.
func (s *Store) find(name string) (string, error) {
	names, err := s.names()
	if err != nil {
		return "", err
	}
	for _, stored := range names {
		if strings.EqualFold(stored, name) {
			return stored, nil
		}
	}
	return "", nil
}

func (s *Store) load(name string) (*Tunnel, error) {
	text, err := os.ReadFile(filepath.Join(s.dir, name+".conf"))
	if err != nil {
		return nil, err
	}
	config, err := conf.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("the stored file of tunnel %s no longer parses: %w", name, err)
	}

	tunnel := &Tunnel{Name: name, Config: config}
	settings, err := os.ReadFile(filepath.Join(s.dir, name+".json"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(settings, &tunnel.Settings); err != nil {
			return nil, fmt.Errorf("the settings of tunnel %s are damaged: %w", name, err)
		}
	}
	return tunnel, nil
}

// write puts a file in place atomically, readable by the owner only. Without replace it refuses to
// overwrite, so two imports under one name cannot both win.
func (s *Store) write(name string, data []byte, replace bool) error {
	temp, err := os.CreateTemp(s.dir, ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	final := filepath.Join(s.dir, name)
	if replace {
		return os.Rename(temp.Name(), final)
	}
	if err := os.Link(temp.Name(), final); errors.Is(err, fs.ErrExist) {
		return &tunnelError{ErrExists, fmt.Sprintf("a tunnel named %s already exists", strings.TrimSuffix(name, ".conf"))}
	} else {
		return err
	}
}
