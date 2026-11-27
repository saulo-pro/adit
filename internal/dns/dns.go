// Package dns gives each tunnel its own DNS on macOS: for every domain on a tunnel's DNS line, a file
// in /etc/resolver sends the names under that domain to the tunnel's servers, and every other name
// goes where it went before.
//
// adit marks each file it writes with the tunnel's name on its first line, removes only files that
// carry its mark, and never replaces a file someone else wrote.
package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const DefaultDir = "/etc/resolver"

const (
	markPrefix = "# Written by adit for the tunnel "
	markSuffix = "; adit removes it when the tunnel goes down."
)

// ErrNotOurs is matched with errors.Is when a resolver file adit would write already exists and
// is not adit's.
var ErrNotOurs = errors.New("resolver file not written by adit")

type notOurs struct{ msg string }

func (e *notOurs) Error() string { return e.msg }
func (e *notOurs) Unwrap() error { return ErrNotOurs }

type Resolvers struct {
	Dir string
}

// fileName is the resolver file for domain: macOS matches it without a final dot.
func fileName(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// Overlap says whether two domains share names: one is the other, or lies under it. macOS sends a
// name to the most specific resolver file, so a tunnel claiming a sub-domain of another's domain
// would take those names from it.
func Overlap(a, b string) bool {
	a, b = fileName(a), fileName(b)
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// maxServers is how many servers a resolver file lists: macOS asks no more than three.
const maxServers = 3

// Check refuses domains whose resolver file exists and does not carry tunnel's mark: someone else
// wrote it, or another adit tunnel did. It also refuses a domain above or below one another
// resolver file covers, adit's or not.
func (r *Resolvers) Check(tunnel string, domains []string) error {
	if entries, err := os.ReadDir(r.Dir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".") || !entry.Type().IsRegular() {
				continue
			}
			for _, domain := range domains {
				if fileName(domain) == name || !Overlap(domain, name) {
					continue
				}
				owner, err := r.owner(filepath.Join(r.Dir, name))
				switch {
				case err != nil || owner == tunnel:
				case owner == "":
					return &notOurs{fmt.Sprintf("%s already sends names under %s to other servers, and %s overlaps it; take %s off %s's DNS line", filepath.Join(r.Dir, name), name, domain, domain, tunnel)}
				default:
					return &notOurs{fmt.Sprintf("the tunnel %s resolves %s, which overlaps %s", owner, name, domain)}
				}
			}
		}
	}
	for _, domain := range domains {
		path := filepath.Join(r.Dir, fileName(domain))
		owner, err := r.owner(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		case owner == "":
			return &notOurs{fmt.Sprintf("%s exists and adit did not write it; remove it, or take %s off %s's DNS line", path, domain, tunnel)}
		case owner != tunnel:
			return &notOurs{fmt.Sprintf("%s belongs to the tunnel %s, which resolves %s already", path, owner, domain)}
		}
	}
	return nil
}

// Set writes one resolver file per domain, each naming every server.
func (r *Resolvers) Set(tunnel string, servers []netip.Addr, domains []string) error {
	if len(servers) == 0 || len(domains) == 0 {
		return nil
	}
	if err := r.Check(tunnel, domains); err != nil {
		return err
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return err
	}
	if err := r.Clear(tunnel); err != nil { // its own files from before, if any
		return err
	}

	var content strings.Builder
	content.WriteString(markPrefix + tunnel + markSuffix + "\n")
	for _, server := range servers[:min(len(servers), maxServers)] {
		fmt.Fprintf(&content, "nameserver %s\n", server)
	}
	for _, domain := range domains {
		// World-readable: mDNSResponder reads it as its own user.
		if err := writeFile(filepath.Join(r.Dir, fileName(domain)), content.String(), 0o644); err != nil {
			r.Clear(tunnel)
			return err
		}
	}
	return nil
}

// Clear removes the files carrying tunnel's mark, and no others.
func (r *Resolvers) Clear(tunnel string) error {
	return r.remove(func(owner string) bool { return owner == tunnel })
}

// ClearAll removes every file adit wrote: at aditd's start, none of its tunnels is up, so any such
// file was left by an aditd that stopped without cleaning up.
func (r *Resolvers) ClearAll() error {
	return r.remove(func(owner string) bool { return owner != "" })
}

func (r *Resolvers) remove(match func(owner string) bool) error {
	entries, err := os.ReadDir(r.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(r.Dir, entry.Name())
		if owner, err := r.owner(path); err == nil && match(owner) {
			errs = append(errs, os.Remove(path))
		}
	}
	return errors.Join(errs...)
}

// owner reads the tunnel named in a file's mark, or "" when it carries none.
func (r *Resolvers) owner(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && line == "" {
		return "", nil
	}
	rest, found := strings.CutPrefix(strings.TrimSuffix(line, "\n"), markPrefix)
	if !found {
		return "", nil
	}
	name, _, found := strings.Cut(rest, markSuffix)
	if !found {
		return "", nil
	}
	return name, nil
}

// writeFile creates path with content, never over an existing file.
func writeFile(path, content string, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".adit-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.WriteString(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(temp.Name(), path); errors.Is(err, fs.ErrExist) {
		return &notOurs{fmt.Sprintf("%s appeared while adit was writing it; adit will not replace it", path)}
	} else {
		return err
	}
}
