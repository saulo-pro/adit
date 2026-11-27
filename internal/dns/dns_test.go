package dns

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var servers = []netip.Addr{netip.MustParseAddr("10.99.1.1"), netip.MustParseAddr("fd00:99:1::1")}

func TestSetWritesOneMarkedFilePerDomain(t *testing.T) {
	r := resolvers(t)
	if err := r.Set("work", servers, []string{"corp.example", "Lab.Example."}); err != nil {
		t.Fatal(err)
	}
	want := "# Written by adit for the tunnel work; adit removes it when the tunnel goes down.\n" +
		"nameserver 10.99.1.1\n" +
		"nameserver fd00:99:1::1\n"
	for _, name := range []string{"corp.example", "lab.example"} {
		path := filepath.Join(r.Dir, name)
		content, err := os.ReadFile(path)
		if err != nil || string(content) != want {
			t.Errorf("%s: %q, %v", name, content, err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
			t.Errorf("%s has mode %o; mDNSResponder must be able to read it", name, info.Mode().Perm())
		}
	}
}

func TestSetAgainReplacesOnlyItsOwnFiles(t *testing.T) {
	r := resolvers(t)
	if err := r.Set("work", servers, []string{"corp.example"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("work", servers[:1], []string{"corp.example"}); err != nil {
		t.Errorf("setting it again failed: %v", err)
	}
}

func TestNothingToWriteWithoutServersOrDomains(t *testing.T) {
	r := resolvers(t)
	r.Set("work", nil, []string{"corp.example"})
	r.Set("work", servers, nil)
	if _, err := os.Stat(r.Dir); err == nil {
		t.Error("a resolver directory or file was written")
	}
}

func TestAFileSomeoneElseWroteIsNeverReplaced(t *testing.T) {
	r := resolvers(t)
	os.MkdirAll(r.Dir, 0o755)
	path := filepath.Join(r.Dir, "corp.example")
	os.WriteFile(path, []byte("nameserver 192.0.2.53\n"), 0o644)

	err := r.Set("work", servers, []string{"corp.example"})
	if !errors.Is(err, ErrNotOurs) || !strings.Contains(err.Error(), "exists and adit did not write it") {
		t.Errorf("got %v", err)
	}
	if content, _ := os.ReadFile(path); string(content) != "nameserver 192.0.2.53\n" {
		t.Errorf("the file was changed: %q", content)
	}
	r.Clear("work")
	r.ClearAll()
	if _, err := os.Stat(path); err != nil {
		t.Error("clearing removed a file adit did not write")
	}
}

func TestAnotherTunnelsFileIsItsOwn(t *testing.T) {
	r := resolvers(t)
	if err := r.Set("home", servers, []string{"corp.example"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Check("work", []string{"corp.example"}); !errors.Is(err, ErrNotOurs) || !strings.Contains(err.Error(), "belongs to the tunnel home") {
		t.Errorf("got %v", err)
	}
	r.Clear("work")
	if _, err := os.Stat(filepath.Join(r.Dir, "corp.example")); err != nil {
		t.Error("clearing work removed home's file")
	}
}

func TestClearAllRemovesEveryMarkedFile(t *testing.T) {
	r := resolvers(t)
	r.Set("home", servers, []string{"home.example"})
	r.Set("work", servers, []string{"corp.example"})
	if err := r.ClearAll(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(r.Dir); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

func resolvers(t *testing.T) *Resolvers {
	return &Resolvers{Dir: filepath.Join(t.TempDir(), "resolver")}
}

func TestCheckRefusesADomainThatOverlapsAnotherResolver(t *testing.T) {
	r := &Resolvers{Dir: t.TempDir()}
	os.WriteFile(filepath.Join(r.Dir, "example.com"), []byte("nameserver 192.0.2.53\n"), 0o644)
	if err := r.Check("diner", []string{"corp.example.com"}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("a sub-domain of another program's domain: %v", err)
	}
	if err := r.Set("cupcakes", []netip.Addr{netip.MustParseAddr("10.99.1.1")}, []string{"shop.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Check("diner", []string{"example.org"}); !errors.Is(err, ErrNotOurs) {
		t.Errorf("a parent of another tunnel's domain: %v", err)
	}
	if err := r.Check("diner", []string{"example.net", "notexample.com"}); err != nil {
		t.Errorf("unrelated domains: %v", err)
	}
}

func TestOverlapOnLabelBoundaries(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"corp.example", "corp.example.", true}, {"a.corp.example", "CORP.example", true}, {"notcorp.example", "corp.example", false}, {"com", "example.com", true}, {"example", "example.com", false}} {
		if got := Overlap(c.a, c.b); got != c.want {
			t.Errorf("Overlap(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
