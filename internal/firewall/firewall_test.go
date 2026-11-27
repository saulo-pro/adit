package firewall

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// fakePf is pf as pfctl shows it: one anchor, and references to the enabled state.
type fakePf struct {
	rules    string
	tokens   map[string]bool
	next     int
	calls    []string
	failLoad bool
}

func (p *fakePf) Run(stdin string, args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	p.calls = append(p.calls, line)
	switch {
	case strings.HasSuffix(line, "-f -"):
		if p.failLoad {
			return []byte("No ALTQ support in kernel\nstdin:3: syntax error\n"), errors.New("exit status 1")
		}
		p.rules = stdin
		return []byte("pfctl: Use of -f option, could result in flushing of rules\nNo ALTQ support in kernel\n"), nil
	case strings.HasSuffix(line, "-s rules"):
		return []byte(p.rules), nil
	case strings.HasSuffix(line, "-F all"):
		p.rules = ""
		return []byte("rules cleared\n"), nil
	case line == "-E":
		p.next++
		token := []string{"", "1420488880338432422", "15850416432640452357"}[p.next]
		p.tokens[token] = true
		return []byte("No ALTQ support in kernel\npf enabled\nToken : " + token + "\n"), nil
	case strings.HasPrefix(line, "-X "):
		delete(p.tokens, strings.TrimPrefix(line, "-X "))
		return []byte("pf disabled\n"), nil
	}
	return nil, errors.New("unexpected call " + line)
}

func newFirewall(t *testing.T) (*Firewall, *fakePf) {
	pf := &fakePf{tokens: map[string]bool{}}
	return &Firewall{Anchor: DefaultAnchor, StateFile: filepath.Join(t.TempDir(), "firewall.json"), Run: pf.Run}, pf
}

var rules = Rules{
	Interfaces: []string{"utun4", "utun5"},
	Servers:    []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820"), netip.MustParseAddrPort("[2001:db8::7]:51821")},
	AllowLAN:   true,
	Guards:     []string{"manhattan"},
}

func TestTheRulesetPassesOnlyAditsTunnels(t *testing.T) {
	got := Ruleset(rules)
	for _, want := range []string{
		"pass quick on lo0 no state\n",
		"pass quick on { utun4 utun5 } no state\n",
		"pass out quick proto udp to 203.0.113.10 port 51820 user root keep state\n",
		"pass out quick proto udp to 2001:db8::7 port 51821 user root keep state\n",
		"block return out quick proto { udp tcp } to any port 53\n",
		"pass out quick to { 10.0.0.0/8 ",
		"pass in quick from { 10.0.0.0/8 ",
		"block return out quick all\nblock drop in quick all\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in:\n%s", want, got)
		}
	}
	if strings.Index(got, "port 53 user root") > strings.Index(got, "block return out quick proto { udp tcp } to any port 53") {
		t.Error("root's DNS must pass before everyone else's is blocked")
	}
	if strings.Contains(got, "pass quick to {") || strings.Contains(got, "pass quick from {") {
		t.Error("the local network passes both ways regardless of direction: a Mac's own private address would pass everything")
	}
	if strings.Contains(Ruleset(Rules{}), "pass out quick to {") {
		t.Error("the local network passes without AllowLAN")
	}
}

func TestBlockLoadsTheAnchorAndTurnsPfOn(t *testing.T) {
	f, pf := newFirewall(t)
	if err := f.Block(rules); err != nil {
		t.Fatal(err)
	}
	if pf.rules != Ruleset(rules) || !pf.tokens["1420488880338432422"] {
		t.Errorf("rules %q, tokens %v", pf.rules, pf.tokens)
	}
	if guards, _ := f.Guards(); len(guards) != 1 || guards[0] != "manhattan" {
		t.Errorf("guards %v", guards)
	}
}

func TestBlockAgainWithTheSameRulesDoesNothing(t *testing.T) {
	f, pf := newFirewall(t)
	f.Block(rules)
	pf.calls = nil
	if err := f.Block(rules); err != nil {
		t.Fatal(err)
	}
	if len(pf.calls) != 1 || pf.calls[0] != "-a com.apple/000.adit -s rules" {
		t.Errorf("calls %v", pf.calls)
	}
}

func TestNewRulesReloadWithTheSameToken(t *testing.T) {
	f, pf := newFirewall(t)
	f.Block(rules)
	more := rules
	more.Interfaces = []string{"utun5"}
	if err := f.Block(more); err != nil {
		t.Fatal(err)
	}
	if pf.rules != Ruleset(more) || len(pf.tokens) != 1 {
		t.Errorf("rules %q, tokens %v", pf.rules, pf.tokens)
	}
}

func TestReleaseLetsGo(t *testing.T) {
	f, pf := newFirewall(t)
	f.Block(rules)
	if err := f.Release(); err != nil {
		t.Fatal(err)
	}
	if pf.rules != "" || len(pf.tokens) != 0 {
		t.Errorf("rules %q, tokens %v", pf.rules, pf.tokens)
	}
	if guards, _ := f.Guards(); len(guards) != 0 {
		t.Errorf("guards %v", guards)
	}
	pf.calls = nil
	if err := f.Release(); err != nil || len(pf.calls) != 1 {
		t.Errorf("a second release: %v, calls %v", err, pf.calls)
	}
}

func TestAnotherAditdTakesOverFromTheStateFile(t *testing.T) {
	f, pf := newFirewall(t)
	f.Block(rules)
	again := &Firewall{Anchor: f.Anchor, StateFile: f.StateFile, Run: pf.Run}
	if guards, _ := again.Guards(); len(guards) != 1 {
		t.Fatalf("guards %v", guards)
	}
	if err := again.Release(); err != nil {
		t.Fatal(err)
	}
	if len(pf.tokens) != 0 {
		t.Errorf("the earlier aditd's token is still held: %v", pf.tokens)
	}
}

func TestARefusedRulesetIsReported(t *testing.T) {
	f, pf := newFirewall(t)
	pf.failLoad = true
	err := f.Block(rules)
	if err == nil || !strings.HasSuffix(err.Error(), "stdin:3: syntax error") {
		t.Errorf("got %v", err)
	}
	if len(pf.tokens) != 0 {
		t.Error("pf was turned on without rules")
	}
}
