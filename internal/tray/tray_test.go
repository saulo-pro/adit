package tray

import (
	"strings"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/api"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func TestRows(t *testing.T) {
	handshake := now.Add(-12 * time.Second)
	tunnels := []api.Tunnel{
		{Name: "home", State: "down"},
		{Name: "work", State: "up", Interface: "utun9", LastHandshake: &handshake, ReceivedBytes: 2048},
		{Name: "williamsburg", State: "connecting", Notes: []string{"aditd is bringing it up and will try again in 4s: williamsburg did not come up: the Endpoint vpn.example.com does not resolve; check the network or the Endpoint line"}},
	}
	others := []api.Tunnel{{Name: "diner", State: "connected", Source: "WireGuard app", ReadOnly: true}}
	failures := map[string]string{"home": "home's AllowedIPs 10.99.2.0/24 overlaps 10.99.2.0/24, which utun7 routes"}

	rows := Rows(tunnels, others, failures, now)
	var lines []string
	for _, row := range rows {
		mark := " "
		if row.Checked {
			mark = "✓"
		}
		lines = append(lines, mark+" "+row.Title)
	}
	want := []string{
		"  home",
		"      Failed: home's AllowedIPs 10.99.2.0/24 overlaps 10.99.2.0/24, which…",
		"✓ work — up · 12s ago",
		"✓ williamsburg — connecting",
		"      aditd is bringing it up and will try again in 4s: williamsburg did…",
		"  ",
		"  diner — connected (WireGuard app)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if rows[1].Tooltip != "Failed: "+failures["home"] {
		t.Errorf("the full failure is not in the tooltip: %q", rows[1].Tooltip)
	}
	if rows[6].Kind != KindOther {
		t.Error("another program's tunnel can be clicked")
	}
}

func TestNoTunnelsSaysHowToAddOne(t *testing.T) {
	rows := Rows(nil, nil, nil, now)
	if len(rows) != 1 || rows[0].Kind != KindMessage || !strings.Contains(rows[0].Title, "sudo adit import") {
		t.Errorf("got %+v", rows)
	}
}

func TestCountShowsTunnelsUp(t *testing.T) {
	tunnels := []api.Tunnel{{State: "up"}, {State: "connecting"}, {State: "up"}, {State: "down"}}
	if got := Count(tunnels); got != "2" {
		t.Errorf("got %q", got)
	}
	if got := Count(tunnels[3:]); got != "" {
		t.Errorf("with none up: %q", got)
	}
}

func TestOnMeansSwitchedOn(t *testing.T) {
	for state, on := range map[string]bool{"up": true, "connecting": true, "idle": true, "down": false} {
		if On(api.Tunnel{State: state}) != on {
			t.Errorf("%s", state)
		}
	}
}
