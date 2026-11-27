// Package tray decides what adit's menu bar menu shows: one row per tunnel, checked when it is up,
// with its state and last handshake; the reason under any tunnel a click failed to switch; other
// software's tunnels greyed out; and a sentence instead when aditd cannot be reached.
//
// It holds no state of its own beyond the last failures: aditd's watch stream is the truth, and
// the command line and the tray show the same thing.
package tray

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/saulo-pro/adit/internal/api"
)

type Kind int

const (
	KindTunnel  Kind = iota // one of adit's: click to switch
	KindDetail              // a line under a tunnel: a failure or a note
	KindOther               // another program's tunnel, greyed out
	KindMessage             // a sentence instead of tunnels, such as aditd not running
	KindSignIn              // lifts the kill switch for a moment, to sign in to a captive network
	KindSeparator
)

type Row struct {
	Kind    Kind
	Name    string // the tunnel a row belongs to
	Title   string
	Tooltip string
	Checked bool
}

// maxDetail keeps a detail line to a menu's width; the tooltip holds all of it.
const maxDetail = 70

// Rows lays out the menu. failures are the sentences from clicks that failed, by tunnel.
func Rows(tunnels, others []api.Tunnel, failures map[string]string, now time.Time) []Row {
	var rows []Row
	// The full tunnel comes first: it decides where everything else goes.
	tunnels = slices.Clone(tunnels)
	slices.SortStableFunc(tunnels, func(a, b api.Tunnel) int {
		return cmp.Compare(btoi(a.KillSwitch == ""), btoi(b.KillSwitch == ""))
	})
	blocking := false
	for _, t := range tunnels {
		blocking = blocking || t.Blocking
	}
	if summary := api.Summary(tunnels); summary != "" && !blocking {
		rows = append(rows, Row{Kind: KindMessage, Title: shorten(summary), Tooltip: summary}, Row{Kind: KindSeparator})
	}
	for _, t := range tunnels {
		if t.Blocking {
			rows = append(rows,
				Row{Kind: KindMessage, Title: "The internet is blocked until " + t.Name + " is up", Tooltip: "Kill switch: nothing leaves the Mac around " + t.Name},
				Row{Kind: KindSignIn, Name: t.Name, Title: "Sign in to this network…", Tooltip: "Lifts the kill switch for 2 minutes and opens the network's sign-in page, as in a hotel or an airport"},
				Row{Kind: KindSeparator})
			break
		}
	}
	if len(tunnels) == 0 {
		rows = append(rows, Row{Kind: KindMessage, Title: "No tunnels yet: add one with sudo adit import FILE"})
	}
	for _, t := range tunnels {
		rows = append(rows, Row{Kind: KindTunnel, Name: t.Name, Title: title(t, now), Checked: On(t), Tooltip: tooltip(t)})
		if failure, failed := failures[t.Name]; failed {
			rows = append(rows, detail(t.Name, "Failed: "+failure))
		}
		for _, note := range t.Notes {
			rows = append(rows, detail(t.Name, note))
		}
	}
	if len(others) > 0 {
		rows = append(rows, Row{Kind: KindSeparator})
		for _, t := range others {
			rows = append(rows, Row{Kind: KindOther, Name: t.Name, Title: fmt.Sprintf("%s — %s (%s)", t.Name, t.State, t.Source),
				Tooltip: fmt.Sprintf("%s runs this tunnel; adit shows it but does not change it", t.Source)})
		}
	}
	return rows
}

// Unreachable is the menu when aditd does not answer: the reason, and nothing to click.
func Unreachable(reason string) []Row {
	return []Row{{Kind: KindMessage, Title: shorten(reason), Tooltip: reason}}
}

// On says whether a tunnel counts as switched on: up, or on its way.
func On(t api.Tunnel) bool {
	return t.State != "down"
}

// Count is the number shown beside the icon: tunnels up.
func Count(tunnels []api.Tunnel) string {
	n := 0
	for _, t := range tunnels {
		if t.State == "up" {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprint(n)
}

func title(t api.Tunnel, now time.Time) string {
	name := t.Name
	if t.KillSwitch != "" {
		name += " (all traffic)"
	}
	switch {
	case t.State == "down":
		return name
	case t.LastHandshake != nil:
		return fmt.Sprintf("%s — %s · %s", name, t.State, age(now.Sub(*t.LastHandshake)))
	default:
		return fmt.Sprintf("%s — %s", name, t.State)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func tooltip(t api.Tunnel) string {
	if t.State == "down" {
		return "Click to bring " + t.Name + " up"
	}
	return fmt.Sprintf("On %s; received %s, sent %s. Click to take it down.", t.Interface, bytes(t.ReceivedBytes), bytes(t.SentBytes))
}

func detail(name, text string) Row {
	return Row{Kind: KindDetail, Name: name, Title: "    " + shorten(text), Tooltip: text}
}

func shorten(text string) string {
	if len(text) <= maxDetail {
		return text
	}
	cut := strings.LastIndex(text[:maxDetail], " ")
	if cut < maxDetail/2 {
		cut = maxDetail
	}
	return text[:cut] + "…"
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", max(0, int(d.Seconds())))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}

func bytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value, unit := float64(n)/1024, "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if value < 1024 {
			break
		}
		value, unit = value/1024, next
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}
