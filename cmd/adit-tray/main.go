// Command adit-tray is adit's menu bar icon. Like the command line, it is a client of aditd, which
// holds every tunnel; a LaunchAgent starts it at login. Clicking a tunnel switches it, with no
// password, and the menu follows aditd's watch stream, so a tunnel switched from the command line
// flips here at once.
package main

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/tray"
)

func main() {
	app := &app{client: &api.Client{Socket: os.Getenv("ADIT_SOCKET")}, failures: map[string]string{}}
	systray.Run(app.ready, func() {})
}

type app struct {
	client *api.Client

	mu          sync.Mutex
	tunnels     []api.Tunnel
	others      []api.Tunnel
	failures    map[string]string // why the last click on a tunnel failed
	unreachable string            // why aditd does not answer, or ""
	menu        context.CancelFunc
}

func (a *app) ready() {
	icon := templateIcon()
	systray.SetTemplateIcon(icon, icon)
	systray.SetTooltip("adit")
	a.unreachable = "Connecting to aditd…"
	a.render()
	go a.watch()
	go func() {
		// Handshake ages move on without a change from aditd.
		for range time.Tick(15 * time.Second) {
			a.render()
		}
	}()
}

// watch follows aditd, and when it goes away says why and tries again every few seconds.
func (a *app) watch() {
	for {
		err := a.client.Watch(context.Background(), func(tunnels, others []api.Tunnel) error {
			a.mu.Lock()
			a.tunnels, a.others, a.unreachable = tunnels, others, ""
			a.mu.Unlock()
			a.render()
			return nil
		})
		a.mu.Lock()
		a.unreachable = err.Error()
		a.mu.Unlock()
		a.render()
		time.Sleep(3 * time.Second)
	}
}

// render rebuilds the menu from the latest state.
func (a *app) render() {
	a.mu.Lock()
	defer a.mu.Unlock()

	rows := tray.Rows(a.tunnels, a.others, a.failures, time.Now())
	if a.unreachable != "" {
		rows = tray.Unreachable(a.unreachable)
	}
	if a.menu != nil {
		a.menu() // ends the click listeners of the menu being replaced
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.menu = cancel

	systray.ResetMenu()
	systray.SetTitle(tray.Count(a.tunnels))
	for _, row := range rows {
		switch row.Kind {
		case tray.KindSeparator:
			systray.AddSeparator()
		case tray.KindTunnel:
			item := systray.AddMenuItemCheckbox(row.Title, row.Tooltip, row.Checked)
			go a.clicks(ctx, item, row.Name, row.Checked)
		default:
			systray.AddMenuItem(row.Title, row.Tooltip).Disable()
		}
	}
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit adit menu", "The tunnels stay as they are: aditd keeps them")
	go func() {
		select {
		case <-quit.ClickedCh:
			systray.Quit()
		case <-ctx.Done():
		}
	}()
}

func (a *app) clicks(ctx context.Context, item *systray.MenuItem, name string, on bool) {
	select {
	case <-ctx.Done():
	case <-item.ClickedCh:
		go a.toggle(name, on)
	}
}

// toggle switches a tunnel. The new state arrives through the watch stream; a failure stays under
// the tunnel until a later click succeeds.
func (a *app) toggle(name string, on bool) {
	command := api.CommandUp
	if on {
		command = api.CommandDown
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	_, err := a.client.Do(ctx, api.Request{Command: command, Name: name})

	a.mu.Lock()
	if err != nil {
		a.failures[name] = err.Error()
	} else {
		delete(a.failures, name)
	}
	a.mu.Unlock()
	a.render()
}

// templateIcon draws an arch, a tunnel's mouth, in black on transparent: macOS recolours template
// images for light and dark menu bars.
func templateIcon() []byte {
	const size = 36
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	cx, cy := size/2, size*3/4
	for y := range size {
		for x := range size {
			dx, dy := x-cx, y-cy
			d := dx*dx + dy*dy
			arch := y <= cy && d <= 15*15 && d >= 9*9
			legs := y > cy && y < size-2 && (x >= cx-15 && x <= cx-9 || x >= cx+9 && x <= cx+15)
			if arch || legs {
				img.Set(x, y, color.NRGBA{A: 255})
			}
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}
