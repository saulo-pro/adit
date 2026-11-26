package service

import (
	"time"

	"github.com/saulo-pro/adit/internal/others"
)

// othersFresh is how long a reading of other software's tunnels serves: asking scutil starts a
// process, and the tray asks every second.
const othersFresh = 3 * time.Second

// otherTunnels returns other software's tunnels, read afresh at most every othersFresh. Called with
// m.mu held.
func (m *Manager) otherTunnels() []others.Tunnel {
	if m.others == nil {
		return nil
	}
	if m.othersRead.IsZero() || time.Since(m.othersRead) > othersFresh {
		m.othersSeen, m.othersRead = m.others(), time.Now()
	}
	return m.othersSeen
}

// describe names the software behind an interface, for a message.
func (m *Manager) describe(iface string) string {
	return others.Describe(m.otherTunnels(), iface)
}

// Others reports other software's tunnels, read-only. wg-quick's have handshakes and counters, so
// their state means what adit's does; the WireGuard app's have only the app's own word. fresh reads
// them again, for a person asking; a watch polling every second may use a reading a few seconds old.
func (m *Manager) Others(fresh bool) []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fresh {
		m.othersRead = time.Time{}
	}

	var statuses []Status
	for _, t := range m.otherTunnels() {
		status := Status{Name: t.Name, Source: t.Source, ReadOnly: true, Interface: t.Interface}
		if t.Source == others.SourceWgQuick {
			status.LastHandshake, status.Received, status.Sent = sum(t.Peers)
			status.State = m.stateOf(status.LastHandshake)
		} else {
			status.State = State(t.State)
			status.Notes = []string{"the WireGuard app does not share its handshakes or byte counts"}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// Other finds another program's tunnel by name, for a status request or a refusal.
func (m *Manager) Other(name string) (Status, bool) {
	for _, status := range m.Others(true) {
		if status.Name == name {
			return status, true
		}
	}
	return Status{}, false
}
