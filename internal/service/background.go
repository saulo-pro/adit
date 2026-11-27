package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/saulo-pro/adit/internal/store"
	"github.com/saulo-pro/adit/internal/tunnel"
)

// maxRetryWait caps the pause between tries of an autostart tunnel.
const maxRetryWait = time.Minute

// errStopped ends a retry whose tunnel was taken down or removed since it began.
var errStopped = errors.New("stopped")

// retry is an autostart tunnel aditd keeps trying to bring up.
type retry struct {
	cancel context.CancelFunc
	last   string    // why the last try failed
	next   time.Time // when the next try is
}

// follower is a device that follows the Mac's network: tunnel.Tunnel in aditd. Fakes in tests need
// not be one.
type follower interface {
	NetworkChanged(ctx context.Context) error
	Reresolve(ctx context.Context) error
}

// Autostart brings up every tunnel set to start automatically, as aditd starts at boot. Each one is
// tried until it comes up, with pauses growing from retryWait to a minute: at boot the network may
// not be there yet. Status shows it as connecting, with the last failure, until then.
func (m *Manager) Autostart(ctx context.Context) error {
	m.mu.Lock()
	tunnels, err := m.store.List()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	for _, t := range tunnels {
		if t.Settings.Autostart {
			m.keepTrying(ctx, t)
		}
	}
	return nil
}

func (m *Manager) keepTrying(ctx context.Context, t *store.Tunnel) {
	ctx, cancel := context.WithCancel(ctx)
	r := &retry{cancel: cancel}
	m.mu.Lock()
	m.retrying[t.Name] = r
	m.notify()
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			if m.retrying[t.Name] == r {
				delete(m.retrying, t.Name)
			}
			m.notify()
			m.mu.Unlock()
		}()

		wait := max(m.retryWait, time.Millisecond)
		for {
			try, done := context.WithTimeout(ctx, 30*time.Second)
			err := m.up(try, t.Name, r)
			done()
			if err == nil || ctx.Err() != nil || errors.Is(err, errStopped) || errors.Is(err, store.ErrNotFound) {
				return
			}

			m.mu.Lock()
			if err.Error() != r.last {
				m.log.Info("autostart tunnel not up yet; trying again", "tunnel", t.Name, "reason", err)
			}
			r.last, r.next = err.Error(), m.now().Add(wait)
			m.notify()
			m.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, maxRetryWait)
		}
	}()
}

// NetworkChanged tells every tunnel that the Mac's network changed: each rebinds its socket to the
// new network and looks its endpoint names up again.
func (m *Manager) NetworkChanged(ctx context.Context) {
	m.each(ctx, func(name string, f follower) error { return f.NetworkChanged(ctx) })
	m.Recheck()
}

// ReresolveStale looks endpoint names up again for tunnels with no recent handshake: the server's
// address may have changed under its name, as with dynamic DNS.
func (m *Manager) ReresolveStale(ctx context.Context) {
	m.Recheck()
	m.mu.Lock()
	stale := map[string]bool{}
	for name, r := range m.running {
		if status, err := r.dev.Status(); err == nil && m.stale(status.Peers) {
			stale[name] = true
		}
	}
	m.mu.Unlock()
	m.each(ctx, func(name string, f follower) error {
		if !stale[name] {
			return nil
		}
		return f.Reresolve(ctx)
	})
}

func (m *Manager) stale(peers []tunnel.PeerStatus) bool {
	for _, peer := range peers {
		if !peer.LastHandshake.IsZero() && m.now().Sub(peer.LastHandshake) <= upWithin {
			return false
		}
	}
	return true
}

// each runs do for every running tunnel that follows the network, at once, without holding the lock:
// a lookup may take seconds.
func (m *Manager) each(ctx context.Context, do func(name string, f follower) error) {
	m.mu.Lock()
	followers := map[string]follower{}
	for name, r := range m.running {
		if f, ok := r.dev.(follower); ok {
			followers[name] = f
		}
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for name, f := range followers {
		wg.Go(func() {
			if err := do(name, f); err != nil {
				m.log.Info("could not follow the network", "tunnel", name, "reason", err)
			}
		})
	}
	wg.Wait()
}
