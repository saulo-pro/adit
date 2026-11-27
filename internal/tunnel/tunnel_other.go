//go:build !darwin

package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/saulo-pro/adit/internal/conf"
)

// Tunnel is not implemented here yet: adit runs tunnels on macOS first.
type Tunnel struct{}

func Start(ctx context.Context, c *conf.Config, beforeRoutes func(endpoints []netip.Addr) error, log *slog.Logger) (*Tunnel, error) {
	return nil, errors.New("adit runs tunnels only on macOS for now")
}

func (t *Tunnel) Interface() string       { return "" }
func (t *Tunnel) Status() (Status, error) { return Status{}, errors.New("not running") }
func (t *Tunnel) Close() error            { return nil }

func (t *Tunnel) NetworkChanged(ctx context.Context) error { return nil }
func (t *Tunnel) Reresolve(ctx context.Context) error      { return nil }
