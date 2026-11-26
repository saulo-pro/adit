//go:build !darwin

package netwatch

import (
	"context"
	"time"
)

// Watch reports nothing away from macOS yet; it waits for ctx to end.
func Watch(ctx context.Context, settle time.Duration, changed func()) error {
	<-ctx.Done()
	return ctx.Err()
}
