// Command adit is adit's command line: it lists, switches, imports and exports tunnels by asking
// aditd, which runs as root.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/saulo-pro/adit/internal/cli"
)

// version is set when building a release: -ldflags "-X main.version=…".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := cli.New(version, os.Stdin, os.Stdout, os.Stderr).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
