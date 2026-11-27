// Command aditd is adit's privileged service: it runs as root, owns every adit tunnel and answers
// the command line and the tray over a Unix socket. A LaunchDaemon starts it at boot.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/netwatch"
	"github.com/saulo-pro/adit/internal/server"
	"github.com/saulo-pro/adit/internal/service"
	"github.com/saulo-pro/adit/internal/store"
)

// version is set when building a release: -ldflags "-X main.version=…".
var version = "dev"

func main() {
	socket := flag.String("socket", api.DefaultSocket, "the socket to answer on")
	storeDir := flag.String("store", "/var/db/adit/tunnels", "where tunnels and their keys are kept")
	group := flag.String("group", "adit", "the group whose members may list, switch and watch tunnels; empty for root only")
	logFile := flag.String("log", "", "a file to log to, opened again on SIGHUP; standard error if empty")
	pidFile := flag.String("pidfile", "", "a file to write the process id to, for newsyslog")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(*socket, *storeDir, *group, *logFile, *pidFile); err != nil {
		fmt.Fprintln(os.Stderr, "aditd:", err)
		os.Exit(1)
	}
}

func run(socket, storeDir, group, logFile, pidFile string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("aditd must run as root: it creates network interfaces and routes")
	}
	// wireguard-go writes the name of each new interface to the file this names: never take it
	// from the environment aditd was started with.
	os.Unsetenv("WG_TUN_NAME_FILE")
	if logFile != "" {
		if err := openLog(logFile); err != nil {
			return err
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if logFile != "" {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				if err := openLog(logFile); err != nil {
					log.Warn("could not open the log again after rotation", "error", err)
				}
			}
		}()
	}
	if pidFile != "" {
		if err := writePid(pidFile); err != nil {
			log.Warn("could not write the pid file: the log will not rotate", "file", pidFile, "error", err)
		}
		defer os.Remove(pidFile)
	}

	st, err := store.Open(storeDir)
	if err != nil {
		return err
	}
	manager := service.New(st, log)
	defer manager.Close()
	if err := manager.CleanUp(); err != nil {
		log.Warn("could not remove what an earlier aditd left behind", "error", err)
	}

	listener, err := server.Listen(socket, group)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("aditd started", "version", version, "socket", socket, "group", group)
	if err := manager.Autostart(ctx); err != nil {
		log.Warn("could not read which tunnels start automatically", "error", err)
	}
	go followTheNetwork(ctx, manager, log)

	err = server.New(manager, group, version, log).Serve(ctx, listener)
	log.Info("aditd stopping")
	return err
}

// followTheNetwork moves the tunnels along when the Mac changes network, and every minute looks the
// endpoint names of tunnels with no recent handshake up again.
func followTheNetwork(ctx context.Context, manager *service.Manager, log *slog.Logger) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				manager.ReresolveStale(ctx)
			}
		}
	}()

	err := netwatch.Watch(ctx, 2*time.Second, func() {
		log.Info("the network changed; the tunnels follow")
		manager.NetworkChanged(ctx)
	})
	if err != nil && ctx.Err() == nil {
		log.Warn("not watching the network: tunnels may not follow a move to another network", "error", err)
	}
}
