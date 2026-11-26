//go:build integration && darwin

package server

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/saulo-pro/adit/internal/api"
	"github.com/saulo-pro/adit/internal/service"
	"github.com/saulo-pro/adit/internal/store"
)

// Runs aditd's own pieces as root — the tunnel manager behind a real socket — and drives both test
// servers' tunnels through the socket, as the command line and the tray will. Run it with
// test/integration.
func TestIntegrationTunnelsThroughTheSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root; run test/integration")
	}
	dir := os.Getenv("ADIT_TEST_SERVERS")
	if dir == "" {
		t.Skip("ADIT_TEST_SERVERS is not set; run test/integration")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "tunnels"))
	if err != nil {
		t.Fatal(err)
	}
	manager := service.New(st, log)
	t.Cleanup(func() { manager.Close() })

	socket := socketPath(t)
	listener, err := Listen(socket, "") // root only: this test runs as root
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error)
	go func() { served <- New(manager, "", "integration", log).Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	client := &api.Client{Socket: socket}

	views := make(chan []api.Tunnel, 100)
	go client.Watch(ctx, func(tunnels, _ []api.Tunnel) error {
		views <- tunnels
		return nil
	})

	servers := map[string]string{"test1": "10.99.1.1", "test2": "10.99.2.1"}
	for name := range servers {
		text, err := os.ReadFile(filepath.Join(dir, name+".conf"))
		if err != nil {
			t.Fatal(err)
		}
		call(t, client, api.Request{Command: api.CommandImport, Name: name, File: string(text)})
		call(t, client, api.Request{Command: api.CommandUp, Name: name})
	}

	waitForView(t, views, "both up", func(tunnels []api.Tunnel) bool {
		return len(tunnels) == 2 && tunnels[0].State == "up" && tunnels[1].State == "up"
	})

	interfaces := map[string]string{}
	for name, server := range servers {
		if output, err := exec.Command("/sbin/ping", "-c", "3", "-t", "5", server).CombinedOutput(); err != nil {
			t.Errorf("ping %s through %s failed: %s", server, name, output)
		}
		tunnel := call(t, client, api.Request{Command: api.CommandStatus, Name: name}).Tunnel
		t.Logf("%s on %s: %s, last handshake %s ago, received %d B, sent %d B", name, tunnel.Interface, tunnel.State,
			time.Since(*tunnel.LastHandshake).Round(time.Second), tunnel.ReceivedBytes, tunnel.SentBytes)
		if tunnel.ReceivedBytes == 0 || tunnel.SentBytes == 0 {
			t.Errorf("%s counted no traffic", name)
		}
		interfaces[name] = tunnel.Interface
	}

	for name := range servers {
		call(t, client, api.Request{Command: api.CommandDown, Name: name})
	}
	waitForView(t, views, "both down", func(tunnels []api.Tunnel) bool {
		return len(tunnels) == 2 && tunnels[0].State == "down" && tunnels[1].State == "down"
	})
	time.Sleep(500 * time.Millisecond)

	ifaces, err := exec.Command("/sbin/ifconfig", "-l").Output()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := exec.Command("/usr/sbin/netstat", "-rn").Output()
	if err != nil {
		t.Fatal(err)
	}
	for name, iface := range interfaces {
		if slices.Contains(strings.Fields(string(ifaces)), iface) {
			t.Errorf("%s left its interface %s behind", name, iface)
		}
		for line := range strings.Lines(string(routes)) {
			if slices.Contains(strings.Fields(line), iface) {
				t.Errorf("%s left a route behind: %s", name, strings.TrimSpace(line))
			}
		}
	}
}

func call(t *testing.T, client *api.Client, req api.Request) *api.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Command, req.Name, err)
	}
	return resp
}

func waitForView(t *testing.T, views chan []api.Tunnel, what string, done func([]api.Tunnel) bool) {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case tunnels := <-views:
			if done(tunnels) {
				return
			}
		case <-deadline:
			t.Fatalf("the watch stream never showed %s", what)
		}
	}
}
