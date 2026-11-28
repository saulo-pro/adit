package api

import (
	"strings"
	"testing"
)

func TestSummary(t *testing.T) {
	full := Tunnel{Name: "manhattan", State: "up", KillSwitch: "on-drop", LAN: "allow"}
	diner := Tunnel{Name: "diner", State: "up"}
	cupcakes := Tunnel{Name: "cupcakes", State: "idle"}
	down := Tunnel{Name: "chestnut", State: "down"}
	blockingLAN := full
	blockingLAN.LAN, blockingLAN.KillSwitch = "block", "off"
	for want, tunnels := range map[string][]Tunnel{
		"": {diner, down},
		"Everything goes through manhattan, except diner, cupcakes and the local network. If it drops, the internet is blocked (kill switch).": {diner, cupcakes, full, down},
		"Everything goes through manhattan; the local network is blocked. If it drops, traffic goes out directly.":                             {blockingLAN},
		"The internet is blocked until manhattan is up (kill switch).":                                                                         {diner, {Name: "manhattan", State: "down", KillSwitch: "always", Blocking: true}},
	} {
		if got := Summary(tunnels); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestSortByReach(t *testing.T) {
	sorted := SortByReach([]Tunnel{
		{Name: "chestnut", Networks: []string{"10.99.1.0/24"}},
		{Name: "manhattan", KillSwitch: "on-drop", Networks: []string{"0.0.0.0/0"}},
		{Name: "williamsburg", Networks: []string{"10.99.3.0/24", "10.98.1.4/32", "10.98.1.5/32"}},
		{Name: "diner", Networks: []string{"10.99.2.0/24"}},
	})
	var names []string
	for _, t := range sorted {
		names = append(names, t.Name)
	}
	if got := strings.Join(names, " "); got != "chestnut diner williamsburg manhattan" {
		t.Errorf("order %s", got)
	}
}
