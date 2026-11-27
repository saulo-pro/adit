package api

import "testing"

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
