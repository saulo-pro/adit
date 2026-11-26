package netwatch

import "testing"

func TestOnlyChangesOnRealNetworksCount(t *testing.T) {
	names := map[int]string{4: "en0", 9: "utun9", 12: "awdl0", 20: "bridge100"}
	name := func(index int) string { return names[index] }

	tests := []struct {
		kind  byte
		index int
		want  bool
	}{
		{rtmNewAddr, 4, true},
		{rtmDelAddr, 4, true},
		{rtmIfInfo, 4, true},
		{0x1, 4, false},        // a route added: not a change of network
		{rtmNewAddr, 9, false}, // a tunnel's own address
		{rtmIfInfo, 12, false}, // Apple's peer-to-peer Wi-Fi, which comes and goes
		{rtmIfInfo, 20, false}, // a virtual machine's bridge
		{rtmIfInfo, 99, false}, // an interface already gone
	}
	for _, test := range tests {
		message := make([]byte, 20)
		message[3] = test.kind
		message[12] = byte(test.index)
		if got := relevant(message, name); got != test.want {
			t.Errorf("type %#x on %q: %v, want %v", test.kind, names[test.index], got, test.want)
		}
	}
	if relevant([]byte{0, 0, 0, rtmIfInfo}, name) {
		t.Error("a short message counted")
	}
}
