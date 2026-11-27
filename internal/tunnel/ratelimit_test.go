package tunnel

import (
	"testing"
	"time"
)

func TestRateLimitLetsOneLineOfEachKindThroughPerPeriod(t *testing.T) {
	now := time.Unix(1795000000, 0)
	r := &rateLimit{every: time.Minute, now: func() time.Time { return now }, last: map[string]time.Time{}, held: map[string]int{}}
	if ok, _ := r.allow("send failed"); !ok {
		t.Fatal("the first line was held back")
	}
	for range 1000 {
		if ok, _ := r.allow("send failed"); ok {
			t.Fatal("a repeated line went through within the minute")
		}
	}
	if ok, _ := r.allow("handshake failed"); !ok {
		t.Error("another kind was held back")
	}
	now = now.Add(time.Minute)
	if ok, skipped := r.allow("send failed"); !ok || skipped != 1000 {
		t.Errorf("after a minute: ok %v, skipped %d; want true, 1000", ok, skipped)
	}
}
