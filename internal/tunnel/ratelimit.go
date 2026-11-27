package tunnel

import (
	"sync"
	"time"
)

// rateLimit lets one line of each kind through per period and counts the others.
type rateLimit struct {
	every time.Duration
	now   func() time.Time

	mu   sync.Mutex
	last map[string]time.Time // kind → when it was last let through
	held map[string]int       // kind → how many were held back since
}

// allow says whether a line of this kind may be written now, and how many like it were held back
// since the last one written.
func (r *rateLimit) allow(kind string) (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if last, seen := r.last[kind]; seen && now.Sub(last) < r.every {
		r.held[kind]++
		return false, 0
	}
	if len(r.last) > 256 { // wireguard-go has a few dozen kinds; never let the map grow
		r.last, r.held = map[string]time.Time{}, map[string]int{}
	}
	skipped := r.held[kind]
	r.last[kind], r.held[kind] = now, 0
	return true, skipped
}
