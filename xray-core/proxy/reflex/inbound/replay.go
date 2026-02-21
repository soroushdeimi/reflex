package inbound

import (
	"sync"
	"time"
)

type replayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[[16]byte]int64 // nonce -> unix time added
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{
		ttl:  ttl,
		data: make(map[[16]byte]int64),
	}
}

// SeenOrAdd returns true if nonce already seen (replay), otherwise stores it and returns false.
func (c *replayCache) SeenOrAdd(nonce [16]byte, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// lazy cleanup (cheap)
	c.cleanupLocked(now)

	if _, ok := c.data[nonce]; ok {
		return true
	}
	c.data[nonce] = now
	return false
}

func (c *replayCache) cleanupLocked(now int64) {
	if len(c.data) == 0 {
		return
	}
	exp := now - int64(c.ttl.Seconds())
	for k, ts := range c.data {
		if ts < exp {
			delete(c.data, k)
		}
	}
}