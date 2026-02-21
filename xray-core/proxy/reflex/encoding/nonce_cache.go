package encoding

import (
    "sync"
)

// NonceCache: prevents replay attacks
type NonceCache struct {
    mu sync.Mutex
    seen map[uint64]bool
    max int
}

// NewNonceCache: creates a new nonce cache with maximum size
func NewNonceCache(max int) *NonceCache {
    return &NonceCache{
        seen: make(map[uint64]bool),
        max: max,
    }
}

// Check: verifies if a nonce has been used before
func (nc *NonceCache) Check(nonce uint64) bool {
    nc.mu.Lock()
    defer nc.mu.Unlock()

    if nc.seen[nonce] {
        return false
    }

    nc.seen[nonce] = true

    // clean up old entries if cache is too large
    if len(nc.seen) > nc.max {
        for k := range nc.seen {
            if len(nc.seen) <= nc.max/2 {
                break
            }
            delete(nc.seen, k)
        }
    }

    return true
}

// Clear: empties the cache
func (nc *NonceCache) Clear() {
    nc.mu.Lock()
    defer nc.mu.Unlock()
    nc.seen = make(map[uint64]bool)
}
