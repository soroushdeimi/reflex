package reflex

import (
	"sync"
)

// NonceCache provides anti-replay protection
type NonceCache struct {
	seen     map[uint64]bool
	maxSize  int
	mu       sync.Mutex
	minNonce uint64
}

// NewNonceCache creates a new nonce cache
func NewNonceCache(maxSize int) *NonceCache {
	return &NonceCache{
		seen:     make(map[uint64]bool),
		maxSize:  maxSize,
		minNonce: 0,
	}
}

// Check validates nonce and prevents replay
func (nc *NonceCache) Check(nonce uint64) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Reject old nonces
	if nonce < nc.minNonce {
		return false
	}

	// Check if already seen
	if nc.seen[nonce] {
		return false
	}

	// Add to cache
	nc.seen[nonce] = true

	// Cleanup if cache too large
	if len(nc.seen) > nc.maxSize {
		nc.cleanup()
	}

	return true
}

// cleanup removes old nonces
func (nc *NonceCache) cleanup() {
	// Find minimum nonce to keep
	threshold := nc.minNonce + uint64(nc.maxSize/2)

	// Remove old entries
	for nonce := range nc.seen {
		if nonce < threshold {
			delete(nc.seen, nonce)
		}
	}

	// Update minimum
	nc.minNonce = threshold
}
