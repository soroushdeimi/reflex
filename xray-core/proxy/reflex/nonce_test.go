package reflex

import (
	"testing"
)

func TestNonceCache(t *testing.T) {
	cache := NewNonceCache(10)

	// Test unique nonces
	if !cache.Check(1) {
		t.Error("expected true for new nonce 1")
	}
	if !cache.Check(2) {
		t.Error("expected true for new nonce 2")
	}

	// Test replay (duplicate nonce)
	if cache.Check(1) {
		t.Error("expected false for replayed nonce 1")
	}

	// Test old nonce (below minNonce)
	// After cache is filled and cleanup runs, minNonce increases
}

func TestNonceCacheCleanup(t *testing.T) {
	maxSize := 10
	cache := NewNonceCache(maxSize)

	// Fill cache beyond maxSize to trigger cleanup
	for i := uint64(0); i <= uint64(maxSize); i++ {
		cache.Check(i)
	}

	// After cleanup, minNonce should have increased
	if cache.minNonce == 0 {
		t.Error("minNonce should have increased after cleanup")
	}

	// Nonces below minNonce must be rejected
	if cache.Check(cache.minNonce - 1) {
		t.Errorf("nonce %d below minNonce %d should be rejected", cache.minNonce-1, cache.minNonce)
	}

	// New high nonce should be accepted
	if !cache.Check(uint64(maxSize + 100)) {
		t.Error("expected true for new high nonce")
	}
}

func TestNonceConcurrency(t *testing.T) {
	cache := NewNonceCache(100)
	const count = 100
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < count; i++ {
		go func(n uint64) {
			cache.Check(n)
			done <- true
		}(uint64(i))
	}

	for i := 0; i < count; i++ {
		<-done
	}

	if len(cache.seen) == 0 {
		t.Error("expected nonces to be recorded")
	}
}
